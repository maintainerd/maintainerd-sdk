package authz

import (
	"context"
	"strings"

	"github.com/maintainerd/sdk/auth"
)

// Claim keys maintainerd-auth mints beyond the registered JWT set.
const (
	// ClaimPermissions is the array form of a token's entitlements. Auth mints it
	// alongside — not instead of — the space-separated "scope" string, depending on
	// how the grant was issued, so a PEP that reads only one of the two silently
	// authorizes half the tokens in the fleet.
	ClaimPermissions = "permissions"
	// ClaimSubjectType is Auth's principal-kind claim. Auth stamps it on every
	// NON-INTERACTIVE token it mints ("service" and "client" for the client-credentials
	// grant, "device" for RFC 8628, "ciba" for OIDC CIBA, "exchange" for RFC 8693) and
	// leaves it ABSENT on an interactive authorization-code login — which is why its
	// absence is evidence rather than ignorance. See ActorKindFromClaims.
	ClaimSubjectType = "sub_type"
	// ClaimService is Auth's service-identity claim: the name of the service a
	// machine client is bound to. Its presence is the single most reliable marker of
	// an m2m caller, because Auth stamps it only when the authenticated client has a
	// service behind it, and it is on Auth's reserved-claim list so a client-configured
	// claim mapper cannot forge one.
	ClaimService = "svc"
	// ClaimTenantSlug is Auth's tenant claim on tokens that do not use "tenant".
	ClaimTenantSlug = "tenant_slug"
)

// The sub_type values Auth mints, classified. Anything Auth adds later that is not
// listed is treated as a machine — see ActorKindFromClaims.
var machineSubjectTypes = map[string]struct{}{
	"service":  {}, // a client bound to a registered service identity
	"client":   {}, // client_credentials with no service binding
	"exchange": {}, // RFC 8693 token exchange: the actor is a delegating client
}

var humanSubjectTypes = map[string]struct{}{
	"user":   {}, // stamped explicitly where Auth knows it is a person
	"device": {}, // RFC 8628: a human approving on a second screen
	"ciba":   {}, // OIDC CIBA: a human approving out of band
}

// SDKVerify adapts an sdk/auth.Verifier (JWKS + issuer + audience) to a VerifyFunc.
// This is the one-call path from the SDK's existing verifier to MRN-aware
// enforcement:
//
//	v, _ := auth.NewVerifier(ctx, jwksURL, issuer, audience)
//	guard := authz.Guard{Mode: authz.ModeEnforced, Verify: authz.SDKVerify(v), Permissions: perms}
//
// Resolve wires this automatically; use it directly only when the verifier is built
// elsewhere.
func SDKVerify(v *auth.Verifier) VerifyFunc {
	return func(_ context.Context, token string) (*Principal, error) {
		c, err := v.Verify(token)
		if err != nil {
			return nil, err
		}
		return PrincipalFromClaims(c), nil
	}
}

// PrincipalFromClaims reduces verified JWT claims to a Principal, reading grants from
// BOTH claim shapes maintainerd-auth can mint: the space-separated "scope" string
// (already split into Claims.Scopes by the verifier) and the "permissions" array.
// Reading only one of the two is a silent half-outage — every token minted in the
// other shape authorizes nothing.
//
// It is exported so a service verifying tokens another way (introspection, a cached
// policy bundle, a test double) produces an identical Principal instead of
// re-deriving the mapping.
func PrincipalFromClaims(c *auth.Claims) *Principal {
	if c == nil {
		return nil
	}
	p := &Principal{Subject: c.Subject, Tenant: c.Tenant}

	p.Scopes = append(p.Scopes, c.Scopes...)
	if raw, ok := c.Raw[ClaimPermissions].([]any); ok {
		for _, entry := range raw {
			if s, ok := entry.(string); ok && strings.TrimSpace(s) != "" {
				p.Scopes = append(p.Scopes, s)
			}
		}
	}
	p.Grants = ParseGrants(p.Scopes)
	p.Kind = ActorKindFromClaims(c.Raw)

	if p.Tenant == "" {
		if t, _ := c.Raw[ClaimTenantSlug].(string); t != "" {
			p.Tenant = t
		}
	}
	return p
}

// ActorKindFromClaims classifies a verified token as a machine identity or a human,
// from the claims Auth actually mints. It is exported because the classification is
// now load-bearing in two places — the audit trail's actor_kind column and the
// surface guard's actor constraint (Actor) — and both must reach the same answer.
//
// THE RULE, positive evidence first:
//
//  1. an "svc" claim  -> service. Auth stamps it only for a client bound to a service
//     identity, and it is a reserved claim, so it cannot be mapped in by a client.
//  2. sub_type in {service, client, exchange} -> service.
//  3. sub_type in {user, device, ciba} -> user.
//  4. any OTHER non-empty sub_type -> service. A value this SDK does not recognise is
//     a flow it does not understand, and treating an unknown flow as a human is the
//     direction that opens a user-only administrative surface.
//  5. no "svc" and no sub_type -> user.
//
// RULE 5 IS THE ONE THAT NEEDS THE ARGUMENT, because it used to read the other way
// ("anything not explicitly a user is a service"). That default was written when the
// classification only fed the audit column, where over-reporting "service" is the
// harmless direction. It is wrong now, and it was already producing a wrong audit
// trail: maintainerd-auth does NOT stamp sub_type on the interactive
// authorization-code + PKCE login the consoles use, so under the old default EVERY
// signed-in human was recorded as a service — collapsing exactly the distinction the
// actor_kind column exists to preserve. Meanwhile every machine path Auth has DOES
// stamp something: client_credentials always sets "client" or "service", workload
// federation sets "service", device and CIBA set their own. So "neither claim
// present" is not an unknown caller, it is the shape of an interactive login, and
// rule 4 keeps the genuinely unknown cases on the machine side.
//
// A service that mints its own tokens some other way should set Principal.Kind
// itself rather than rely on this; an empty Kind is refused by every constrained
// surface (Actor.Permits), which is the fail-closed direction.
// A nil map reads as "neither claim present" — rule 5 — because indexing a nil map is
// legal and yields the zero value, and a verified token that carries no extra claims
// at all has the same shape as an interactive login.
func ActorKindFromClaims(raw map[string]any) string {
	if strings.TrimSpace(stringClaim(raw, ClaimService)) != "" {
		return ActorKindService
	}
	subjectType := strings.ToLower(strings.TrimSpace(stringClaim(raw, ClaimSubjectType)))
	if subjectType == "" {
		return ActorKindUser
	}
	if _, human := humanSubjectTypes[subjectType]; human {
		return ActorKindUser
	}
	if _, machine := machineSubjectTypes[subjectType]; machine {
		return ActorKindService
	}
	// Rule 4: a sub_type this SDK does not recognise is a flow it does not
	// understand, and the safe reading of "I do not know what this is" on a
	// user-only administrative surface is "not a human".
	return ActorKindService
}

// stringClaim reads a claim that should be a string, tolerating the absence.
func stringClaim(raw map[string]any, key string) string {
	s, _ := raw[key].(string)
	return s
}
