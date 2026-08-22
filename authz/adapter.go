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
	// ClaimSubjectType is Auth's principal-kind claim ("user" / "service").
	ClaimSubjectType = "sub_type"
	// ClaimTenantSlug is Auth's tenant claim on tokens that do not use "tenant".
	ClaimTenantSlug = "tenant_slug"
)

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
	p := &Principal{Subject: c.Subject, Tenant: c.Tenant, Kind: ActorKindService}

	p.Scopes = append(p.Scopes, c.Scopes...)
	if raw, ok := c.Raw[ClaimPermissions].([]any); ok {
		for _, entry := range raw {
			if s, ok := entry.(string); ok && strings.TrimSpace(s) != "" {
				p.Scopes = append(p.Scopes, s)
			}
		}
	}
	p.Grants = ParseGrants(p.Scopes)

	// Anything that is not explicitly a user is recorded as a service: mislabelling a
	// workload as a human in the audit trail is the less misleading direction.
	if st, _ := c.Raw[ClaimSubjectType].(string); strings.EqualFold(st, ActorKindUser) {
		p.Kind = ActorKindUser
	}
	if p.Tenant == "" {
		if t, _ := c.Raw[ClaimTenantSlug].(string); t != "" {
			p.Tenant = t
		}
	}
	return p
}
