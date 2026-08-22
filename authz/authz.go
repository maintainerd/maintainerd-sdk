// Package authz is the shared enforcement point (PEP) for maintainerd services and
// for third-party resource servers built beside them.
//
// # The PDP/PEP split
//
// maintainerd-auth is the policy AUTHORITY (the PDP): it owns principals, roles and
// grants, and it mints the tokens that carry them. Every service ENFORCES
// authorization itself (the PEP) — non-negotiable, because a service must run
// standalone with no gateway in front of it, because only the service knows its own
// resource ownership and tenant scoping, and because zero trust means traffic
// arrives from peers, agents and clients that never passed a gateway.
//
// "Do not repeat authz in every service" is solved by this library, not by moving
// enforcement out of the services: the CODE lives once (here), the POLICY lives once
// (in Auth), and the DECISION happens per-service. A bug here is a vulnerability in
// every service at once, so the package is deliberately small, additive, and
// fail-closed at every branch.
//
// # Two layers, two different questions
//
//  1. THE SURFACE GUARD (Guard.Middleware, Guard.UnaryInterceptor,
//     Guard.StreamInterceptor). Is the caller authenticated at all, and is the
//     surface it is calling one this service has decided a permission for? The
//     route/method Map doubles as an ALLOWLIST: an unmapped surface is DENIED even
//     to a valid token, so mounting a router or adding an RPC without deciding its
//     permission fails closed instead of shipping open.
//
//  2. THE OPERATION CHECK (Principal.Allows). May THIS principal perform THIS action
//     on THIS resource? This is the one that matters, and it is MRN-level: the
//     caller's grants are matched against the target's
//     mrn:<service>:<tenant>:<project>:<resource-path>, which is what makes "may
//     read staging, must not read prod" expressible at all. A permission check that
//     stopped at the route would make every grant environment-wide.
//
// Both are required. Layer 1 without layer 2 is a service where anyone who may touch
// one resource may touch all of them; layer 2 without layer 1 is a service that
// answers unauthenticated callers.
//
// # The grant grammar
//
// A grant is one entry of a token's scope/permissions claim:
//
//	secret:ReadMetadata                                        — action, service-wide
//	secret:GetSecret=mrn:secret:acme:billing:secret/staging/*   — action, scoped
//
// A BARE action is SERVICE-WIDE (equivalent to `=mrn:<service>:*:*:*`).
// `action=pattern` NARROWS it to the resources the MRN pattern matches. See Grant.
//
// # Fail-closed startup
//
// Outside development, a missing auth configuration does not degrade to "open":
// Resolve returns ModeUnavailable and every guarded surface answers 503 /
// codes.Unavailable. In development it may open with a LOUD boot banner naming every
// guard that is off (Guard.LogBanner), because a silent dev-open default is how an
// unguarded service reaches production.
//
// # Relationship to the rest of the SDK
//
// This package supersedes scope-only enforcement (sdk/auth.RequireScope and
// maintainerd-kit's authz) for anything that needs resource-level decisions. Those
// remain valid and untouched for surfaces whose only question is "does this token
// carry scope X". Plug an existing sdk/auth.Verifier in with one call: SDKVerify.
package authz

import (
	"strings"

	"github.com/maintainerd/sdk/mrn"
)

// Actor kinds, as recorded on an audit row.
const (
	ActorKindUser    = "user"
	ActorKindService = "service"
)

// WildcardAction is the universal blanket action: a grant carrying it covers every
// required action. It is the ONLY blanket the SDK knows without configuration — a
// service's own admin action (e.g. "secret:Admin") is its vocabulary, not the
// platform's, and is declared via Map.BlanketActions.
const WildcardAction = "*"

// Grant is one entitlement: an action, optionally confined to an MRN pattern.
//
// THE GRANT GRAMMAR, as it appears in a token's scope/permissions claim:
//
//	secret:ReadMetadata                                        — action, service-wide
//	secret:GetSecret=mrn:secret:acme:billing:secret/staging/*   — action, scoped
//
// An UNQUALIFIED grant is service-wide (equivalent to `=mrn:<service>:*:*:*`). That
// is stated plainly rather than hidden because it is the one place this design
// trades safety for compatibility: a plain permission token minted by an Auth that
// knows nothing about MRNs still works, and the operator narrows it by writing the
// resource form. The narrow form is what makes per-environment grants expressible,
// and it is the form the console and Auth's policy authoring should emit.
//
// The separator is '=' and only the FIRST one splits, because an action never
// contains '=' while a resource pattern theoretically may.
type Grant struct {
	Action string
	// Resource is an MRN pattern, or "" for service-wide.
	Resource string
}

// ParseGrant parses one entry of a scope/permissions claim.
func ParseGrant(raw string) Grant {
	raw = strings.TrimSpace(raw)
	if i := strings.IndexByte(raw, '='); i >= 0 {
		return Grant{Action: strings.TrimSpace(raw[:i]), Resource: strings.TrimSpace(raw[i+1:])}
	}
	return Grant{Action: raw}
}

// ParseGrants parses a whole claim list, skipping empty entries.
func ParseGrants(raw []string) []Grant {
	out := make([]Grant, 0, len(raw))
	for _, s := range raw {
		g := ParseGrant(s)
		if g.Action == "" {
			continue
		}
		out = append(out, g)
	}
	return out
}

// String renders the grant back into claim form.
func (g Grant) String() string {
	if g.Resource == "" {
		return g.Action
	}
	return g.Action + "=" + g.Resource
}

// Principal is the verified identity of a caller, reduced to what authorization
// needs. It is what the surface guard places in the request context.
type Principal struct {
	// Subject is the principal as authenticated — an Auth subject, a service
	// identity, or a bootstrap controller. It is what belongs in an audit row's
	// actor column.
	Subject string
	// Kind is ActorKindUser or ActorKindService, recorded on the audit row so an
	// incident review can tell a human reading a resource from a workload reading it.
	Kind string
	// Tenant is the tenant slug the token asserts, when it asserts one. It is used
	// only as the DEFAULT tenant for a request that does not name one; it is never a
	// substitute for the grant check, because a token's own tenant claim says who the
	// caller is, not what it may read.
	Tenant string
	// Scopes is the raw claim list exactly as minted, preserved so scope-only checks
	// (HasScope) and audit logging see what the token actually said.
	Scopes []string
	// Grants is Scopes parsed into the grant grammar.
	Grants []Grant
	// BlanketActions are the SERVICE's own blanket actions — e.g. "secret:Admin" —
	// which cover every required action when granted. WildcardAction is always
	// blanket and need not be listed.
	//
	// The SDK cannot infer this: it is the service's action vocabulary, not the
	// platform's. Guard populates it from Map.BlanketActions on every principal it
	// verifies, so enforcement and declaration come from the same value; a Principal
	// built by hand (a test, a custom transport) sets it explicitly or gets
	// wildcard-only blanket coverage.
	BlanketActions []string
}

// Claims is the maintainerd-secret / maintainerd-core spelling of Principal, kept as
// an alias so both call sites read naturally and neither has to convert.
type Claims = Principal

// Allows reports whether this principal may perform action on resourceMRN.
//
// This is the operation check — layer 2 — and the only one that can enforce
// "may read staging, must not read prod". Call it in the handler, with the target's
// MRN, in addition to whatever the surface guard already required.
//
// Deny-by-default at every step: no principal, no action, no resource, no grants, an
// unparseable pattern, an unparseable resource — all false. A malformed pattern is
// treated as no grant rather than as a wildcard, which is the only safe reading of
// "we cannot evaluate this".
func (p *Principal) Allows(action, resourceMRN string) bool {
	if p == nil || action == "" || resourceMRN == "" {
		return false
	}
	target, err := mrn.Parse(resourceMRN)
	if err != nil {
		// A resource the service itself could not render as a valid MRN is a bug, and
		// the fail-closed answer is the correct one: better a denied read than an
		// allowed one against an identifier nobody can reason about.
		return false
	}
	for _, g := range p.Grants {
		if !p.actionCovers(g.Action, action) {
			continue
		}
		if g.Resource == "" {
			return true
		}
		pattern, perr := mrn.ParsePattern(g.Resource)
		if perr != nil {
			continue
		}
		if pattern.Matches(target) {
			return true
		}
	}
	return false
}

// AllowsAny reports whether any of the actions is permitted on resourceMRN. It exists
// for operations that two different grants can authorize; it is not a way to avoid
// naming the action.
func (p *Principal) AllowsAny(resourceMRN string, actions ...string) bool {
	for _, a := range actions {
		if p.Allows(a, resourceMRN) {
			return true
		}
	}
	return false
}

// HasAction reports whether the principal carries an action at all, ignoring resource
// scope. It exists for the surface guard (layer 1), which runs before the target MRN
// is known — never for an operation decision, which must always be MRN-level.
func (p *Principal) HasAction(action string) bool {
	if p == nil || action == "" {
		return false
	}
	for _, g := range p.Grants {
		if p.actionCovers(g.Action, action) {
			return true
		}
	}
	return false
}

// HasScope reports whether the token carried the given raw scope string verbatim. It
// is the scope-only check, kept for parity with sdk/auth.Claims.HasScope and
// maintainerd-kit; prefer HasAction (which understands blanket actions) or Allows
// (which understands resources).
func (p *Principal) HasScope(scope string) bool {
	if p == nil {
		return false
	}
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope reports whether the token carried at least one of the scopes verbatim.
func (p *Principal) HasAnyScope(scopes ...string) bool {
	for _, s := range scopes {
		if p.HasScope(s) {
			return true
		}
	}
	return false
}

// actionCovers reports whether a granted action covers a required one.
// WildcardAction and the service's declared BlanketActions are blanket; everything
// else is exact. There is deliberately NO prefix matching on actions — "secret:Get*"
// would be a grant whose blast radius changes every time a new RPC is added.
func (p *Principal) actionCovers(granted, required string) bool {
	if granted == required || granted == WildcardAction {
		return true
	}
	for _, blanket := range p.BlanketActions {
		if blanket != "" && granted == blanket {
			return true
		}
	}
	return false
}
