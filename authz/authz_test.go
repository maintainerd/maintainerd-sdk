package authz

import (
	"slices"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/maintainerd/sdk/auth"
)

// A service's permission vocabulary, as a service would declare it. These mirror
// maintainerd-secret's, which is the implementation this package was promoted from.
const (
	permReadMetadata = "secret:ReadMetadata"
	permGetSecret    = "secret:GetSecret"
	permPutSecret    = "secret:PutSecret"
	permDeleteSecret = "secret:DeleteSecret"
	permManageFolder = "secret:ManageFolder"
	permReadAudit    = "secret:ReadAudit"
	permAdmin        = "secret:Admin"
)

const prodPassword = "mrn:secret:acme:billing:secret/prod/db/PASSWORD"

// testMap is the permission table the guard tests enforce against.
var testMap = Map{
	Prefix: "/api/v1/",
	Routes: map[string]Perms{
		"projects": {Read: permReadMetadata, Write: permManageFolder},
		"secrets":  {Read: permReadMetadata, Write: permReadMetadata},
		"audit":    {Read: permReadAudit, Write: permAdmin},
	},
	Methods: map[string]string{
		"/maintainerd.secret.v1.SecretService/Describe": permReadMetadata,
		"/maintainerd.secret.v1.SecretService/Reveal":   permGetSecret,
		"/maintainerd.secret.v1.SecretService/Put":      permPutSecret,
	},
	OperationPermissions: []string{permGetSecret, permPutSecret, permDeleteSecret},
	BlanketActions:       []string{permAdmin},
	ExemptPaths:          []string{"/healthz", "/api/v1/setup"},
	ExemptMethods:        []string{"/grpc.health.v1.Health/Check"},
}

// blanket returns a principal carrying the test map's blanket vocabulary, the way the
// Guard populates a verified one.
func blanket(grants ...Grant) *Principal {
	return &Principal{Grants: grants, BlanketActions: testMap.BlanketActions}
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

func TestParseGrant(t *testing.T) {
	g := ParseGrant("secret:GetSecret")
	if g.Action != permGetSecret {
		t.Errorf("Action = %q, want %q", g.Action, permGetSecret)
	}
	if g.Resource != "" {
		t.Errorf("Resource = %q, want empty (a bare grant is service-wide)", g.Resource)
	}

	g = ParseGrant("secret:GetSecret=mrn:secret:acme:billing:secret/staging/*")
	if g.Action != permGetSecret {
		t.Errorf("Action = %q, want %q", g.Action, permGetSecret)
	}
	if want := "mrn:secret:acme:billing:secret/staging/*"; g.Resource != want {
		t.Errorf("Resource = %q, want %q — only the FIRST '=' splits, so a pattern containing one survives", g.Resource, want)
	}
	if g.String() != "secret:GetSecret=mrn:secret:acme:billing:secret/staging/*" {
		t.Errorf("String() = %q, want the claim form back", g.String())
	}

	// Whitespace around a claim entry is not part of the action.
	if g := ParseGrant("  secret:GetSecret  "); g.Action != permGetSecret {
		t.Errorf("Action = %q, want the trimmed action", g.Action)
	}
}

func TestParseGrantsSkipsEmptyEntries(t *testing.T) {
	got := ParseGrants([]string{permGetSecret, "", "   ", permPutSecret})
	if len(got) != 2 {
		t.Fatalf("ParseGrants returned %d grants, want 2", len(got))
	}
	if got[0].Action != permGetSecret || got[1].Action != permPutSecret {
		t.Errorf("ParseGrants = %v", got)
	}
}

// TestUnqualifiedGrantIsServiceWide states the one compatibility trade in the design,
// as a test, so it cannot change silently.
func TestUnqualifiedGrantIsServiceWide(t *testing.T) {
	p := blanket(Grant{Action: permGetSecret})
	if !p.Allows(permGetSecret, prodPassword) {
		t.Error("a bare grant must authorize any resource in the service")
	}
	if !p.Allows(permGetSecret, "mrn:secret:other:other:secret/dev/X") {
		t.Error("a bare grant is service-wide, including other tenants")
	}
}

// TestScopedGrantIsConfinedToItsPattern is the point of MRN-level authorization.
func TestScopedGrantIsConfinedToItsPattern(t *testing.T) {
	p := blanket(Grant{Action: permGetSecret, Resource: "mrn:secret:acme:billing:secret/staging/*"})
	if !p.Allows(permGetSecret, "mrn:secret:acme:billing:secret/staging/db/PASSWORD") {
		t.Error("a staging grant must allow a staging resource")
	}
	if p.Allows(permGetSecret, prodPassword) {
		t.Error("a staging grant must not reach prod")
	}
}

// TestGrantsFromAnotherServiceNeverAuthorizeThisOne: the service segment is a hard
// world boundary, even when the action name happens to line up.
func TestCrossWorldGrantAndResourceMismatch(t *testing.T) {
	// A grant scoped to storage's world cannot authorize a secret resource.
	p := blanket(Grant{Action: permGetSecret, Resource: "mrn:storage:acme:billing:*"})
	if p.Allows(permGetSecret, prodPassword) {
		t.Error("a grant written for the storage world must not authorize a secret resource")
	}

	// A grant scoped to another tenant cannot authorize this tenant's resource, and
	// the prefix-lookalike tenant is the case a flat glob would get wrong.
	p = blanket(Grant{Action: permGetSecret, Resource: "mrn:secret:acmecorp:*:*"})
	if p.Allows(permGetSecret, prodPassword) {
		t.Error("a grant for tenant acmecorp must not reach tenant acme")
	}

	// A grant scoped to another project likewise.
	p = blanket(Grant{Action: permGetSecret, Resource: "mrn:secret:acme:marketing:*"})
	if p.Allows(permGetSecret, prodPassword) {
		t.Error("a grant for project marketing must not reach project billing")
	}
}

// TestMetadataGrantIsNotARevealGrant is the split the contract requires: browsing
// which secrets exist and revealing a value are different privileges.
func TestMetadataGrantIsNotARevealGrant(t *testing.T) {
	p := blanket(Grant{Action: permReadMetadata})
	if !p.Allows(permReadMetadata, prodPassword) {
		t.Error("a metadata grant must allow metadata")
	}
	if p.Allows(permGetSecret, prodPassword) {
		t.Error("metadata browsing and value reveal are different privileges")
	}
}

// TestBlanketActionImpliesEveryActionButNotAWiderScope: a service's blanket action
// covers every verb, and NEVER widens resource scope.
func TestBlanketActionImpliesEveryActionButNotAWiderScope(t *testing.T) {
	p := blanket(Grant{Action: permAdmin, Resource: "mrn:secret:acme:*:*"})
	if !p.Allows(permGetSecret, prodPassword) {
		t.Error("a blanket grant must cover a read")
	}
	if !p.Allows(permDeleteSecret, prodPassword) {
		t.Error("a blanket grant must cover a delete")
	}
	if p.Allows(permGetSecret, "mrn:secret:other:billing:secret/prod/X") {
		t.Error("a blanket grant written for one tenant stays in that tenant")
	}
}

// TestBlanketActionsMustBeDeclared: the SDK owns no service's vocabulary, so an admin
// action nobody declared is just another exact-match action.
func TestBlanketActionsMustBeDeclared(t *testing.T) {
	undeclared := &Principal{Grants: []Grant{{Action: permAdmin}}}
	if undeclared.Allows(permGetSecret, prodPassword) {
		t.Error("an undeclared blanket action must not silently cover other actions")
	}
	if !undeclared.Allows(permAdmin, prodPassword) {
		t.Error("an undeclared blanket action must still work as an exact action")
	}

	// The wildcard is blanket without any declaration.
	wildcard := &Principal{Grants: []Grant{{Action: WildcardAction}}}
	if !wildcard.Allows(permGetSecret, prodPassword) {
		t.Error("the wildcard action is blanket by construction")
	}
}

// TestDenyByDefault covers every fail-closed path in one place.
func TestDenyByDefault(t *testing.T) {
	var nilPrincipal *Principal
	if nilPrincipal.Allows(permGetSecret, prodPassword) {
		t.Error("a nil principal must be denied")
	}
	if nilPrincipal.HasAction(permGetSecret) || nilPrincipal.HasScope(permGetSecret) {
		t.Error("a nil principal carries nothing")
	}

	if (&Principal{}).Allows(permGetSecret, prodPassword) {
		t.Error("a principal with no grants must be denied")
	}

	// A malformed grant pattern is treated as no grant, never as a wildcard.
	broken := blanket(Grant{Action: permGetSecret, Resource: "not-an-mrn"})
	if broken.Allows(permGetSecret, prodPassword) {
		t.Error("an unparseable grant pattern must never widen to a wildcard")
	}

	// A mid-path wildcard is rejected by the parser, so a grant carrying one grants
	// nothing rather than matching loosely.
	midPath := blanket(Grant{Action: permGetSecret, Resource: "mrn:secret:acme:billing:secret/*/PASSWORD"})
	if midPath.Allows(permGetSecret, prodPassword) {
		t.Error("a grant with a mid-path wildcard must not authorize anything")
	}

	// A resource the service could not render as a valid MRN is refused rather than
	// matched loosely.
	wide := blanket(Grant{Action: permGetSecret})
	if wide.Allows(permGetSecret, "not-an-mrn") {
		t.Error("an unparseable resource must be denied")
	}
	if wide.Allows("", prodPassword) {
		t.Error("an empty action must be denied")
	}
	if wide.Allows(permGetSecret, "") {
		t.Error("an empty resource must be denied")
	}
}

// TestNoActionPrefixMatching: "secret:Get*" must not be a grant whose blast radius
// changes every time an RPC is added.
func TestNoActionPrefixMatching(t *testing.T) {
	p := blanket(Grant{Action: "secret:Get*"})
	if p.Allows(permGetSecret, prodPassword) {
		t.Error("actions are matched exactly; there is no prefix matching")
	}
}

func TestAllowsAny(t *testing.T) {
	p := blanket(Grant{Action: permPutSecret})
	if !p.AllowsAny(prodPassword, permGetSecret, permPutSecret) {
		t.Error("AllowsAny must succeed when any listed action is granted")
	}
	if p.AllowsAny(prodPassword, permGetSecret, permDeleteSecret) {
		t.Error("AllowsAny must fail when no listed action is granted")
	}
}

// TestHasActionIgnoresResourceScope: the surface guard runs before the target MRN is
// known, so it must see a scoped grant as carrying its action.
func TestHasActionIgnoresResourceScope(t *testing.T) {
	p := blanket(Grant{Action: permGetSecret, Resource: "mrn:secret:acme:billing:secret/staging/*"})
	if !p.HasAction(permGetSecret) {
		t.Error("HasAction must ignore resource scope")
	}
	if p.HasAction(permDeleteSecret) {
		t.Error("HasAction must still be action-exact")
	}
}

// ---------------------------------------------------------------------------
// Claim shapes
// ---------------------------------------------------------------------------

// TestPrincipalFromClaimsReadsBothClaimShapes. Auth mints entitlements as a
// space-separated "scope" string AND as a "permissions" array depending on how the
// grant was issued. A PEP that reads only one silently authorizes half the fleet.
func TestPrincipalFromClaimsReadsBothClaimShapes(t *testing.T) {
	c := &auth.Claims{
		Subject: "user-1",
		Tenant:  "acme",
		Scopes:  []string{permReadMetadata}, // from the space-separated "scope" string
		Raw: jwt.MapClaims{
			ClaimPermissions: []any{
				"secret:GetSecret=mrn:secret:acme:billing:secret/staging/*",
				permPutSecret,
				42, // a non-string entry is skipped rather than panicking
				"",
			},
			ClaimSubjectType: "user",
		},
	}
	p := PrincipalFromClaims(c)
	p.BlanketActions = testMap.BlanketActions

	if p.Subject != "user-1" {
		t.Errorf("Subject = %q", p.Subject)
	}
	if p.Tenant != "acme" {
		t.Errorf("Tenant = %q", p.Tenant)
	}
	if p.Kind != ActorKindUser {
		t.Errorf("Kind = %q, want %q", p.Kind, ActorKindUser)
	}
	if !p.HasScope(permReadMetadata) || !p.HasScope(permPutSecret) {
		t.Errorf("Scopes = %v, want the raw claim entries from both shapes", p.Scopes)
	}
	if !p.Allows(permReadMetadata, prodPassword) {
		t.Error("the scope-string grant must authorize")
	}
	if !p.Allows(permPutSecret, prodPassword) {
		t.Error("the permissions-array grant must authorize")
	}
	if !p.Allows(permGetSecret, "mrn:secret:acme:billing:secret/staging/db/X") {
		t.Error("the scoped permissions-array grant must authorize inside its pattern")
	}
	if p.Allows(permGetSecret, prodPassword) {
		t.Error("the scoped permissions-array grant must stay inside its pattern")
	}
}

// TestPrincipalFromClaimsDefaultsToServiceKind: mislabelling a workload as a human in
// the audit trail is the less misleading direction.
func TestPrincipalFromClaimsDefaultsToServiceKind(t *testing.T) {
	p := PrincipalFromClaims(&auth.Claims{Subject: "svc-1", Raw: jwt.MapClaims{}})
	if p.Kind != ActorKindService {
		t.Errorf("Kind = %q, want %q", p.Kind, ActorKindService)
	}

	// tenant_slug is the fallback tenant claim.
	p = PrincipalFromClaims(&auth.Claims{Raw: jwt.MapClaims{ClaimTenantSlug: "acme"}})
	if p.Tenant != "acme" {
		t.Errorf("Tenant = %q, want the tenant_slug fallback", p.Tenant)
	}

	if PrincipalFromClaims(nil) != nil {
		t.Error("nil claims must produce a nil principal, never an empty authorized one")
	}
}

// ---------------------------------------------------------------------------
// The permission map: allowlist + declared permissions
// ---------------------------------------------------------------------------

// TestDeclaredPermissionsCoversEverySurfacePermission is the anti-drift check.
// Registration and enforcement are two halves of one fact: when they drift the
// failure is silent and total, because the guard demands a permission that exists
// nowhere in Auth.
func TestDeclaredPermissionsCoversEverySurfacePermission(t *testing.T) {
	declared := testMap.DeclaredPermissions()
	for key, p := range testMap.Routes {
		if !slices.Contains(declared, p.Read) {
			t.Errorf("route %q read permission %q is not declared", key, p.Read)
		}
		if !slices.Contains(declared, p.Write) {
			t.Errorf("route %q write permission %q is not declared", key, p.Write)
		}
	}
	for method, p := range testMap.Methods {
		if !slices.Contains(declared, p) {
			t.Errorf("method %q permission %q is not declared", method, p)
		}
	}
	for _, p := range testMap.OperationPermissions {
		if !slices.Contains(declared, p) {
			t.Errorf("operation permission %q is not declared", p)
		}
	}
	if !slices.Contains(declared, permAdmin) {
		t.Error("a blanket action must be declared — Auth has to be able to mint it")
	}
}

func TestDeclaredPermissionsIsSortedAndDeduped(t *testing.T) {
	declared := testMap.DeclaredPermissions()
	if !slices.IsSorted(declared) {
		t.Error("an unsorted list makes setup logs and diffs unreadable")
	}
	seen := map[string]bool{}
	for _, p := range declared {
		if seen[p] {
			t.Errorf("%q appears twice", p)
		}
		seen[p] = true
	}
	// permReadMetadata is the read permission of two routes and a gRPC method.
	if !slices.Contains(declared, permReadMetadata) {
		t.Error("a permission used by several surfaces must still be declared once")
	}
	// The wildcard is never registered in Auth — it is the SDK's own construct.
	wildcardMap := Map{BlanketActions: []string{WildcardAction, permAdmin}}
	if got := wildcardMap.DeclaredPermissions(); !slices.Equal(got, []string{permAdmin}) {
		t.Errorf("DeclaredPermissions = %v, want the wildcard excluded", got)
	}
}

func TestDeclaredPermissionsOfAZeroMapIsEmpty(t *testing.T) {
	if got := (Map{}).DeclaredPermissions(); len(got) != 0 {
		t.Errorf("the zero Map declares %v, want nothing", got)
	}
}

// TestRequiredIsAnAllowlist: ok=false for anything unmapped is what makes adding a
// route without deciding its permission fail closed.
func TestRequiredIsAnAllowlist(t *testing.T) {
	if _, ok := testMap.Required(Surface{Path: "/api/v1/brand-new-thing", HTTPMethod: "GET"}); ok {
		t.Error("an unmapped route must not resolve to a permission")
	}
	if _, ok := testMap.Required(Surface{FullMethod: "/maintainerd.secret.v1.SecretService/BrandNew"}); ok {
		t.Error("an unmapped gRPC method must not resolve to a permission")
	}
	if _, ok := (Map{}).Required(Surface{Path: "/anything", HTTPMethod: "GET"}); ok {
		t.Error("the zero Map must map nothing")
	}
}

func TestRequiredDerivesReadWriteFromTheVerb(t *testing.T) {
	for _, tc := range []struct {
		method string
		want   string
	}{
		{"GET", permReadAudit},
		{"HEAD", permReadAudit},
		{"POST", permAdmin},
		{"PUT", permAdmin},
		{"PATCH", permAdmin},
		{"DELETE", permAdmin},
	} {
		got, ok := testMap.Required(Surface{Path: "/api/v1/audit", HTTPMethod: tc.method})
		if !ok {
			t.Fatalf("%s /api/v1/audit is unmapped", tc.method)
		}
		if got != tc.want {
			t.Errorf("%s /api/v1/audit requires %q, want %q", tc.method, got, tc.want)
		}
	}
}

func TestFirstSegment(t *testing.T) {
	for _, tc := range []struct{ prefix, path, want string }{
		{"/api/v1/", "/api/v1/secrets", "secrets"},
		{"/api/v1/", "/api/v1/secrets/reveal", "secrets"},
		{"/api/v1/", "/api/v1/setup/status", "setup"},
		{"/api/v1/", "/healthz", ""},
		{"/api/v1/", "/api/v2/secrets", ""},
		{"", "/secrets/reveal", "secrets"},
		{"", "/", ""},
	} {
		if got := FirstSegment(tc.prefix, tc.path); got != tc.want {
			t.Errorf("FirstSegment(%q, %q) = %q, want %q", tc.prefix, tc.path, got, tc.want)
		}
	}
}

// TestExemptPathsMatchOnASegmentBoundary: a plain prefix match would let an exemption
// for /api/v1/setup silently unguard /api/v1/setup-admin.
func TestExemptPathsMatchOnASegmentBoundary(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/healthz", true},
		{"/healthz/live", true},
		{"/api/v1/setup", true},
		{"/api/v1/setup/status", true},
		{"/api/v1/setup-admin", false},
		{"/healthzz", false},
		{"/api/v1/secrets", false},
	} {
		if got := testMap.IsExempt(Surface{Path: tc.path, HTTPMethod: "GET"}); got != tc.want {
			t.Errorf("IsExempt(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestExemptMethodsMatchExactly(t *testing.T) {
	if !testMap.IsExempt(Surface{FullMethod: "/grpc.health.v1.Health/Check"}) {
		t.Error("the health method must be exempt")
	}
	if testMap.IsExempt(Surface{FullMethod: "/grpc.health.v1.Health/Watch"}) {
		t.Error("only the listed methods are exempt")
	}
}

func TestExemptPredicateIsConsultedToo(t *testing.T) {
	m := Map{Exempt: func(s Surface) bool { return s.HTTPMethod == "OPTIONS" }}
	if !m.IsExempt(Surface{Path: "/api/v1/secrets", HTTPMethod: "OPTIONS"}) {
		t.Error("the Exempt predicate must be consulted")
	}
	if m.IsExempt(Surface{Path: "/api/v1/secrets", HTTPMethod: "GET"}) {
		t.Error("the Exempt predicate must not exempt everything")
	}
}

func TestCustomRouteKey(t *testing.T) {
	m := Map{
		Routes:   map[string]Perms{"/api/v1/secrets/reveal": {Read: permGetSecret, Write: permGetSecret}},
		RouteKey: func(s Surface) string { return s.Path },
	}
	got, ok := m.Required(Surface{Path: "/api/v1/secrets/reveal", HTTPMethod: "POST"})
	if !ok || got != permGetSecret {
		t.Errorf("Required = (%q, %v), want (%q, true)", got, ok, permGetSecret)
	}
	if _, ok := m.Required(Surface{Path: "/api/v1/secrets", HTTPMethod: "POST"}); ok {
		t.Error("a custom route key must still be an allowlist")
	}
}
