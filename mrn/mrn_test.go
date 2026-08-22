package mrn

import (
	"strings"
	"testing"
)

// These mirror maintainerd-auth's own MRN cases. Every implementation of this
// grammar must agree exactly: a pattern that matches in Auth's policy engine and
// not in an enforcement point is a locked-out operator, and one that matches in an
// enforcement point but not in Auth is an unauthorized read.

func TestParseRoundTrips(t *testing.T) {
	m, err := Parse("mrn:secret:acme:billing-app:secret/prod/db/primary/PASSWORD")
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if m.Service != "secret" {
		t.Errorf("Service = %q, want secret", m.Service)
	}
	if m.Tenant != "acme" {
		t.Errorf("Tenant = %q, want acme", m.Tenant)
	}
	if m.Project != "billing-app" {
		t.Errorf("Project = %q, want billing-app", m.Project)
	}
	if m.ResourcePath != "secret/prod/db/primary/PASSWORD" {
		t.Errorf("ResourcePath = %q", m.ResourcePath)
	}
	if got, want := m.String(), "mrn:secret:acme:billing-app:secret/prod/db/primary/PASSWORD"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// TestColonInResourcePathIsNeverReSplit: SplitN with a limit of 5 keeps a
// resource-path that legitimately contains a colon intact. Re-splitting it would
// silently shorten the path and match a different resource.
func TestColonInResourcePathIsNeverReSplit(t *testing.T) {
	const raw = "mrn:secret:acme:billing:secret/prod/url/DSN:5432"
	m, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if m.ResourcePath != "secret/prod/url/DSN:5432" {
		t.Errorf("ResourcePath = %q, want the colon preserved", m.ResourcePath)
	}
	if m.String() != raw {
		t.Errorf("String() = %q, want %q", m.String(), raw)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"",
		"secret:acme:billing:x",                 // no scheme
		"mrn:secret:acme:billing",               // four parts
		"mrn::acme:billing:secret/x",            // empty service
		"mrn:secret:ACME:billing:secret/x",      // uppercase segment
		"mrn:secret:acme:BILLING:secret/x",      // uppercase project
		"mrn:SECRET:acme:billing:secret/x",      // uppercase service
		"mrn:secret:acme:billing:/secret/x",     // leading slash
		"mrn:secret:acme:billing:secret/*",      // a concrete resource that looks like a pattern
		"mrn:secret:acme:billing:",              // empty resource path
		"mrn:secret:acme:billing:secret/\x01/X", // unprintable byte
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) must fail", bad)
		}
	}
}

func TestParsePatternRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"",
		"secret:acme:*:*",                   // no scheme
		"mrn:secret:acme:*",                 // four parts
		"mrn::acme:billing:*",               // empty service
		"mrn:secret:ACME:billing:*",         // uppercase segment
		"mrn:secret:acme:billing:/secret/*", // leading slash on the literal part
		"mrn:secret:acme:billing:",          // empty resource path
	} {
		if _, err := ParsePattern(bad); err == nil {
			t.Errorf("ParsePattern(%q) must fail", bad)
		}
	}
}

func TestParsePatternRoundTrips(t *testing.T) {
	const raw = "mrn:secret:acme:billing:secret/staging/*"
	p, err := ParsePattern(raw)
	if err != nil {
		t.Fatalf("ParsePattern: unexpected error: %v", err)
	}
	if p.String() != raw {
		t.Errorf("String() = %q, want %q", p.String(), raw)
	}
}

// TestWildcardNeverSpansAColon is the property that makes an MRN pattern usable as a
// tenant-isolation boundary. A flat glob would let "acme*" reach "acmecorp".
func TestWildcardNeverSpansAColon(t *testing.T) {
	matched, err := MatchPattern("mrn:secret:acme:*:*", "mrn:secret:acmecorp:billing:secret/prod/X")
	if err != nil {
		t.Fatalf("MatchPattern: unexpected error: %v", err)
	}
	if matched {
		t.Error("a grant for tenant acme must not reach tenant acmecorp")
	}
}

// TestEmptyPatternSegmentIsAScopeBoundary: an empty segment matches ONLY an empty
// segment. Treating it as a wildcard would turn "narrower scope" into "broader grant".
func TestEmptyPatternSegmentIsAScopeBoundary(t *testing.T) {
	// A tenant-scoped pattern (empty project) speaks only for tenant-scoped resources.
	mustMatch(t, "mrn:secret:acme::project", "mrn:secret:acme::project", true)
	mustMatch(t, "mrn:secret:acme::project", "mrn:secret:acme:billing:project", false)

	// A platform-scoped pattern (empty tenant AND project) likewise.
	mustMatch(t, "mrn:core:::agent/agent-1", "mrn:core:::agent/agent-1", true)
	mustMatch(t, "mrn:core:::agent/agent-1", "mrn:core:acme::agent/agent-1", false)

	// "*" does match an empty segment, which is the documented asymmetry.
	mustMatch(t, "mrn:secret:acme:*:project", "mrn:secret:acme::project", true)
}

// TestResourcePathPrefixMatching is the "may read staging, not prod" grant, in its
// raw form.
func TestResourcePathPrefixMatching(t *testing.T) {
	const staging = "mrn:secret:acme:billing:secret/staging/*"
	mustMatch(t, staging, "mrn:secret:acme:billing:secret/staging/db/PASSWORD", true)
	mustMatch(t, staging, "mrn:secret:acme:billing:secret/prod/db/PASSWORD", false)
}

// TestFolderPathsAreDisjointFromSecretPaths: a grant over secrets must not carry the
// ability to move the folders those secrets live in, because a move rewrites the MRNs
// of everything beneath it.
func TestFolderPathsAreDisjointFromSecretPaths(t *testing.T) {
	mustMatch(t, "mrn:secret:acme:billing:secret/prod/*", "mrn:secret:acme:billing:folder/prod/db", false)
}

// TestServiceSegmentIsolatesWorlds: a grant minted for one service must never
// authorize a resource owned by another, even with everything else wildcarded.
func TestServiceSegmentIsolatesWorlds(t *testing.T) {
	mustMatch(t, "mrn:secret:*:*:*", "mrn:storage:acme:billing:bucket/invoices", false)
	mustMatch(t, "mrn:*:*:*:*", "mrn:storage:acme:billing:bucket/invoices", true)
}

// TestMidPathWildcardsAreRejectedAtParseTime: rejecting them where they are written
// beats mis-matching them where they are evaluated, which would be invisible.
func TestMidPathWildcardsAreRejectedAtParseTime(t *testing.T) {
	_, err := ParsePattern("mrn:secret:acme:billing:secret/*/PASSWORD")
	if err == nil {
		t.Fatal("a mid-path wildcard must be rejected at parse time")
	}
	if !strings.Contains(err.Error(), "mid-path wildcards") {
		t.Errorf("error %q should name mid-path wildcards", err)
	}
	if _, err := ParsePattern("mrn:secret:acme:billing:secret/prod/*/*"); err == nil {
		t.Error("multiple wildcards must be rejected at parse time")
	}
}

// TestMatchPatternReportsEvaluationFailureRatherThanFalse lets a caller distinguish
// "does not match" from "cannot be evaluated" and fail closed on the latter.
func TestMatchPatternReportsEvaluationFailureRatherThanFalse(t *testing.T) {
	if _, err := MatchPattern("not-an-mrn", "mrn:secret:acme:billing:secret/prod/X"); err == nil {
		t.Error("an unparseable pattern must report an error")
	}
	if _, err := MatchPattern("mrn:secret:acme:billing:*", "not-an-mrn"); err == nil {
		t.Error("an unparseable resource must report an error")
	}
}

func TestBareWildcardMatchesEverything(t *testing.T) {
	mustMatch(t, "mrn:secret:*:*:*", "mrn:secret:acme:billing:secret/prod/db/X", true)
}

func TestNewBuildsAnMRN(t *testing.T) {
	m := New("secret", "acme", "billing", "secret/prod/X")
	if got, want := m.String(), "mrn:secret:acme:billing:secret/prod/X"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if !IsMRN(m.String()) {
		t.Error("IsMRN must accept a rendered MRN")
	}
	if IsMRN("arn:aws:s3:::bucket/key") {
		t.Error("IsMRN must reject a foreign scheme")
	}
}

// TestPatternMatchesReusesAParsedPattern covers the hot path a policy evaluation
// takes: parse the grant once, match it against many resources.
func TestPatternMatchesReusesAParsedPattern(t *testing.T) {
	p, err := ParsePattern("mrn:secret:acme:billing:secret/staging/*")
	if err != nil {
		t.Fatalf("ParsePattern: %v", err)
	}
	hit, err := Parse("mrn:secret:acme:billing:secret/staging/db/PASSWORD")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	miss, err := Parse("mrn:secret:acme:billing:secret/prod/db/PASSWORD")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.Matches(hit) {
		t.Error("staging pattern must match a staging resource")
	}
	if p.Matches(miss) {
		t.Error("staging pattern must not match a prod resource")
	}
}

func mustMatch(t *testing.T, pattern, resource string, want bool) {
	t.Helper()
	got, err := MatchPattern(pattern, resource)
	if err != nil {
		t.Fatalf("MatchPattern(%q, %q): unexpected error: %v", pattern, resource, err)
	}
	if got != want {
		t.Errorf("MatchPattern(%q, %q) = %v, want %v", pattern, resource, got, want)
	}
}
