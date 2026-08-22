// Package mrn parses and matches maintainerd resource names — the platform-wide
// resource identifier every authorization decision is keyed on:
//
//	mrn:<service>:<tenant>:<project>:<resource-path>
//
// WHY THIS LIVES IN THE SDK. maintainerd-auth is the policy authority (PDP) and
// every service enforces authorization itself (PEP). That only works if every
// enforcement point agrees EXACTLY with the authority on what a grant means: a
// pattern that matches in Auth's policy engine but not in a service is a
// locked-out operator, and one that matches in a service but not in Auth is an
// unauthorized read. Auth's own implementation is internal and a service must not
// take a source dependency on the identity service to answer a request, so the
// grammar is reproduced here — once, in the shared library every service and every
// third-party resource server already imports — rather than re-hand-rolled per
// service. The rules below are reproduced verbatim in behaviour and asserted by
// tests that mirror Auth's own cases.
//
// Matching is SEGMENT-AWARE rather than a flat glob. A flat glob lets a wildcard
// run across colon boundaries, so "mrn:secret:acme:*" would match
// "mrn:secret:acmecorp:x:y" — a grant written for tenant "acme" silently reaching
// into tenant "acmecorp". Confining a wildcard to the segment it was written in is
// what makes an MRN pattern safe to use as a tenant-isolation boundary.
//
// The package is stdlib-only and has no maintainerd dependencies, so it is safe to
// import from anywhere, including from a service's own hot path.
package mrn

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Prefix is the scheme prefix every MRN carries. A string carrying it is committed
// to this grammar: it either parses or is rejected, never silently treated as some
// other kind of identifier.
const Prefix = "mrn:"

// MRN is a parsed resource name identifying one concrete resource. It carries no
// wildcards; patterns are the separate Pattern type so a resource can never be
// accidentally interpreted as a grant over other resources.
type MRN struct {
	Service      string // owning service — required
	Tenant       string // tenant slug — empty means platform-scoped
	Project      string // project slug — empty means tenant-scoped
	ResourcePath string // service-defined path, e.g. "secret/prod/db/primary/PASSWORD"
}

// Pattern is a parsed pattern as written in a grant. Service/Tenant/Project are a
// literal, "*", or "" (tenant/project only); ResourcePath is a literal, a prefix
// ending in "*", or a bare "*".
type Pattern struct {
	Service      string
	Tenant       string
	Project      string
	ResourcePath string
}

// IsMRN reports whether s claims the MRN scheme. It is a cheap prefix check only —
// a true result means s must be held to this grammar, not that it is valid.
func IsMRN(s string) bool { return strings.HasPrefix(s, Prefix) }

// New builds the MRN of one concrete resource.
//
// The service segment is a parameter rather than a package constant because the SDK
// is shared: it is imported by every maintainerd service AND by third-party resource
// servers that own their own namespace. A service typically wraps this once with its
// own namespace baked in.
func New(service, tenant, project, resourcePath string) MRN {
	return MRN{Service: service, Tenant: tenant, Project: project, ResourcePath: resourcePath}
}

// String renders the canonical form. For any m produced by Parse,
// Parse(m.String()) round-trips to an identical value.
func (m MRN) String() string {
	return Prefix + m.Service + ":" + m.Tenant + ":" + m.Project + ":" + m.ResourcePath
}

// String renders the pattern's canonical form. For any p produced by ParsePattern,
// ParsePattern(p.String()) round-trips to an identical value.
func (p Pattern) String() string {
	return Prefix + p.Service + ":" + p.Tenant + ":" + p.Project + ":" + p.ResourcePath
}

// Parse parses s as a concrete resource MRN.
//
// Validation is strict and fail-closed: this is the identifier an authorization
// decision is keyed on, so anything ambiguous (wrong part count, a wildcard
// character, an unprintable byte) is rejected rather than normalized. A permissive
// parser would let two visually different strings authorize as the same resource.
func Parse(s string) (MRN, error) {
	parts, err := split(s)
	if err != nil {
		return MRN{}, err
	}
	m := MRN{Service: parts[1], Tenant: parts[2], Project: parts[3], ResourcePath: parts[4]}
	if m.Service == "" {
		return MRN{}, fmt.Errorf("mrn %q: service segment is required", s)
	}
	if !validSegment(m.Service) {
		return MRN{}, fmt.Errorf("mrn %q: service segment must contain only lowercase letters, digits, and hyphens", s)
	}
	if !validSegment(m.Tenant) {
		return MRN{}, fmt.Errorf("mrn %q: tenant segment must contain only lowercase letters, digits, and hyphens", s)
	}
	if !validSegment(m.Project) {
		return MRN{}, fmt.Errorf("mrn %q: project segment must contain only lowercase letters, digits, and hyphens", s)
	}
	if err := validResourcePath(m.ResourcePath); err != nil {
		return MRN{}, fmt.Errorf("mrn %q: %w", s, err)
	}
	return m, nil
}

// ParsePattern parses s as a grant pattern.
//
// Wildcard placement is restricted to shapes whose meaning is unambiguous: a
// segment is matched by "*" or by exact equality, and the resource-path glob is a
// literal, a trailing-"*" prefix, or a bare "*". Mid-path wildcards
// ("secret/*/PASSWORD") are rejected HERE, at parse time, rather than accepted and
// silently mis-matched at evaluation time where the miss would be invisible until
// it either denied legitimate access or granted more than the author intended.
func ParsePattern(s string) (Pattern, error) {
	parts, err := split(s)
	if err != nil {
		return Pattern{}, err
	}
	p := Pattern{Service: parts[1], Tenant: parts[2], Project: parts[3], ResourcePath: parts[4]}
	if p.Service == "" {
		// A concrete MRN can never have an empty service, so an empty service
		// pattern segment could match nothing — always an authoring mistake.
		return Pattern{}, fmt.Errorf("mrn pattern %q: service segment is required (a literal or *)", s)
	}
	if p.Service != "*" && !validSegment(p.Service) {
		return Pattern{}, fmt.Errorf("mrn pattern %q: service segment must be a literal (lowercase letters, digits, hyphens) or *", s)
	}
	if p.Tenant != "*" && !validSegment(p.Tenant) {
		return Pattern{}, fmt.Errorf("mrn pattern %q: tenant segment must be a literal (lowercase letters, digits, hyphens), *, or empty", s)
	}
	if p.Project != "*" && !validSegment(p.Project) {
		return Pattern{}, fmt.Errorf("mrn pattern %q: project segment must be a literal (lowercase letters, digits, hyphens), *, or empty", s)
	}
	if err := validPathPattern(p.ResourcePath); err != nil {
		return Pattern{}, fmt.Errorf("mrn pattern %q: %w", s, err)
	}
	return p, nil
}

// MatchPattern reports whether the pattern matches the concrete resource.
//
// It returns an error — never a silent false — when either side is invalid for its
// role, so a caller can distinguish "does not match" from "cannot be evaluated"
// and fail closed on the latter.
//
// Segment semantics:
//   - "*" matches anything, INCLUDING an empty segment.
//   - a literal matches only itself.
//   - an EMPTY pattern segment matches only an EMPTY resource segment. Scope is a
//     boundary, not a wildcard: a tenant-scoped pattern (mrn:secret:acme::…) speaks
//     only for tenant-scoped resources and must never leak into that tenant's
//     project-scoped ones — that would turn "narrower scope" into "broader grant".
//
// A wildcard never spans a colon boundary; that is the whole point versus a naive
// glob (see the package comment).
func MatchPattern(pattern, resource string) (bool, error) {
	p, err := ParsePattern(pattern)
	if err != nil {
		return false, err
	}
	r, err := Parse(resource)
	if err != nil {
		return false, err
	}
	return p.Matches(r), nil
}

// Matches applies the segment rules against an already-parsed resource. Use this
// when the same pattern is evaluated against many resources — parsing once and
// matching N times is the hot path in a policy evaluation.
func (p Pattern) Matches(r MRN) bool {
	if !segmentMatches(p.Service, r.Service) {
		return false
	}
	if !segmentMatches(p.Tenant, r.Tenant) {
		return false
	}
	if !segmentMatches(p.Project, r.Project) {
		return false
	}
	return pathMatches(p.ResourcePath, r.ResourcePath)
}

// split enforces the shared head shape: the "mrn:" prefix and exactly five parts,
// split with a limit of 5 so colons inside the resource-path are preserved rather
// than re-split into extra segments.
func split(s string) ([]string, error) {
	if !strings.HasPrefix(s, Prefix) {
		return nil, fmt.Errorf("%q does not start with %q", s, Prefix)
	}
	parts := strings.SplitN(s, ":", 5)
	if len(parts) != 5 {
		return nil, fmt.Errorf("%q must have exactly 5 colon-separated parts: mrn:<service>:<tenant>:<project>:<resource-path>", s)
	}
	return parts, nil
}

// validSegment reports whether s is a valid (possibly empty) name segment:
// lowercase letters, digits and hyphens only. The charset is deliberately narrow —
// no uppercase, no dots, no percent-escapes — so there is exactly one spelling of
// every segment and no case-folding ambiguity for an attacker to exploit.
func validSegment(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}

// validResourcePath validates the fifth part of a concrete MRN: required,
// printable, valid UTF-8, no leading "/" (which would create two spellings of one
// resource, only one of which a prefix grant would cover), and no "*" at all — a
// concrete resource that LOOKS like a pattern is rejected rather than matched
// literally, so a crafted resource string can never masquerade as a grant.
func validResourcePath(path string) error {
	if path == "" {
		return errors.New("resource-path is required")
	}
	if strings.ContainsRune(path, '*') {
		return errors.New("resource-path of a concrete resource must not contain *")
	}
	if strings.HasPrefix(path, "/") {
		return errors.New("resource-path must not start with /")
	}
	if !utf8.ValidString(path) {
		return errors.New("resource-path must be valid UTF-8")
	}
	for _, r := range path {
		if !unicode.IsPrint(r) {
			return errors.New("resource-path must contain only printable characters")
		}
	}
	return nil
}

// validPathPattern validates a pattern's resource-path glob: "*" may only be the
// whole path or its single final character, plus everything validResourcePath
// requires of the literal part.
func validPathPattern(path string) error {
	if path == "*" {
		return nil
	}
	literal := path
	if strings.ContainsRune(path, '*') {
		if strings.Count(path, "*") > 1 || !strings.HasSuffix(path, "*") {
			return errors.New("resource-path may use * only as a bare * or a single trailing wildcard (mid-path wildcards are not supported)")
		}
		literal = strings.TrimSuffix(path, "*")
	}
	return validResourcePath(literal)
}

func segmentMatches(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	// Covers literals AND the empty-pattern-matches-only-empty scope boundary.
	return pattern == value
}

func pathMatches(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, pattern[:len(pattern)-1])
	}
	return pattern == value
}
