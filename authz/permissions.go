package authz

import (
	"net/http"
	"sort"
	"strings"
)

// Surface identifies the API surface a request is addressed to. Exactly one of the
// HTTP fields or FullMethod is populated, so one Map and one Guard can decide for
// both transports without either knowing about the other.
type Surface struct {
	// Path is the HTTP request path ("" for gRPC).
	Path string
	// HTTPMethod is the HTTP verb ("" for gRPC).
	HTTPMethod string
	// FullMethod is the gRPC full method, "/pkg.Service/Method" ("" for HTTP).
	FullMethod string
}

// IsGRPC reports whether the surface is a gRPC method rather than an HTTP route.
func (s Surface) IsGRPC() bool { return s.FullMethod != "" }

// SurfaceFromRequest builds the Surface for an HTTP request.
func SurfaceFromRequest(r *http.Request) Surface {
	return Surface{Path: r.URL.Path, HTTPMethod: r.Method}
}

// Perms is the read/write permission pair guarding one HTTP route key. GET and HEAD
// require Read; every other verb requires Write.
//
// A pair, rather than one permission per route, because the read/write split is the
// one distinction that is universal across HTTP surfaces. When a segment carries
// reads on a mutating verb (a reveal that takes a POST body so the resource address
// never lands in an access log), set both to the same BASELINE permission and enforce
// the real privilege per-operation against the target MRN — which is the only place
// it can be enforced correctly anyway. The Map is the surface allowlist, not the
// authorization decision.
type Perms struct {
	Read  string
	Write string
}

// Map is a service's surface→permission table. It is an ALLOWLIST BY CONSTRUCTION:
// Required reports ok=false for anything not in it, and the Guard denies on
// ok=false. Mounting a router or registering an RPC without deciding its permission
// therefore fails closed instead of shipping an open surface.
//
// The zero Map denies everything, which is the correct default for a value nobody
// filled in.
type Map struct {
	// Prefix is the path prefix the Routes keys live under, e.g. "/api/v1/". A path
	// outside it yields an empty route key, which is never in Routes and is therefore
	// denied. Empty Prefix means keys are the first segment of the path itself.
	Prefix string

	// Routes maps a route key — by default the first path segment under Prefix — to
	// the baseline permission pair its surface requires.
	Routes map[string]Perms

	// Methods maps a gRPC full method ("/maintainerd.secret.v1.SecretService/Get") to
	// the permission it requires. gRPC has no read/write verb to derive from, so each
	// method names its permission outright.
	Methods map[string]string

	// OperationPermissions are permissions this service enforces DEEPER than the
	// surface — per-operation, against a target MRN, inside a handler. They demand no
	// route of their own but must still be registered in Auth, so they are declared
	// here rather than being invisible to DeclaredPermissions.
	OperationPermissions []string

	// BlanketActions are the service's own blanket actions (e.g. "secret:Admin"):
	// granted, they cover every required action. They do NOT widen resource scope — a
	// blanket grant written for one tenant is still confined to that tenant's MRNs.
	// WildcardAction is always blanket and need not be listed.
	BlanketActions []string

	// ExemptPaths are HTTP path prefixes served with NO guard at all: liveness and
	// readiness probes, and self-guarded bootstrap surfaces (a first-run setup
	// endpoint has to work before any token can be minted, so it carries its own
	// gate). A prefix matches only on a segment boundary, so "/api/v1/setup" exempts
	// "/api/v1/setup/status" but never "/api/v1/setupsomethingelse".
	//
	// No path is exempt by default. The SDK does not know which probe convention a
	// service follows, and guessing one would silently unguard a real route that
	// happened to share the name.
	ExemptPaths []string

	// ExemptMethods are gRPC full methods served with no guard — typically the
	// health-check and reflection services. Matched exactly.
	ExemptMethods []string

	// Exempt, when non-nil, is consulted in addition to ExemptPaths/ExemptMethods for
	// exemptions a prefix list cannot express.
	Exempt func(Surface) bool

	// RouteKey, when non-nil, replaces the default first-segment-under-Prefix
	// derivation — for a service that needs finer granularity than a segment.
	RouteKey func(Surface) string
}

// Required resolves the permission a surface demands.
//
// ok=false means the surface is NOT in the allowlist and MUST be denied. It is not
// the same as an empty permission string: a mapped surface whose permission is ""
// returns ("", true) and is treated as requiring nothing, which is only ever correct
// for a surface a service deliberately opened.
func (m Map) Required(s Surface) (string, bool) {
	if s.IsGRPC() {
		p, ok := m.Methods[s.FullMethod]
		return p, ok
	}
	p, ok := m.Routes[m.routeKey(s)]
	if !ok {
		return "", false
	}
	if s.HTTPMethod == http.MethodGet || s.HTTPMethod == http.MethodHead {
		return p.Read, true
	}
	return p.Write, true
}

// IsExempt reports whether a surface is outside the guard entirely.
func (m Map) IsExempt(s Surface) bool {
	if m.Exempt != nil && m.Exempt(s) {
		return true
	}
	if s.IsGRPC() {
		for _, method := range m.ExemptMethods {
			if method != "" && method == s.FullMethod {
				return true
			}
		}
		return false
	}
	for _, prefix := range m.ExemptPaths {
		if pathHasPrefix(s.Path, prefix) {
			return true
		}
	}
	return false
}

// DeclaredPermissions returns every permission this service's surfaces can demand —
// route pairs, gRPC methods, per-operation permissions and blanket actions — deduped
// and sorted.
//
// SETUP MUST REGISTER EXACTLY THIS LIST IN AUTH, and it must be DERIVED from the Map
// rather than hand-listed at the registration site. Enforcement and registration are
// two halves of one fact, and when they drift the failure is silent and total: the
// guard demands a permission that exists nowhere in Auth, so no token can ever carry
// it and every call answers 403 regardless of who makes it — with nothing in any log
// saying why. This exact drift caused a total silent API outage in maintainerd-core,
// which is why the derivation lives here and not in a second list somebody has to
// remember to update.
//
// The result is sorted because map iteration is randomised and a permission list that
// reorders every boot makes setup logs and diffs unreadable.
func (m Map) DeclaredPermissions() []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(m.Routes)*2+len(m.Methods)+len(m.OperationPermissions))
	add := func(p string) {
		if p == "" {
			return
		}
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, p := range m.Routes {
		add(p.Read)
		add(p.Write)
	}
	for _, p := range m.Methods {
		add(p)
	}
	for _, p := range m.OperationPermissions {
		add(p)
	}
	for _, p := range m.BlanketActions {
		if p != WildcardAction {
			add(p)
		}
	}
	sort.Strings(out)
	return out
}

// routeKey derives the Routes key for an HTTP surface.
func (m Map) routeKey(s Surface) string {
	if m.RouteKey != nil {
		return m.RouteKey(s)
	}
	return FirstSegment(m.Prefix, s.Path)
}

// FirstSegment extracts the first path segment under prefix, or "" when path is not
// under it. It is the default route-key derivation and is exported so a service can
// reuse it inside a custom Map.RouteKey.
//
//	FirstSegment("/api/v1/", "/api/v1/secrets/reveal") == "secrets"
//	FirstSegment("/api/v1/", "/healthz")               == ""
func FirstSegment(prefix, path string) string {
	if prefix != "" {
		if !strings.HasPrefix(path, prefix) {
			return ""
		}
		path = strings.TrimPrefix(path, prefix)
	} else {
		path = strings.TrimPrefix(path, "/")
	}
	if i := strings.IndexByte(path, '/'); i >= 0 {
		path = path[:i]
	}
	return path
}

// pathHasPrefix reports whether path is prefix or lies beneath it, matching only on a
// segment boundary. A plain strings.HasPrefix would let "/api/v1/setup" exempt
// "/api/v1/setup-admin", turning an exemption for one route into an unguarded
// neighbour.
func pathHasPrefix(path, prefix string) bool {
	if prefix == "" {
		return false
	}
	prefix = strings.TrimSuffix(prefix, "/")
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}
