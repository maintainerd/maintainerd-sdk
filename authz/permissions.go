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

// Actor is the CLASS of caller a surface accepts, checked alongside — never instead
// of — the permission.
//
// THE TWO QUESTIONS ARE DIFFERENT, AND ONE CANNOT ANSWER THE OTHER.
//
//	a permission answers  "may THIS principal do X?"
//	the actor kind answers "should this CLASS of caller be doing X at all?"
//
// A machine identity and a signed-in human reach a resource server through entirely
// different trust contexts: the human arrived through an interactive OAuth2
// authorization-code + PKCE flow with a browser session behind it, the workload
// arrived m2m with a long-lived client credential deployed next to it. The two are
// compromised in different ways and are stolen in different ways, and a grant list
// cannot express the difference — a workload's token legitimately carries broad
// grants precisely because nobody is sitting behind it to be phished.
//
// So a stolen m2m credential — the failure that does not look like a failure, because
// the token is valid and its grants are real — should still not be able to drive the
// ADMINISTRATIVE console surface: create a project, rewrite a webhook, delete an
// environment, read the audit trail. Those are things a human does from a console,
// and a workload doing them is, by itself, the signal. Conversely a browser session
// should not be able to impersonate a workload's private fetch path where a service
// has one. ActorUserOnly and ActorServiceOnly make those statements enforceable
// instead of aspirational.
//
// The zero value is ActorAny, so a surface that says nothing keeps today's behaviour.
type Actor uint8

const (
	// ActorAny accepts every authenticated caller. The default, and the right answer
	// for any surface both a console operator and a workload legitimately use.
	ActorAny Actor = iota
	// ActorUserOnly accepts only a principal classified as a human
	// (Principal.Kind == ActorKindUser).
	ActorUserOnly
	// ActorServiceOnly accepts only a machine identity
	// (Principal.Kind == ActorKindService).
	ActorServiceOnly
)

// String renders the constraint for a denial message and a log line.
func (a Actor) String() string {
	switch a {
	case ActorUserOnly:
		return "user-only"
	case ActorServiceOnly:
		return "service-only"
	default:
		return "any"
	}
}

// Permits reports whether a principal of this kind may reach the surface.
//
// FAIL-CLOSED ON AN UNKNOWN KIND. A constrained surface refuses a principal whose
// Kind is empty or unrecognised, because "we could not classify this caller" is not
// a reason to admit it to a surface somebody deliberately restricted. Only ActorAny
// admits an unclassified caller, and ActorAny is the surface that asked no question.
func (a Actor) Permits(kind string) bool {
	switch a {
	case ActorUserOnly:
		return kind == ActorKindUser
	case ActorServiceOnly:
		return kind == ActorKindService
	default:
		return true
	}
}

// Rule is the complete surface-guard decision for one surface: the permission it
// demands, and the class of caller allowed to reach it at all.
//
// THE PERMISSION IS THE ONE THE OPERATION ACTUALLY PERFORMS, not a weaker baseline.
// Where a handler enforces MORE than one permission (a rollback that both writes and
// reads, a folder delete that both manages the folder and deletes the secrets under
// it), the Rule names the PRIMARY one and the operation layer keeps enforcing the
// rest against the concrete target MRN. What the Rule must never be is WEAKER than
// what the surface reaches: the route guard runs first, so a weak Rule is the check
// an attacker meets first, and a handler that forgets its deeper check then ships
// carrying only that weak permission.
type Rule struct {
	// Permission is the action this surface demands. Empty means the surface is
	// deliberately open to any authenticated caller — see Map.Required.
	Permission string
	// Actor constrains which class of caller may reach the surface. Zero value:
	// ActorAny.
	Actor Actor
}

// Perms is the read/write permission pair guarding one HTTP route SEGMENT. GET and
// HEAD require Read; every other verb requires Write.
//
// A pair, rather than one permission per route, because the read/write split is the
// one distinction that is universal across HTTP surfaces — and it is exactly right
// for a segment whose whole surface is "browse these, and manage these". It is WRONG
// for a segment that mixes privileges (a reveal, a write, a destroy and a listing all
// hanging off one noun), and the fix for that is Map.Exact, not a weaker pair: see
// the comment on Map.Exact for why a baseline is the wrong shape for the FIRST check
// a request meets.
//
// ReadActor and WriteActor carry the actor constraint per verb, because a segment's
// reads and its writes are usually not the same kind of act — browsing projects is
// something a workload may legitimately do, creating one is console work.
type Perms struct {
	Read  string
	Write string
	// ReadActor constrains GET/HEAD. Zero value: ActorAny.
	ReadActor Actor
	// WriteActor constrains every other verb. Zero value: ActorAny.
	WriteActor Actor
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

	// Exact maps ONE HTTP method and ONE path to the exact Rule that surface
	// requires. It is consulted BEFORE Routes and wins over it.
	//
	// Build a key with ExactKey (or write it literally — "POST /api/v1/secrets/reveal"
	// is the canonical form: an upper-case method, a space, and the path with any
	// trailing slash trimmed).
	//
	// WHY EXACT ENTRIES EXIST AT ALL. A segment pair can only be as strong as the
	// WEAKEST route on the segment, because one pair guards them all. A noun that
	// carries a listing, a write, a reveal and a destroy therefore collapses to
	// whatever the listing needs, and that collapse lands on the check that runs
	// FIRST — the route guard — while the real privilege is enforced later, deeper, by
	// a handler. That ordering is inverted: it means the guard a request meets at the
	// door is the weakest statement in the system, the route table stops being
	// self-documenting, and a NEW handler added to the segment that forgets its deeper
	// check ships carrying the weak permission and nothing catches it. Declaring the
	// surface exactly makes the route guard correct ON ITS OWN, and leaves the
	// MRN-level operation check as a second layer rather than the only one.
	//
	// A segment that is genuinely uniform — "browse these, manage these" — should stay
	// in Routes. Exactness is for the segments that mix privileges, not a style.
	//
	// THE ALLOWLIST PROPERTY IS UNCHANGED, and strengthened where a segment is dropped
	// from Routes entirely: a path that matches neither Exact nor Routes is unmapped
	// and denied, so a new route added beside declared ones fails closed.
	Exact map[string]Rule

	// Routes maps a route key — by default the first path segment under Prefix — to
	// the permission pair its surface requires. Consulted only when Exact has no entry
	// for the request.
	Routes map[string]Perms

	// Methods maps a gRPC full method ("/maintainerd.secret.v1.SecretService/Get") to
	// the permission it requires. gRPC has no read/write verb to derive from, so each
	// method names its permission outright — it has always been the exact form.
	Methods map[string]string

	// MethodActors carries the ACTOR constraint for a gRPC method; an absent entry
	// means ActorAny. It is a second map rather than a field on a Rule value in
	// Methods because Methods is a long table whose entire content is the permission,
	// and turning every row into a struct literal to express the rare constraint would
	// make the common case — the row a reviewer actually has to read — unreadable.
	// Both maps are keyed by the same full method, and DeclaredMethodRule joins them.
	MethodActors map[string]Actor

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

// Resolve reports the full Rule a surface demands: its permission AND the class of
// caller allowed to reach it.
//
// ok=false means the surface is NOT in the allowlist and MUST be denied. It is not
// the same as an empty permission string: a mapped surface whose permission is ""
// resolves to a zero Rule with ok=true and is treated as requiring nothing, which is
// only ever correct for a surface a service deliberately opened.
//
// PRECEDENCE, most specific first:
//
//	gRPC   Methods[fullMethod]        (+ MethodActors[fullMethod])
//	HTTP   Exact[METHOD path]         exact method + path
//	HTTP   Routes[segment]            the read/write pair for the segment
//
// An exact entry wins outright — it is not merged with the segment pair, because a
// half-overridden rule is the kind of thing a reader gets wrong.
func (m Map) Resolve(s Surface) (Rule, bool) {
	if s.IsGRPC() {
		p, ok := m.Methods[s.FullMethod]
		if !ok {
			return Rule{}, false
		}
		return Rule{Permission: p, Actor: m.MethodActors[s.FullMethod]}, true
	}
	if r, ok := m.Exact[ExactKey(s.HTTPMethod, s.Path)]; ok {
		return r, true
	}
	p, ok := m.Routes[m.routeKey(s)]
	if !ok {
		return Rule{}, false
	}
	if s.HTTPMethod == http.MethodGet || s.HTTPMethod == http.MethodHead {
		return Rule{Permission: p.Read, Actor: p.ReadActor}, true
	}
	return Rule{Permission: p.Write, Actor: p.WriteActor}, true
}

// Required resolves the permission a surface demands, discarding the actor
// constraint. It is Resolve for the callers that only ask the permission question.
func (m Map) Required(s Surface) (string, bool) {
	r, ok := m.Resolve(s)
	return r.Permission, ok
}

// ExactKey builds the Map.Exact key for one HTTP method and path.
//
// The method is upper-cased and a trailing slash is trimmed from the path, so the
// three spellings a router and a request can produce for the same surface —
// "/api/v1/secrets", "/api/v1/secrets/" and the pattern a route walker reports —
// all resolve to one entry. Without that, a table written against one spelling
// silently fails to match the other and the surface falls through to the segment
// pair, which is precisely the weakening the exact entry exists to prevent.
func ExactKey(method, path string) string {
	return strings.ToUpper(strings.TrimSpace(method)) + " " + trimTrailingSlash(path)
}

// trimTrailingSlash normalises a path for exact matching, leaving root alone.
func trimTrailingSlash(path string) string {
	for len(path) > 1 && path[len(path)-1] == '/' {
		path = path[:len(path)-1]
	}
	return path
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
// exact routes, route pairs, gRPC methods, per-operation permissions and blanket
// actions — deduped and sorted.
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
	out := make([]string, 0, len(m.Exact)+len(m.Routes)*2+len(m.Methods)+len(m.OperationPermissions))
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
	for _, r := range m.Exact {
		add(r.Permission)
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
