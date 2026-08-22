package authz

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Mode is the resolved posture of the guard.
type Mode int

const (
	// ModeEnforced verifies tokens and permissions on every guarded surface — the
	// only mode permitted outside development.
	ModeEnforced Mode = iota
	// ModeDevOpen serves without authentication. Permitted ONLY in development, and
	// announced loudly at boot (Guard.LogBanner).
	ModeDevOpen
	// ModeUnavailable refuses every guarded surface: auth is required
	// (non-development) but not configured. HTTP answers 503 and gRPC answers
	// codes.Unavailable. Exempt surfaces — probes, and a self-guarded first-run setup
	// endpoint — stay reachable, because a fresh install has to be provisionable into
	// a state where tokens exist at all.
	ModeUnavailable
)

func (m Mode) String() string {
	switch m {
	case ModeEnforced:
		return "enforced"
	case ModeDevOpen:
		return "development-open"
	default:
		return "unavailable"
	}
}

// DevOpenSubject is the subject attributed to a caller in ModeDevOpen. It is a name
// that will look wrong in an audit row if it is ever seen on a real deployment, which
// is the point.
const DevOpenSubject = "development-open"

// VerifyFunc validates a bearer token and returns its principal. The guard is
// deliberately verifier-agnostic — plug in sdk/auth.Verifier with SDKVerify, an
// introspection call, or a test double — so enforcement does not drag a token library
// into every consumer.
type VerifyFunc func(ctx context.Context, token string) (*Principal, error)

// ResourceResolver derives the target resource MRN for a surface, so the guard can
// run the MRN-level check (Principal.Allows) instead of only the action-level one.
//
// Return ok=false when the surface has no single resolvable target — a list, a batch,
// or anything whose target is only known after the request body is decoded. The guard
// then falls back to the action check and the HANDLER remains responsible for calling
// Allows with the real MRN. A resolver is an optimization for the surfaces where the
// target is in the path; it is never a replacement for the operation check.
type ResourceResolver func(ctx context.Context, s Surface) (mrn string, ok bool)

// Guard is the resolved posture plus the service's permission table. Build it with
// Resolve at startup, then mount Middleware / UnaryInterceptor / StreamInterceptor.
type Guard struct {
	// Mode is the resolved posture.
	Mode Mode
	// Verify validates bearer tokens. Required when Mode == ModeEnforced; a nil
	// Verify in ModeEnforced is a misconfiguration and every guarded surface fails
	// closed as if auth were unavailable.
	Verify VerifyFunc
	// Permissions is the surface allowlist.
	Permissions Map
	// Resource, when non-nil, upgrades the surface guard from an action check to an
	// MRN check for the surfaces it can resolve.
	Resource ResourceResolver
	// Service names the service in banners and logs, e.g. "secret".
	Service string
	// Reason is the human-readable cause for ModeDevOpen / ModeUnavailable.
	Reason string
	// DevOpenWarnings are extra service-specific lines appended to the dev-open
	// banner — the concrete consequences a reader needs to see, e.g. "ANY caller can
	// read ANY secret's decrypted value".
	DevOpenWarnings []string
	// WriteError, when non-nil, renders HTTP denials in the service's own error
	// envelope. Default: a compact JSON body, {"error":"…","code":"…"}.
	WriteError func(w http.ResponseWriter, status int, code, message string)
	// Logger, when non-nil, receives the boot banner. Default: slog.Default().
	Logger *slog.Logger
}

// Denial is a refused request, carrying the status for both transports so one
// decision function can serve HTTP and gRPC. The Message is always safe to return to
// the caller: it never contains the verify error.
type Denial struct {
	HTTPStatus int
	GRPCCode   codes.Code
	Code       string
	Message    string
}

func (d *Denial) Error() string { return d.Code + ": " + d.Message }

// Denial codes, stable enough for a client to branch on.
const (
	DenyAuthUnavailable = "auth_unavailable"
	DenyMissingToken    = "missing_token"
	DenyInvalidToken    = "invalid_token"
	DenyUnmappedSurface = "no_permission_mapping"
	DenyInsufficient    = "insufficient_permission"
)

// DeclaredPermissions returns every permission this guard can demand — see
// Map.DeclaredPermissions for why registration must be derived from it.
func (g Guard) DeclaredPermissions() []string { return g.Permissions.DeclaredPermissions() }

// DevPrincipal is the identity attributed to a caller in ModeDevOpen. It carries a
// blanket grant, because a dev-open service by definition has no way to tell one
// caller from another.
func (g Guard) DevPrincipal() *Principal {
	return &Principal{
		Subject:        DevOpenSubject,
		Kind:           ActorKindService,
		Scopes:         []string{WildcardAction},
		Grants:         []Grant{{Action: WildcardAction}},
		BlanketActions: g.Permissions.BlanketActions,
	}
}

// Check runs the surface guard for one request and returns either the verified
// principal or the Denial to render. It is the single decision path behind the HTTP
// middleware and both gRPC interceptors, exported so a service on a third transport
// enforces identically instead of re-deriving the ladder.
//
// An exempt surface returns (nil, nil): no principal, no denial, let it through.
func (g Guard) Check(ctx context.Context, token string, s Surface) (*Principal, *Denial) {
	if g.Permissions.IsExempt(s) {
		return nil, nil
	}

	switch g.Mode {
	case ModeDevOpen:
		return g.DevPrincipal(), nil
	case ModeUnavailable:
		return nil, g.unavailable()
	}

	if g.Verify == nil {
		// ModeEnforced without a verifier cannot authenticate anyone. Fail closed
		// rather than fall through to a nil-pointer panic or an accidental open.
		return nil, &Denial{
			HTTPStatus: http.StatusServiceUnavailable,
			GRPCCode:   codes.Unavailable,
			Code:       DenyAuthUnavailable,
			Message:    "API authentication is not configured (no verifier); the API is disabled",
		}
	}

	if token == "" {
		return nil, &Denial{
			HTTPStatus: http.StatusUnauthorized,
			GRPCCode:   codes.Unauthenticated,
			Code:       DenyMissingToken,
			Message:    "missing bearer token",
		}
	}
	principal, err := g.Verify(ctx, token)
	if err != nil || principal == nil {
		// Deliberately generic: WHICH check a forged token failed is oracle material —
		// it tells an attacker whether the signature, the issuer, the audience or the
		// expiry was wrong, and that is enough to iterate towards a valid forgery.
		return nil, &Denial{
			HTTPStatus: http.StatusUnauthorized,
			GRPCCode:   codes.Unauthenticated,
			Code:       DenyInvalidToken,
			Message:    "invalid token",
		}
	}
	if principal.BlanketActions == nil && len(g.Permissions.BlanketActions) > 0 {
		// Copy rather than assign: a VerifyFunc backed by a decision cache may hand the
		// same *Principal to concurrent requests, and writing through it would be a
		// data race on a security decision. The copy is shallow — Scopes and Grants are
		// read-only after verification.
		withBlanket := *principal
		withBlanket.BlanketActions = g.Permissions.BlanketActions
		principal = &withBlanket
	}

	required, mapped := g.Permissions.Required(s)
	if !mapped {
		// The allowlist property: an unmapped surface is denied even to a valid token.
		return nil, &Denial{
			HTTPStatus: http.StatusForbidden,
			GRPCCode:   codes.PermissionDenied,
			Code:       DenyUnmappedSurface,
			Message:    unmappedMessage(s),
		}
	}
	if required == "" {
		return principal, nil
	}

	if g.Resource != nil {
		if resourceMRN, ok := g.Resource(ctx, s); ok {
			if !principal.Allows(required, resourceMRN) {
				return nil, &Denial{
					HTTPStatus: http.StatusForbidden,
					GRPCCode:   codes.PermissionDenied,
					Code:       DenyInsufficient,
					Message:    "requires permission " + required + " on " + resourceMRN,
				}
			}
			return principal, nil
		}
	}

	if !principal.HasAction(required) {
		return nil, &Denial{
			HTTPStatus: http.StatusForbidden,
			GRPCCode:   codes.PermissionDenied,
			Code:       DenyInsufficient,
			Message:    "requires permission " + required,
		}
	}
	return principal, nil
}

func (g Guard) unavailable() *Denial {
	msg := "API authentication is not configured"
	if g.Reason != "" {
		msg += " (" + g.Reason + ")"
	}
	msg += "; the API is disabled outside development"
	return &Denial{
		HTTPStatus: http.StatusServiceUnavailable,
		GRPCCode:   codes.Unavailable,
		Code:       DenyAuthUnavailable,
		Message:    msg,
	}
}

func unmappedMessage(s Surface) string {
	if s.IsGRPC() {
		return "method has no permission mapping"
	}
	return "route has no permission mapping"
}

type ctxKey struct{}

// FromContext returns the Principal the guard placed, if any.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok
}

// NewContext attaches a principal to a context. The HTTP middleware and both gRPC
// interceptors use it, so handlers on either transport read the caller the same way.
func NewContext(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// Middleware enforces the surface guard on every route it wraps, and places the
// verified Principal in the request context for the handler's operation checks.
func (g Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		surface := SurfaceFromRequest(r)
		principal, denial := g.Check(r.Context(), Bearer(r.Header.Get("Authorization")), surface)
		if denial != nil {
			g.writeError(w, denial)
			return
		}
		if principal == nil {
			next.ServeHTTP(w, r) // exempt surface
			return
		}
		next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), principal)))
	})
}

// HTTPMiddleware is Middleware in the func(http.Handler) http.Handler shape that
// chi//alice-style routers and maintainerd-kit's authz expect.
func (g Guard) HTTPMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return g.Middleware(next) }
}

// RequirePermission wraps a handler so it runs only when the request's principal
// (placed by Middleware) carries the action. It is an action-level check: use it for
// a surface with no single resource, and call Principal.Allows with the target MRN
// everywhere else.
func RequirePermission(action string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := FromContext(r.Context())
		if !ok || !p.HasAction(action) {
			writeJSONError(w, http.StatusForbidden, DenyInsufficient, "requires permission "+action)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// UnaryInterceptor enforces the surface guard on gRPC unary calls.
func (g Guard) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		surface := Surface{FullMethod: info.FullMethod}
		principal, denial := g.Check(ctx, BearerFromMetadata(ctx), surface)
		if denial != nil {
			return nil, status.Error(denial.GRPCCode, denial.Message)
		}
		if principal == nil {
			return handler(ctx, req)
		}
		return handler(NewContext(ctx, principal), req)
	}
}

// StreamInterceptor enforces the surface guard on gRPC streaming calls and carries
// the principal into the stream handler's context (read it with FromContext).
func (g Guard) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		surface := Surface{FullMethod: info.FullMethod}
		principal, denial := g.Check(ss.Context(), BearerFromMetadata(ss.Context()), surface)
		if denial != nil {
			return status.Error(denial.GRPCCode, denial.Message)
		}
		if principal == nil {
			return handler(srv, ss)
		}
		return handler(srv, &principalStream{ServerStream: ss, ctx: NewContext(ss.Context(), principal)})
	}
}

// principalStream overrides Context() so downstream stream handlers see the principal
// the interceptor placed.
type principalStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *principalStream) Context() context.Context { return s.ctx }

func (g Guard) writeError(w http.ResponseWriter, d *Denial) {
	if g.WriteError != nil {
		g.WriteError(w, d.HTTPStatus, d.Code, d.Message)
		return
	}
	writeJSONError(w, d.HTTPStatus, d.Code, d.Message)
}

func writeJSONError(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}{Error: message, Code: code})
}

// Bearer extracts a "Bearer <token>" Authorization header value, "" when the header
// is absent or carries another scheme.
func Bearer(header string) string {
	if len(header) > 7 && strings.EqualFold(header[:7], "bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
}

// BearerFromMetadata extracts the bearer token from a gRPC call's incoming metadata.
func BearerFromMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return ""
	}
	return Bearer(vals[0])
}
