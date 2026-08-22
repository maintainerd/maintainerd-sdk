package authz

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
}

func request(method, path, token string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// verifier accepts only the token "good", and its failure message is a distinctive
// string so a test can assert it never reaches the caller.
func verifier(p *Principal) VerifyFunc {
	return func(_ context.Context, token string) (*Principal, error) {
		if token != "good" {
			return nil, errors.New("signature-verification-failed-for-kid-abc")
		}
		return p, nil
	}
}

func enforced(p *Principal) Guard {
	return Guard{Mode: ModeEnforced, Verify: verifier(p), Permissions: testMap, Service: "secret"}
}

func serve(g Guard, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	g.Middleware(okHandler()).ServeHTTP(w, r)
	return w
}

// ---------------------------------------------------------------------------
// The HTTP surface guard
// ---------------------------------------------------------------------------

// TestUnmappedRouteIsDenied is the allowlist property: mounting a router without
// deciding its permissions fails closed instead of shipping an open surface.
func TestUnmappedRouteIsDenied(t *testing.T) {
	g := enforced(blanket(Grant{Action: permAdmin}))
	w := serve(g, request(http.MethodGet, "/api/v1/brand-new-thing", "good"))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if !strings.Contains(w.Body.String(), "no permission mapping") {
		t.Errorf("body = %q, want the unmapped-route reason", w.Body.String())
	}
}

func TestMissingAndInvalidTokensAreUnauthorized(t *testing.T) {
	g := enforced(&Principal{})

	w := serve(g, request(http.MethodGet, "/api/v1/projects", ""))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("missing token: status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(w.Body.String(), "missing bearer token") {
		t.Errorf("body = %q", w.Body.String())
	}

	w = serve(g, request(http.MethodGet, "/api/v1/projects", "forged"))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("forged token: status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(w.Body.String(), "invalid token") {
		t.Errorf("body = %q", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "signature-verification-failed") {
		t.Error("the verify error is never echoed — it is oracle material")
	}
}

// TestVerifierReturningNilPrincipalIsDenied: a VerifyFunc that returns (nil, nil) is
// a bug in the adapter, and the fail-closed reading is the only safe one.
func TestVerifierReturningNilPrincipalIsDenied(t *testing.T) {
	g := Guard{
		Mode:        ModeEnforced,
		Verify:      func(context.Context, string) (*Principal, error) { return nil, nil },
		Permissions: testMap,
	}
	w := serve(g, request(http.MethodGet, "/api/v1/projects", "good"))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// TestEnforcedWithoutAVerifierFailsClosed: a misconfigured guard must not fall
// through to the handler.
func TestEnforcedWithoutAVerifierFailsClosed(t *testing.T) {
	g := Guard{Mode: ModeEnforced, Permissions: testMap}
	w := serve(g, request(http.MethodGet, "/api/v1/projects", "good"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestBaselinePermissionIsEnforcedPerMethod(t *testing.T) {
	g := enforced(blanket(Grant{Action: permReadMetadata}))

	w := serve(g, request(http.MethodGet, "/api/v1/projects", "good"))
	if w.Code != http.StatusTeapot {
		t.Errorf("read: status = %d, want the handler to run", w.Code)
	}

	w = serve(g, request(http.MethodPost, "/api/v1/projects", "good"))
	if w.Code != http.StatusForbidden {
		t.Errorf("write: status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if !strings.Contains(w.Body.String(), permManageFolder) {
		t.Errorf("body = %q, want the required permission named", w.Body.String())
	}
}

// TestGuardPopulatesBlanketActionsOnTheVerifiedPrincipal, so a handler's Allows call
// honours the service's admin action without every VerifyFunc having to know it.
func TestGuardPopulatesBlanketActionsOnTheVerifiedPrincipal(t *testing.T) {
	var seen *Principal
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = FromContext(r.Context())
		w.WriteHeader(http.StatusTeapot)
	})
	g := Guard{
		Mode:        ModeEnforced,
		Permissions: testMap,
		Verify: func(context.Context, string) (*Principal, error) {
			return &Principal{Subject: "u1", Grants: []Grant{{Action: permAdmin}}}, nil
		},
	}
	w := httptest.NewRecorder()
	g.Middleware(handler).ServeHTTP(w, request(http.MethodGet, "/api/v1/projects", "good"))
	if w.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want the handler to run", w.Code)
	}
	if seen == nil {
		t.Fatal("no principal in the request context")
	}
	if !seen.Allows(permGetSecret, prodPassword) {
		t.Error("the guard must populate BlanketActions from its Map")
	}
}

// TestGuardDoesNotMutateAVerifiersPrincipal: a VerifyFunc backed by a decision cache
// may hand the same *Principal to concurrent requests, so writing through it would be
// a data race on a security decision.
func TestGuardDoesNotMutateAVerifiersPrincipal(t *testing.T) {
	shared := &Principal{Subject: "u1", Grants: []Grant{{Action: permAdmin}}}
	g := Guard{
		Mode:        ModeEnforced,
		Permissions: testMap,
		Verify:      func(context.Context, string) (*Principal, error) { return shared, nil },
	}
	if w := serve(g, request(http.MethodGet, "/api/v1/projects", "good")); w.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want the handler to run", w.Code)
	}
	if shared.BlanketActions != nil {
		t.Errorf("the guard wrote BlanketActions=%v through the verifier's principal", shared.BlanketActions)
	}
}

// TestResourceResolverUpgradesTheSurfaceGuardToAnMRNCheck.
func TestResourceResolverUpgradesTheSurfaceGuardToAnMRNCheck(t *testing.T) {
	g := enforced(blanket(Grant{
		Action:   permReadMetadata,
		Resource: "mrn:secret:acme:billing:secret/staging/*",
	}))
	g.Resource = func(_ context.Context, s Surface) (string, bool) {
		switch {
		case strings.HasSuffix(s.Path, "/staging"):
			return "mrn:secret:acme:billing:secret/staging/db/PASSWORD", true
		case strings.HasSuffix(s.Path, "/prod"):
			return prodPassword, true
		default:
			return "", false // unresolvable — the handler owns the check
		}
	}

	if w := serve(g, request(http.MethodGet, "/api/v1/secrets/staging", "good")); w.Code != http.StatusTeapot {
		t.Errorf("staging: status = %d, want the handler to run", w.Code)
	}
	w := serve(g, request(http.MethodGet, "/api/v1/secrets/prod", "good"))
	if w.Code != http.StatusForbidden {
		t.Errorf("prod: status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if !strings.Contains(w.Body.String(), prodPassword) {
		t.Errorf("body = %q, want the refused resource named", w.Body.String())
	}
	// Unresolvable: the action check still applies and the handler runs.
	if w := serve(g, request(http.MethodGet, "/api/v1/secrets", "good")); w.Code != http.StatusTeapot {
		t.Errorf("unresolved: status = %d, want the action check to carry it", w.Code)
	}
}

// TestModeUnavailableRefusesEverythingButExemptSurfaces: outside development a
// missing auth configuration disables the API rather than quietly serving it open —
// and probes plus the self-guarded setup surface stay reachable so a fresh install
// can be provisioned at all.
func TestModeUnavailableRefusesEverythingButExemptSurfaces(t *testing.T) {
	g := Guard{Mode: ModeUnavailable, Reason: EnvJWKSURL + " not set", Permissions: testMap}

	w := serve(g, request(http.MethodGet, "/api/v1/secrets", ""))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(w.Body.String(), EnvJWKSURL+" not set") {
		t.Errorf("body = %q, want the missing variable named", w.Body.String())
	}

	if w := serve(g, request(http.MethodPost, "/api/v1/setup", "")); w.Code != http.StatusTeapot {
		t.Errorf("setup: status = %d, want the self-guarded surface to stay reachable", w.Code)
	}
	if w := serve(g, request(http.MethodGet, "/healthz", "")); w.Code != http.StatusTeapot {
		t.Errorf("healthz: status = %d, want the probe to stay reachable", w.Code)
	}
}

// TestModeDevOpenAttachesBlanketPrincipal so downstream audit rows are attributed to
// a subject that looks wrong if it is ever seen on a real deployment.
func TestModeDevOpenAttachesBlanketPrincipal(t *testing.T) {
	var seen *Principal
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = FromContext(r.Context())
		w.WriteHeader(http.StatusTeapot)
	})
	g := Guard{Mode: ModeDevOpen, Reason: EnvJWKSURL + " not set", Permissions: testMap}

	w := httptest.NewRecorder()
	g.Middleware(handler).ServeHTTP(w, request(http.MethodPost, "/api/v1/secrets", ""))
	if w.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want the handler to run without a token", w.Code)
	}
	if seen == nil {
		t.Fatal("no principal in the request context")
	}
	if seen.Subject != DevOpenSubject {
		t.Errorf("Subject = %q, want %q", seen.Subject, DevOpenSubject)
	}
	if !seen.Allows(permGetSecret, prodPassword) {
		t.Error("the dev-open principal carries a blanket grant")
	}
	// Dev-open skips the surface check entirely, so even an unmapped route is served.
	// That is exactly what "authorization is disabled" means, and it is asserted here
	// so the scope of the mode is explicit rather than discovered — it is also why the
	// banner has to be loud and why the mode is unreachable outside development.
	if w := serve(g, request(http.MethodGet, "/api/v1/brand-new-thing", "")); w.Code != http.StatusTeapot {
		t.Errorf("dev-open serves unmapped routes too: status = %d", w.Code)
	}
}

func TestCustomErrorWriter(t *testing.T) {
	g := enforced(&Principal{})
	g.WriteError = func(w http.ResponseWriter, statusCode int, code, message string) {
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte("service-envelope:" + code + ":" + message))
	}
	w := serve(g, request(http.MethodGet, "/api/v1/projects", ""))
	if !strings.HasPrefix(w.Body.String(), "service-envelope:"+DenyMissingToken) {
		t.Errorf("body = %q, want the service's own envelope", w.Body.String())
	}
}

func TestHTTPMiddlewareShape(t *testing.T) {
	g := enforced(blanket(Grant{Action: permReadMetadata}))
	w := httptest.NewRecorder()
	g.HTTPMiddleware()(okHandler()).ServeHTTP(w, request(http.MethodGet, "/api/v1/projects", "good"))
	if w.Code != http.StatusTeapot {
		t.Errorf("status = %d, want the handler to run", w.Code)
	}
}

func TestRequirePermission(t *testing.T) {
	guarded := RequirePermission(permGetSecret, okHandler())

	// No principal in context at all.
	w := httptest.NewRecorder()
	guarded.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("no principal: status = %d, want %d", w.Code, http.StatusForbidden)
	}

	// Present but without the action.
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r = r.WithContext(NewContext(r.Context(), blanket(Grant{Action: permReadMetadata})))
	w = httptest.NewRecorder()
	guarded.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("wrong action: status = %d, want %d", w.Code, http.StatusForbidden)
	}

	// Present with the action.
	r = httptest.NewRequest(http.MethodGet, "/x", nil)
	r = r.WithContext(NewContext(r.Context(), blanket(Grant{Action: permGetSecret})))
	w = httptest.NewRecorder()
	guarded.ServeHTTP(w, r)
	if w.Code != http.StatusTeapot {
		t.Errorf("granted: status = %d, want the handler to run", w.Code)
	}
}

func TestBearerParsing(t *testing.T) {
	for _, tc := range []struct{ header, want string }{
		{"Bearer abc", "abc"},
		{"bearer abc", "abc"},
		{"BEARER  abc  ", "abc"},
		{"Basic abc", ""},
		{"", ""},
		{"Bearer", ""},
	} {
		if got := Bearer(tc.header); got != tc.want {
			t.Errorf("Bearer(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// The gRPC surface guard
// ---------------------------------------------------------------------------

func mdCtx(token string) context.Context {
	if token == "" {
		return context.Background()
	}
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token))
}

func unaryPass(ctx context.Context, _ any) (any, error) { return ctx, nil }

func callUnary(g Guard, ctx context.Context, fullMethod string) (any, error) {
	return g.UnaryInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: fullMethod}, unaryPass)
}

type fakeStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *fakeStream) Context() context.Context { return s.ctx }

func callStream(g Guard, ctx context.Context, fullMethod string) (context.Context, error) {
	var handlerCtx context.Context
	err := g.StreamInterceptor()(nil, &fakeStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: fullMethod},
		func(_ any, ss grpc.ServerStream) error {
			handlerCtx = ss.Context()
			return nil
		})
	return handlerCtx, err
}

func wantCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if status.Code(err) != want {
		t.Errorf("code = %v (%v), want %v", status.Code(err), err, want)
	}
}

func TestUnaryInterceptorMapsMethodsToPermissions(t *testing.T) {
	const describe = "/maintainerd.secret.v1.SecretService/Describe"
	const reveal = "/maintainerd.secret.v1.SecretService/Reveal"

	g := enforced(blanket(Grant{Action: permReadMetadata}))

	if _, err := callUnary(g, mdCtx("good"), describe); err != nil {
		t.Errorf("Describe: unexpected error %v", err)
	}
	_, err := callUnary(g, mdCtx("good"), reveal)
	wantCode(t, err, codes.PermissionDenied)
	if !strings.Contains(status.Convert(err).Message(), permGetSecret) {
		t.Errorf("message = %q, want the required permission named", status.Convert(err).Message())
	}
}

// TestUnaryInterceptorDeniesUnmappedMethods is the allowlist property on gRPC:
// registering an RPC without deciding its permission fails closed.
func TestUnaryInterceptorDeniesUnmappedMethods(t *testing.T) {
	g := enforced(blanket(Grant{Action: permAdmin}))
	_, err := callUnary(g, mdCtx("good"), "/maintainerd.secret.v1.SecretService/BrandNew")
	wantCode(t, err, codes.PermissionDenied)
	if !strings.Contains(status.Convert(err).Message(), "method has no permission mapping") {
		t.Errorf("message = %q", status.Convert(err).Message())
	}
}

func TestUnaryInterceptorTokenHandling(t *testing.T) {
	const describe = "/maintainerd.secret.v1.SecretService/Describe"
	g := enforced(blanket(Grant{Action: permReadMetadata}))

	_, err := callUnary(g, context.Background(), describe)
	wantCode(t, err, codes.Unauthenticated)

	_, err = callUnary(g, mdCtx("forged"), describe)
	wantCode(t, err, codes.Unauthenticated)
	if strings.Contains(status.Convert(err).Message(), "signature-verification-failed") {
		t.Error("the verify error is never echoed — it is oracle material")
	}
}

func TestUnaryInterceptorExemptAndUnavailable(t *testing.T) {
	const health = "/grpc.health.v1.Health/Check"

	// Unavailable refuses guarded methods but serves health.
	g := Guard{Mode: ModeUnavailable, Reason: EnvIssuer + " not set", Permissions: testMap}
	_, err := callUnary(g, context.Background(), "/maintainerd.secret.v1.SecretService/Describe")
	wantCode(t, err, codes.Unavailable)
	if _, err := callUnary(g, context.Background(), health); err != nil {
		t.Errorf("health must stay reachable: %v", err)
	}
}

func TestUnaryInterceptorPlacesThePrincipal(t *testing.T) {
	g := enforced(blanket(Grant{Action: permReadMetadata}))
	out, err := callUnary(g, mdCtx("good"), "/maintainerd.secret.v1.SecretService/Describe")
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	ctx, ok := out.(context.Context)
	if !ok {
		t.Fatal("handler did not receive a context")
	}
	if _, ok := FromContext(ctx); !ok {
		t.Error("the interceptor must place the principal in the handler's context")
	}
}

func TestStreamInterceptor(t *testing.T) {
	const describe = "/maintainerd.secret.v1.SecretService/Describe"
	g := enforced(blanket(Grant{Action: permReadMetadata}))

	ctx, err := callStream(g, mdCtx("good"), describe)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if _, ok := FromContext(ctx); !ok {
		t.Error("the stream handler's context must carry the principal")
	}

	_, err = callStream(g, context.Background(), describe)
	wantCode(t, err, codes.Unauthenticated)

	_, err = callStream(g, mdCtx("good"), "/maintainerd.secret.v1.SecretService/BrandNew")
	wantCode(t, err, codes.PermissionDenied)

	// An exempt method passes the original stream straight through.
	if _, err := callStream(g, context.Background(), "/grpc.health.v1.Health/Check"); err != nil {
		t.Errorf("health must stay reachable: %v", err)
	}
}

func TestBearerFromMetadata(t *testing.T) {
	if got := BearerFromMetadata(mdCtx("abc")); got != "abc" {
		t.Errorf("BearerFromMetadata = %q, want abc", got)
	}
	if got := BearerFromMetadata(context.Background()); got != "" {
		t.Errorf("BearerFromMetadata with no metadata = %q, want empty", got)
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("other", "x"))
	if got := BearerFromMetadata(ctx); got != "" {
		t.Errorf("BearerFromMetadata with no authorization = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// The mode ladder
// ---------------------------------------------------------------------------

// TestResolveLadder: three rungs, and no fourth where a partial configuration
// guesses. A JWKS URL without an issuer or audience check accepts any token Auth
// signed for anyone, so partial is treated as absent.
func TestResolveLadder(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cfg         Config
		wantMode    Mode
		wantMissing []string
	}{
		{"nothing set, production", Config{}, ModeUnavailable, []string{EnvJWKSURL, EnvIssuer, EnvAudience}},
		{"nothing set, development", Config{Development: true}, ModeDevOpen, []string{EnvJWKSURL, EnvIssuer, EnvAudience}},
		{"jwks only, production", Config{JWKSURL: "https://auth/jwks"}, ModeUnavailable, []string{EnvIssuer, EnvAudience}},
		{"missing audience, production", Config{JWKSURL: "https://auth/jwks", Issuer: "https://auth"}, ModeUnavailable, []string{EnvAudience}},
		{"missing issuer, development", Config{JWKSURL: "https://auth/jwks", Audience: "secret", Development: true}, ModeDevOpen, []string{EnvIssuer}},
		{"whitespace is not configuration", Config{JWKSURL: "  ", Issuer: " ", Audience: " "}, ModeUnavailable, []string{EnvJWKSURL, EnvIssuer, EnvAudience}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := Resolve(context.Background(), tc.cfg, testMap)
			if err != nil {
				t.Fatalf("Resolve: unexpected error %v", err)
			}
			if g.Mode != tc.wantMode {
				t.Errorf("Mode = %v, want %v", g.Mode, tc.wantMode)
			}
			for _, name := range tc.wantMissing {
				if !strings.Contains(g.Reason, name) {
					t.Errorf("Reason = %q, want %q named", g.Reason, name)
				}
			}
			if g.Verify != nil {
				t.Error("an unconfigured guard must carry no verifier")
			}
			if len(g.DeclaredPermissions()) == 0 {
				t.Error("Resolve must carry the permission map onto the guard")
			}
		})
	}
}

// TestResolveFailsTheBootWhenConfiguredButUnusable: the operator asked for
// enforcement and it cannot be provided, so neither open nor unavailable is an
// honest answer.
func TestResolveFailsTheBootWhenConfiguredButUnusable(t *testing.T) {
	_, err := Resolve(context.Background(), Config{
		JWKSURL:  "://not-a-url",
		Issuer:   "https://auth",
		Audience: "secret",
	}, testMap)
	if err == nil {
		t.Error("an unusable JWKS endpoint must fail the boot, not downgrade the posture")
	}
}

func TestModeString(t *testing.T) {
	for mode, want := range map[Mode]string{
		ModeEnforced:    "enforced",
		ModeDevOpen:     "development-open",
		ModeUnavailable: "unavailable",
	} {
		if got := mode.String(); got != want {
			t.Errorf("Mode(%d).String() = %q, want %q", mode, got, want)
		}
	}
}

// TestDevOpenBannerNamesEveryDisabledGuard. A one-line "auth disabled" is easy to
// skim past in a startup log; a list of concrete consequences is not.
func TestDevOpenBannerNamesEveryDisabledGuard(t *testing.T) {
	var buf bytes.Buffer
	g := Guard{
		Mode:            ModeDevOpen,
		Reason:          EnvJWKSURL + " not set",
		Permissions:     testMap,
		Service:         "secret",
		DevOpenWarnings: []string{"reveal gating — ANY caller can read ANY secret's decrypted value"},
		Logger:          slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	g.LogBanner()

	out := buf.String()
	for _, want := range []string{
		"AUTHORIZATION IS DISABLED",
		EnvJWKSURL + " not set",
		"bearer-token authentication",
		"per-action permissions",
		"MRN scoping",
		"ANY caller can read ANY secret",
		DevOpenSubject,
		EnvIssuer,
		EnvAudience,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dev-open banner is missing %q\n%s", want, out)
		}
	}
	if !strings.Contains(out, "level=WARN") {
		t.Error("the dev-open banner must be logged at WARN or above")
	}
}

func TestEnforcedBannerListsDeclaredPermissions(t *testing.T) {
	var buf bytes.Buffer
	g := Guard{
		Mode:        ModeEnforced,
		Permissions: testMap,
		Service:     "secret",
		Logger:      slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	g.LogBanner()

	out := buf.String()
	if !strings.Contains(out, "ENFORCED") {
		t.Errorf("banner = %q", out)
	}
	for _, want := range testMap.DeclaredPermissions() {
		if !strings.Contains(out, want) {
			t.Errorf("enforced banner is missing declared permission %q\n%s", want, out)
		}
	}
}

func TestUnavailableBannerIsAnError(t *testing.T) {
	var buf bytes.Buffer
	g := Guard{
		Mode:        ModeUnavailable,
		Reason:      EnvAudience + " not set",
		Permissions: testMap,
		Logger:      slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	g.LogBanner()

	out := buf.String()
	if !strings.Contains(out, "level=ERROR") {
		t.Errorf("banner = %q, want ERROR", out)
	}
	if !strings.Contains(out, EnvAudience+" not set") {
		t.Errorf("banner = %q, want the cause named", out)
	}
}

// TestCheckIsTheSingleDecisionPath — a service on a third transport enforces
// identically instead of re-deriving the ladder.
func TestCheckIsTheSingleDecisionPath(t *testing.T) {
	g := enforced(blanket(Grant{Action: permReadMetadata}))

	p, denial := g.Check(context.Background(), "good", Surface{Path: "/api/v1/projects", HTTPMethod: "GET"})
	if denial != nil || p == nil {
		t.Fatalf("allowed request returned (%v, %v)", p, denial)
	}

	p, denial = g.Check(context.Background(), "good", Surface{Path: "/healthz", HTTPMethod: "GET"})
	if p != nil || denial != nil {
		t.Errorf("an exempt surface must return (nil, nil), got (%v, %v)", p, denial)
	}

	_, denial = g.Check(context.Background(), "good", Surface{Path: "/api/v1/nope", HTTPMethod: "GET"})
	if denial == nil || denial.Code != DenyUnmappedSurface {
		t.Errorf("denial = %v, want %q", denial, DenyUnmappedSurface)
	}
	if denial.Error() == "" {
		t.Error("Denial must render as an error")
	}
}

// ---------------------------------------------------------------------------
// Exact surfaces: the route guard is the real permission, not a baseline
// ---------------------------------------------------------------------------

// TestExactRouteWinsOverTheSegmentPair is the whole point of Map.Exact. The
// "secrets" segment pair says ReadMetadata on both verbs; the reveal and the write
// declare what they actually do, and a caller holding only the pair's permission is
// refused at the DOOR rather than deeper in a handler that might forget to ask.
func TestExactRouteWinsOverTheSegmentPair(t *testing.T) {
	metadataOnly := enforced(blanket(Grant{Action: permReadMetadata}))

	// The segment pair still governs the routes nobody declared exactly.
	if w := serve(metadataOnly, request(http.MethodGet, "/api/v1/secrets", "good")); w.Code != http.StatusTeapot {
		t.Errorf("segment read: status = %d, want the handler to run", w.Code)
	}

	w := serve(metadataOnly, request(http.MethodPost, "/api/v1/secrets/reveal", "good"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("reveal with metadata only: status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if !strings.Contains(w.Body.String(), permGetSecret) {
		t.Errorf("body = %q, want the REVEAL permission named, not the segment baseline", w.Body.String())
	}

	w = serve(metadataOnly, request(http.MethodPost, "/api/v1/secrets", "good"))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), permPutSecret) {
		t.Errorf("write with metadata only: status = %d body = %q, want the WRITE permission demanded",
			w.Code, w.Body.String())
	}

	revealer := enforced(blanket(Grant{Action: permGetSecret}))
	if w := serve(revealer, request(http.MethodPost, "/api/v1/secrets/reveal", "good")); w.Code != http.StatusTeapot {
		t.Errorf("reveal with GetSecret: status = %d, want the handler to run", w.Code)
	}
}

// TestExactKeyNormalisesTheSpellingsOfOneSurface. A router reports "/api/v1/secrets/",
// a client sends "/api/v1/secrets", and both are the same surface. If they resolved
// differently, a table written against one spelling would silently fall through to the
// segment pair for the other — which is exactly the weakening the entry exists to stop.
func TestExactKeyNormalisesTheSpellingsOfOneSurface(t *testing.T) {
	want := ExactKey("POST", "/api/v1/secrets")
	for _, spelling := range []string{"/api/v1/secrets", "/api/v1/secrets/", "/api/v1/secrets//"} {
		if got := ExactKey("post", spelling); got != want {
			t.Errorf("ExactKey(post, %q) = %q, want %q", spelling, got, want)
		}
	}
	if got := ExactKey("GET", "/"); got != "GET /" {
		t.Errorf("ExactKey(GET, /) = %q, want the root path preserved", got)
	}

	g := enforced(blanket(Grant{Action: permReadMetadata}))
	for _, spelling := range []string{"/api/v1/secrets", "/api/v1/secrets/"} {
		w := serve(g, request(http.MethodPost, spelling, "good"))
		if w.Code != http.StatusForbidden {
			t.Errorf("POST %q: status = %d, want the exact entry to apply to both spellings",
				spelling, w.Code)
		}
	}
}

// TestAnUndeclaredNeighbourOfAnExactRouteIsDenied. Dropping a segment from Routes and
// declaring its routes exactly is STRONGER than a baseline: a new handler mounted
// beside them is unmapped, so it fails closed instead of inheriting a weak pair.
func TestAnUndeclaredNeighbourOfAnExactRouteIsDenied(t *testing.T) {
	m := Map{Prefix: "/api/v1/", Exact: map[string]Rule{
		"POST /api/v1/vault/reveal": {Permission: permGetSecret},
	}}
	if _, ok := m.Resolve(Surface{Path: "/api/v1/vault/exfiltrate", HTTPMethod: http.MethodPost}); ok {
		t.Error("an undeclared route on a segment with no pair must read as UNMAPPED")
	}
	if _, ok := m.Resolve(Surface{Path: "/api/v1/vault/reveal", HTTPMethod: http.MethodGet}); ok {
		t.Error("an exact entry is method-specific; another verb on the same path is unmapped")
	}
}

// TestExactPermissionsAreDeclared: a permission a route can demand must be registered
// in Auth, or the guard demands something no token can ever carry.
func TestExactPermissionsAreDeclared(t *testing.T) {
	declared := strings.Join(testMap.DeclaredPermissions(), " ")
	for _, p := range []string{permGetSecret, permPutSecret, permDeleteSecret} {
		if !strings.Contains(declared, p) {
			t.Errorf("DeclaredPermissions() = %q, missing the exact-route permission %q", declared, p)
		}
	}
}

// ---------------------------------------------------------------------------
// The actor check: service-to-service is not browser-to-backend
// ---------------------------------------------------------------------------

// TestServicePrincipalIsRefusedOnAUserOnlySurface is the stolen-m2m-credential case:
// the token is valid, the grants are real, and the caller is still the wrong CLASS of
// caller for an administrative surface.
func TestServicePrincipalIsRefusedOnAUserOnlySurface(t *testing.T) {
	workload := enforced(blanketOfKind(ActorKindService, Grant{Action: permAdmin}))

	w := serve(workload, request(http.MethodPost, "/api/v1/secrets/purge", "good"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if !strings.Contains(w.Body.String(), DenyActorKind) {
		t.Errorf("body = %q, want the distinct %q code", w.Body.String(), DenyActorKind)
	}
	if strings.Contains(w.Body.String(), permDeleteSecret) {
		t.Error("the actor denial must not name the grant the caller would need — " +
			"it runs first precisely so a wrong-class caller gets no shopping list")
	}

	operator := enforced(blanketOfKind(ActorKindUser, Grant{Action: permAdmin}))
	if w := serve(operator, request(http.MethodPost, "/api/v1/secrets/purge", "good")); w.Code != http.StatusTeapot {
		t.Errorf("a user principal on the same surface: status = %d, want the handler to run", w.Code)
	}
}

// TestUserPrincipalIsRefusedOnAServiceOnlySurface is the other direction: a browser
// session must not be able to drive a path that exists for a workload.
func TestUserPrincipalIsRefusedOnAServiceOnlySurface(t *testing.T) {
	operator := enforced(blanketOfKind(ActorKindUser, Grant{Action: permAdmin}))
	w := serve(operator, request(http.MethodPost, "/api/v1/secrets/fetch", "good"))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), DenyActorKind) {
		t.Errorf("status = %d body = %q, want an actor-kind denial", w.Code, w.Body.String())
	}

	workload := enforced(blanketOfKind(ActorKindService, Grant{Action: permAdmin}))
	if w := serve(workload, request(http.MethodPost, "/api/v1/secrets/fetch", "good")); w.Code != http.StatusTeapot {
		t.Errorf("a service principal on the same surface: status = %d, want the handler to run", w.Code)
	}
}

// TestTheSegmentPairCarriesTheActorConstraintPerVerb. Browsing projects is something a
// workload legitimately does; creating one is console work.
func TestTheSegmentPairCarriesTheActorConstraintPerVerb(t *testing.T) {
	workload := enforced(blanketOfKind(ActorKindService, Grant{Action: permAdmin}))

	if w := serve(workload, request(http.MethodGet, "/api/v1/projects", "good")); w.Code != http.StatusTeapot {
		t.Errorf("read: status = %d, want an unconstrained read to run", w.Code)
	}
	if w := serve(workload, request(http.MethodPost, "/api/v1/projects", "good")); w.Code != http.StatusForbidden {
		t.Errorf("write: status = %d, want the user-only write refused", w.Code)
	}
	// The audit segment constrains BOTH verbs.
	if w := serve(workload, request(http.MethodGet, "/api/v1/audit", "good")); w.Code != http.StatusForbidden {
		t.Errorf("audit read: status = %d, want the user-only read refused", w.Code)
	}
}

// TestAnUnclassifiedPrincipalFailsClosedOnAConstrainedSurface. "We could not tell what
// this caller is" is not a reason to admit it to a surface somebody restricted.
func TestAnUnclassifiedPrincipalFailsClosedOnAConstrainedSurface(t *testing.T) {
	unknown := enforced(&Principal{Grants: []Grant{{Action: permAdmin}}, BlanketActions: testMap.BlanketActions})

	if w := serve(unknown, request(http.MethodPost, "/api/v1/secrets/purge", "good")); w.Code != http.StatusForbidden {
		t.Errorf("user-only: status = %d, want a refusal", w.Code)
	}
	if w := serve(unknown, request(http.MethodPost, "/api/v1/secrets/fetch", "good")); w.Code != http.StatusForbidden {
		t.Errorf("service-only: status = %d, want a refusal", w.Code)
	}
	// ActorAny asked no question, so it admits the caller.
	if w := serve(unknown, request(http.MethodPost, "/api/v1/secrets/reveal", "good")); w.Code != http.StatusTeapot {
		t.Errorf("unconstrained: status = %d, want the handler to run", w.Code)
	}
}

// TestActorConstraintIsCheckedOnAnOpenSurfaceToo. A surface with no permission is one
// a service deliberately opened to authenticated callers — it can still be the wrong
// KIND of caller, and the empty permission must not short-circuit the class check.
func TestActorConstraintIsCheckedOnAnOpenSurfaceToo(t *testing.T) {
	m := testMap
	m.Exact = map[string]Rule{"GET /api/v1/secrets/open": {Actor: ActorUserOnly}}
	g := Guard{Mode: ModeEnforced, Permissions: m, Service: "secret",
		Verify: verifier(blanketOfKind(ActorKindService))}

	if w := serve(g, request(http.MethodGet, "/api/v1/secrets/open", "good")); w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want the class check to run before the empty permission short-circuits", w.Code)
	}
}

// TestGRPCActorConstraint: MethodActors is the gRPC half of the same statement.
func TestGRPCActorConstraint(t *testing.T) {
	const purge = "/maintainerd.secret.v1.SecretService/Purge"

	workload := enforced(blanketOfKind(ActorKindService, Grant{Action: permAdmin}))
	_, denial := workload.Check(context.Background(), "good", Surface{FullMethod: purge})
	if denial == nil || denial.Code != DenyActorKind {
		t.Fatalf("denial = %v, want %q", denial, DenyActorKind)
	}
	if denial.GRPCCode != codes.PermissionDenied {
		t.Errorf("GRPCCode = %v, want PermissionDenied", denial.GRPCCode)
	}

	operator := enforced(blanketOfKind(ActorKindUser, Grant{Action: permAdmin}))
	if _, denial := operator.Check(context.Background(), "good", Surface{FullMethod: purge}); denial != nil {
		t.Errorf("a user principal was denied: %v", denial)
	}

	// A method with no MethodActors entry is unconstrained.
	unconstrained := Surface{FullMethod: "/maintainerd.secret.v1.SecretService/Reveal"}
	if _, denial := workload.Check(context.Background(), "good", unconstrained); denial != nil {
		t.Errorf("an unconstrained method denied a service principal: %v", denial)
	}
}

// TestDevOpenBypassesTheActorCheck. The dev-open principal is attributed to a service
// subject; if the actor check ran before the mode ladder, every user-only surface in a
// development stack would answer 403 and the console would look broken rather than open.
func TestDevOpenBypassesTheActorCheck(t *testing.T) {
	g := Guard{Mode: ModeDevOpen, Permissions: testMap}
	if w := serve(g, request(http.MethodPost, "/api/v1/secrets/purge", "")); w.Code != http.StatusTeapot {
		t.Errorf("status = %d, want dev-open to admit every caller before the map is consulted", w.Code)
	}
}
