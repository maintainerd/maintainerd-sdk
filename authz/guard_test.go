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
