package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIntrospectActive(t *testing.T) {
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotToken = r.Form.Get("token")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"scope":"core:read core:admin","sub":"u1","tenant":"t1","client_id":"c1"}`))
	}))
	defer srv.Close()

	got, err := Introspect(context.Background(), "abc", IntrospectionConfig{IntrospectionEndpoint: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotToken != "abc" {
		t.Fatalf("server received token %q, want abc", gotToken)
	}
	if !got.Active {
		t.Fatal("expected active token")
	}
	if got.Subject != "u1" || got.Tenant != "t1" {
		t.Fatalf("subject/tenant = %q/%q", got.Subject, got.Tenant)
	}
	if s := got.Scopes(); len(s) != 2 || s[0] != "core:read" || s[1] != "core:admin" {
		t.Fatalf("scopes = %v", s)
	}
	if got.Raw["client_id"] != "c1" {
		t.Fatalf("raw client_id = %v", got.Raw["client_id"])
	}
}

func TestIntrospectInactive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"active":false}`))
	}))
	defer srv.Close()

	got, err := Introspect(context.Background(), "x", IntrospectionConfig{IntrospectionEndpoint: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Active {
		t.Fatal("expected inactive token")
	}
}

func TestIntrospectRequiresConfig(t *testing.T) {
	if _, err := Introspect(context.Background(), "", IntrospectionConfig{IntrospectionEndpoint: "x"}); err == nil {
		t.Fatal("expected error for empty token")
	}
	if _, err := Introspect(context.Background(), "t", IntrospectionConfig{}); err == nil {
		t.Fatal("expected error for empty endpoint")
	}
}

func TestRevoke(t *testing.T) {
	var gotToken, gotHint string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotToken = r.Form.Get("token")
		gotHint = r.Form.Get("token_type_hint")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := Revoke(context.Background(), "rt", "refresh_token", RevocationConfig{RevocationEndpoint: srv.URL}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotToken != "rt" || gotHint != "refresh_token" {
		t.Fatalf("server received token/hint = %q/%q", gotToken, gotHint)
	}
}

func TestRevokeRequiresConfig(t *testing.T) {
	if err := Revoke(context.Background(), "", "", RevocationConfig{RevocationEndpoint: "x"}); err == nil {
		t.Fatal("expected error for empty token")
	}
	if err := Revoke(context.Background(), "t", "", RevocationConfig{}); err == nil {
		t.Fatal("expected error for empty endpoint")
	}
}

func TestUserInfo(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"u1","email":"a@b.c"}`))
	}))
	defer srv.Close()

	claims, err := UserInfo(context.Background(), srv.URL, "AT", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer AT" {
		t.Fatalf("Authorization header = %q, want 'Bearer AT'", gotAuth)
	}
	if claims["sub"] != "u1" || claims["email"] != "a@b.c" {
		t.Fatalf("claims = %v", claims)
	}
}

func TestUserInfoRequiresConfig(t *testing.T) {
	if _, err := UserInfo(context.Background(), "", "t", nil); err == nil {
		t.Fatal("expected error for empty endpoint")
	}
	if _, err := UserInfo(context.Background(), "x", "", nil); err == nil {
		t.Fatal("expected error for empty token")
	}
}
