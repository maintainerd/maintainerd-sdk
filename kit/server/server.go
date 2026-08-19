// Package server bootstraps the HTTP + gRPC servers every maintainerd service
// runs — health, gRPC reflection, graceful shutdown, and concurrent serving —
// so services stop copy-pasting the same boilerplate.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// NewGRPC builds a gRPC server with health + reflection registered, then calls
// register so the caller can attach its own service(s).
func NewGRPC(register func(*grpc.Server)) *grpc.Server {
	gs := grpc.NewServer()
	if register != nil {
		register(gs)
	}
	healthpb.RegisterHealthServer(gs, health.NewServer())
	reflection.Register(gs)
	return gs
}

// ServeGRPC serves gs on addr and stops gracefully when ctx is cancelled.
func ServeGRPC(ctx context.Context, addr string, gs *grpc.Server) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		slog.Info("shutting down grpc server", "addr", addr)
		gs.GracefulStop()
	}()
	slog.Info("grpc server listening", "addr", addr)
	if err := gs.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

// ServeHTTP serves handler on addr and shuts down gracefully when ctx is cancelled.
func ServeHTTP(ctx context.Context, addr string, handler http.Handler) error {
	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		slog.Info("http server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutting down http server", "addr", addr)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// Healthz is a liveness handler returning {"status":"ok"}.
func Healthz() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// WriteJSON writes a JSON response.
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// Run serves the given functions concurrently and returns when the first errors
// or ctx is cancelled (whereupon the rest drain). This is the errgroup pattern
// every service's bootstrap repeats.
func Run(ctx context.Context, fns ...func(context.Context) error) error {
	g, gctx := errgroup.WithContext(ctx)
	for _, fn := range fns {
		fn := fn
		g.Go(func() error { return fn(gctx) })
	}
	return g.Wait()
}
