// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 HyvMind.io

// Package proxy implements a transparent HTTPS forward proxy with selective
// TLS interception (MITM) for hosts with known credentials, and raw TCP
// tunneling (passthrough) for all other hosts.
package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/hyvmind-io/stellaris-auth-golang/internal/ca"
	"github.com/hyvmind-io/stellaris-auth-golang/internal/credentials"
)

// Config holds the configuration for the proxy Server.
type Config struct {
	// Addr is the TCP address to listen on. Must be on 127.0.0.1 (e.g. "127.0.0.1:8080").
	Addr string

	// Credentials is the store used to look up Bearer tokens by hostname.
	Credentials *credentials.CredentialStore

	// CA is the Certificate Authority used to sign per-host leaf certificates.
	CA *ca.CA

	// CertCache caches generated leaf certificates keyed by hostname.
	CertCache *ca.Cache

	// Logger receives structured log output. Defaults to slog.Default().
	Logger *slog.Logger

	// ConnectTimeout is the dial timeout when connecting to upstream hosts.
	// Defaults to 10 seconds.
	ConnectTimeout time.Duration

	// IdleTimeout is the idle connection timeout on the HTTP server side.
	// Defaults to 60 seconds.
	IdleTimeout time.Duration

	// UpstreamTLSConfig is an optional base TLS configuration used when
	// dialling upstream servers over TLS. ServerName is always set to the
	// target hostname. When nil, a default config with only ServerName set
	// is used. Useful in tests to set InsecureSkipVerify: true.
	UpstreamTLSConfig *tls.Config
}

// Server is an HTTP/CONNECT forward proxy that selectively intercepts TLS.
type Server struct {
	cfg    Config
	ln     atomic.Pointer[net.Listener] // written once in ListenAndServe; read by Addr()
	server atomic.Pointer[http.Server]  // same lifecycle
	mitm   *mitmHandler
	tunnel *tunnelHandler
}

// New creates a new proxy Server from cfg. Zero-value fields receive sensible
// defaults: ConnectTimeout=10s, IdleTimeout=60s, Logger=slog.Default().
func New(cfg Config) *Server {
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 60 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	s := &Server{cfg: cfg}

	s.mitm = &mitmHandler{
		ca:                cfg.CA,
		certCache:         cfg.CertCache,
		logger:            cfg.Logger,
		dialTimeout:       cfg.ConnectTimeout,
		upstreamTLSConfig: cfg.UpstreamTLSConfig,
	}
	s.tunnel = &tunnelHandler{
		logger:      cfg.Logger,
		dialTimeout: cfg.ConnectTimeout,
	}

	return s
}

// ListenAndServe binds to cfg.Addr, stores the listener, and starts serving
// CONNECT requests. It blocks until the server is closed. Run it in a
// goroutine if you need non-blocking startup.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("proxy: listen %s: %w", s.cfg.Addr, err)
	}

	// Store atomically so Addr() and Shutdown() are safe without a mutex.
	s.ln.Store(&ln)

	srv := &http.Server{
		Handler:           s,
		IdleTimeout:       s.cfg.IdleTimeout,
		ReadHeaderTimeout: 10 * time.Second, // bound slow-header (Slowloris) clients
	}
	s.server.Store(srv)

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("proxy: serve: %w", err)
	}
	return nil
}

// Addr returns the address the proxy is listening on (e.g. "127.0.0.1:54321").
// Returns "" if the server has not started yet.
func (s *Server) Addr() string {
	if p := s.ln.Load(); p != nil {
		return (*p).Addr().String()
	}
	return ""
}

// Shutdown gracefully stops the proxy server. It drains active connections
// honouring ctx, then closes the listener.
func (s *Server) Shutdown(ctx context.Context) error {
	if p := s.server.Load(); p != nil {
		return (*p).Shutdown(ctx)
	}
	return nil
}

// ServeHTTP is the core dispatch method. It only accepts CONNECT; everything
// else is answered with 405. CONNECT requests are routed to the MITM handler
// when a credential exists for the target hostname, otherwise to the tunnel.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// r.Host for CONNECT is "hostname:port" — split to get the bare hostname
	// used for certificate issuance. We keep the full host string for dialling.
	hostname, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		// If SplitHostPort fails (no port in r.Host), treat the whole value as
		// both the bare hostname and the dial target.
		hostname = r.Host
	}

	// host is the full "hostname:port" string used for dialling.
	host := r.Host

	// ── Credential lookup ─────────────────────────────────────────────────────
	// Try the full host:port first (most specific — matches .tofurc blocks like
	// `credentials "registry.example.com:3000" { ... }`), then fall back to the
	// bare hostname (matches blocks without a port). This two-step lookup is
	// intentional: CredentialStore.Lookup performs exact matching only, so the
	// port-stripping fallback lives here where we have the full CONNECT context.
	token, found := s.cfg.Credentials.Lookup(host)
	if !found {
		token, found = s.cfg.Credentials.Lookup(hostname)
	}

	if s.cfg.Logger.Enabled(r.Context(), slog.LevelDebug) {
		s.cfg.Logger.Debug("[proxy] credential lookup",
			slog.String("r.Host", r.Host),
			slog.String("tried_host_port", host),
			slog.String("tried_hostname", hostname),
			slog.Bool("found", found),
		)
	}

	if found {
		s.cfg.Logger.Info("[proxy] MITM",
			slog.String("hostname", hostname),
			slog.String("host", host),
			slog.String("action", "Bearer injected"),
		)
		s.mitm.Handle(w, r, host, hostname, token)
	} else {
		s.cfg.Logger.Info("[proxy] TUNNEL",
			slog.String("hostname", hostname),
			slog.String("host", host),
			slog.String("action", "passthrough"),
		)
		s.tunnel.Handle(w, r, host)
	}
}
