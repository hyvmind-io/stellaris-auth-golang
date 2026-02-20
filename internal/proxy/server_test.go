package proxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hyvmind-io/stellaris-auth/internal/ca"
	"github.com/hyvmind-io/stellaris-auth/internal/credentials"
	"github.com/hyvmind-io/stellaris-auth/internal/proxy"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// newTestProxy creates a proxy server configured with the given host→token
// map and an ephemeral port on 127.0.0.1. It blocks until the listener is
// ready (or t.Fatal on timeout) and registers a Cleanup hook to shut it down.
// The test CA is returned so callers can build trust pools for clients.
func newTestProxy(t *testing.T, hosts map[string]string) (*proxy.Server, *ca.CA) {
	t.Helper()

	store := credentials.New()
	for h, tok := range hosts {
		store.Set(h, tok)
	}

	caManager := ca.NewManager(t.TempDir(), slog.Default())
	testCA, err := caManager.GenerateCA(false)
	if err != nil {
		t.Fatal(err)
	}

	cache := ca.NewCache()
	srv := proxy.New(proxy.Config{
		Addr:           "127.0.0.1:0",
		Credentials:    store,
		CA:             testCA,
		CertCache:      cache,
		Logger:         slog.Default(),
		ConnectTimeout: 5 * time.Second,
		IdleTimeout:    10 * time.Second,
		// Skip upstream cert verification so tests work with httptest servers.
		UpstreamTLSConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	})

	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	go func() { _ = srv.ListenAndServe() }()

	// Wait for the listener to be ready.
	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Addr() == "" {
		t.Fatal("proxy did not start")
	}

	return srv, testCA
}

// proxyClient returns an *http.Client that routes all traffic through the proxy
// at proxyAddr and trusts the provided CA certificate PEM (used to verify the
// MITM leaf certificates issued by the proxy).
// Pass skipVerify=true to disable all TLS verification (useful for tests that
// only care about request metadata, not cert correctness).
func proxyClient(t *testing.T, proxyAddr string, caPEM []byte, skipVerify bool) *http.Client {
	t.Helper()

	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatal(err)
	}

	tlsCfg := &tls.Config{} //nolint:gosec
	if skipVerify {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
	} else if caPEM != nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			t.Fatal("failed to add CA cert to pool")
		}
		tlsCfg.RootCAs = pool
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: tlsCfg,
		},
		Timeout: 10 * time.Second,
	}
}

// ─── tests ────────────────────────────────────────────────────────────────────

// TestProxy_MITMInjectsBearer verifies that when the target hostname has
// credentials, the proxy performs MITM and injects "Bearer <token>" into the
// upstream request.
func TestProxy_MITMInjectsBearer(t *testing.T) {
	// Capture the Authorization header seen by the upstream.
	var (
		mu         sync.Mutex
		gotAuthHdr string
	)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuthHdr = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// The upstream URL is e.g. https://127.0.0.1:PORT — extract host:port.
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamHost := upstreamURL.Hostname() // "127.0.0.1"
	upstreamAddr := upstreamURL.Host       // "127.0.0.1:PORT"

	const token = "test-token"
	srv, _ := newTestProxy(t, map[string]string{
		upstreamHost: token,
	})

	// The proxy issues a leaf cert for "127.0.0.1" which only has a DNSName
	// SAN (not an IP SAN), so the standard TLS verifier rejects it.  Use
	// InsecureSkipVerify on the client side in the test — what we're testing
	// here is the header injection, not certificate validity.
	client := proxyClient(t, srv.Addr(), nil, true)

	resp, err := client.Get("https://" + upstreamAddr + "/")
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	mu.Lock()
	got := gotAuthHdr
	mu.Unlock()

	want := "Bearer " + token
	if got != want {
		t.Errorf("Authorization header = %q; want %q", got, want)
	}
}

// TestProxy_TunnelPassthrough verifies that a host with no registered
// credentials is tunnelled without interception: bytes pass through verbatim.
func TestProxy_TunnelPassthrough(t *testing.T) {
	// Start a raw TCP echo server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const echoed = "HELLO TUNNEL\n"
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read one line, echo it back.
		buf := make([]byte, len(echoed))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		_, _ = conn.Write(buf)
	}()

	echoAddr := ln.Addr().String() // "127.0.0.1:PORT"

	// No credentials registered → tunnel.
	srv, _ := newTestProxy(t, map[string]string{})

	// Manually perform the CONNECT + raw exchange.
	conn, err := net.DialTimeout("tcp", srv.Addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send CONNECT to the echo server's address.
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr)

	// Read the 200 response.
	resp, err := http.ReadResponse(newBufReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response status: %d", resp.StatusCode)
	}

	// Send data and expect it back (echo).
	if _, err := fmt.Fprint(conn, echoed); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(echoed))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != echoed {
		t.Errorf("echo = %q; want %q", got, echoed)
	}
}

// TestProxy_HeaderReplacement verifies that an existing Authorization header
// is replaced (not duplicated) by the proxy's injected Bearer token.
func TestProxy_HeaderReplacement(t *testing.T) {
	var (
		mu         sync.Mutex
		gotHeaders []string
	)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		// Collect all Authorization values to detect duplication.
		gotHeaders = r.Header["Authorization"]
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamHost := upstreamURL.Hostname()
	upstreamAddr := upstreamURL.Host

	const newToken = "new-secret"
	srv, _ := newTestProxy(t, map[string]string{
		upstreamHost: newToken,
	})

	// Same IP SAN caveat as TestProxy_MITMInjectsBearer.
	client := proxyClient(t, srv.Addr(), nil, true)

	req, _ := http.NewRequest(http.MethodGet, "https://"+upstreamAddr+"/", nil)
	req.Header.Set("Authorization", "Bearer OLD")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	mu.Lock()
	hdrs := gotHeaders
	mu.Unlock()

	if len(hdrs) != 1 {
		t.Fatalf("Authorization header count = %d; want exactly 1 (got: %v)", len(hdrs), hdrs)
	}
	want := "Bearer " + newToken
	if hdrs[0] != want {
		t.Errorf("Authorization = %q; want %q", hdrs[0], want)
	}
}

// TestProxy_NonCONNECT verifies that non-CONNECT methods are rejected with 405.
func TestProxy_NonCONNECT(t *testing.T) {
	srv, _ := newTestProxy(t, map[string]string{})

	resp, err := http.Get("http://" + srv.Addr() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// TestProxy_Shutdown verifies that after Shutdown the proxy no longer accepts
// connections.
func TestProxy_Shutdown(t *testing.T) {
	srv, _ := newTestProxy(t, map[string]string{})
	addr := srv.Addr()
	if addr == "" {
		t.Fatal("Addr() is empty before shutdown")
	}

	// Trigger shutdown explicitly (cleanup will also call it, but that's ok).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// Allow the server goroutine to stop.
	time.Sleep(50 * time.Millisecond)

	// New connections should now fail.
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		conn.Close()
		t.Error("expected connection to fail after Shutdown, but it succeeded")
	}
}

// TestProxy_AddrAfterListen verifies that binding to port 0 yields a non-zero
// ephemeral port reported by Addr().
func TestProxy_AddrAfterListen(t *testing.T) {
	srv, _ := newTestProxy(t, map[string]string{})

	addr := srv.Addr()
	if addr == "" {
		t.Fatal("Addr() returned empty string")
	}

	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}

	if portStr == "0" {
		t.Errorf("Addr() returned port 0; expected ephemeral port: %s", addr)
	}

	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Errorf("Addr() = %q; want 127.0.0.1:<port>", addr)
	}
}

// ─── internal helpers ─────────────────────────────────────────────────────────

// newBufReader wraps a net.Conn in a bufio.Reader so http.ReadResponse can
// consume the header.
func newBufReader(conn net.Conn) *bufio.Reader {
	return bufio.NewReader(conn)
}
