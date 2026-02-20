package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/hyvmind-io/stellaris-auth/internal/ca"
)

// mitmHandler intercepts TLS connections for hosts that have a registered
// Bearer token credential. It terminates the client TLS session using a
// CA-signed leaf certificate, reads plain HTTP requests, injects the
// Authorization header, and forwards them over a fresh TLS connection to the
// real upstream server.
type mitmHandler struct {
	ca                *ca.CA
	certCache         *ca.Cache
	logger            *slog.Logger
	dialTimeout       time.Duration
	upstreamTLSConfig *tls.Config // nil → default (ServerName only)
}

// Handle performs the full MITM flow for a single CONNECT request:
//
//  1. Retrieve (or generate) a leaf certificate for hostname.
//  2. Hijack the client TCP connection.
//  3. Send "200 Connection Established" to start the TLS handshake.
//  4. Wrap the client side in TLS (server role) using the leaf cert.
//  5. Dial the upstream and wrap it in TLS (client role) with SNI.
//  6. Proxy HTTP/1.1 keep-alive requests, injecting the Bearer token on each.
func (h *mitmHandler) Handle(
	w http.ResponseWriter,
	r *http.Request,
	host, hostname, token string,
) {
	// ── 1. Leaf certificate ─────────────────────────────────────────────────
	leafCert, err := h.certCache.GetOrCreate(hostname, h.ca)
	if err != nil {
		h.logger.Error("mitm: get leaf cert", "hostname", hostname, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// ── 2. Hijack client connection ──────────────────────────────────────────
	clientConn, _, err := hijackConn(w)
	if err != nil {
		h.logger.Error("mitm: hijack", "err", err)
		return
	}
	defer clientConn.Close()

	// ── 3. 200 Connection Established ───────────────────────────────────────
	if _, err := fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		h.logger.Error("mitm: write 200", "err", err)
		return
	}

	// ── 4. TLS server side (towards client) ─────────────────────────────────
	tlsClient := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
	})
	defer tlsClient.Close()

	if err := tlsClient.Handshake(); err != nil {
		h.logger.Error("mitm: client TLS handshake", "hostname", hostname, "err", err)
		return
	}

	// ── 5. Dial upstream ─────────────────────────────────────────────────────
	tcpUpstream, err := net.DialTimeout("tcp", host, h.dialTimeout)
	if err != nil {
		h.logger.Error("mitm: dial upstream", "host", host, "err", err)
		return
	}
	defer tcpUpstream.Close()

	upstreamTLSCfg := h.upstreamTLSConfigFor(hostname)
	tlsUpstream := tls.Client(tcpUpstream, upstreamTLSCfg)
	defer tlsUpstream.Close()

	if err := tlsUpstream.Handshake(); err != nil {
		h.logger.Error("mitm: upstream TLS handshake", "hostname", hostname, "err", err)
		return
	}

	// ── 6. HTTP/1.1 request-response loop ────────────────────────────────────
	clientReader := bufio.NewReader(tlsClient)
	upstreamReader := bufio.NewReader(tlsUpstream)

	for {
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err != io.EOF {
				h.logger.Debug("mitm: read request", "hostname", hostname, "err", err)
			}
			return
		}

		// Inject Bearer token — Set replaces any existing Authorization header.
		injectBearer(req, token)

		// Fix the request for forwarding: clear RequestURI (Go's HTTP client
		// rejects non-empty RequestURI) and ensure URL has scheme + host.
		req.RequestURI = ""
		if req.URL.Scheme == "" {
			req.URL.Scheme = "https"
		}
		if req.URL.Host == "" {
			req.URL.Host = host
		}

		if err := req.Write(tlsUpstream); err != nil {
			h.logger.Error("mitm: write request to upstream", "hostname", hostname, "err", err)
			return
		}

		resp, err := http.ReadResponse(upstreamReader, req)
		if err != nil {
			h.logger.Error("mitm: read response from upstream", "hostname", hostname, "err", err)
			return
		}

		if err := resp.Write(tlsClient); err != nil {
			resp.Body.Close()
			h.logger.Error("mitm: write response to client", "hostname", hostname, "err", err)
			return
		}
		resp.Body.Close()

		// Honour Connection: close from either side.
		if req.Close || resp.Close {
			return
		}
	}
}

// hijackConn promotes the HTTP connection to a raw TCP connection via the
// http.Hijacker interface.
func hijackConn(w http.ResponseWriter) (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("proxy: ResponseWriter does not implement http.Hijacker")
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: hijack: %w", err)
	}
	return conn, bufrw, nil
}

// injectBearer sets the Authorization header to "Bearer <token>", replacing
// any existing value. Using Set (not Add) prevents header duplication.
func injectBearer(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
}

// upstreamTLSConfigFor returns a *tls.Config suitable for dialling hostname.
// If h.upstreamTLSConfig is set it is cloned and ServerName applied; otherwise
// a minimal config containing only ServerName is returned.
func (h *mitmHandler) upstreamTLSConfigFor(hostname string) *tls.Config {
	var cfg *tls.Config
	if h.upstreamTLSConfig != nil {
		cfg = h.upstreamTLSConfig.Clone()
	} else {
		cfg = &tls.Config{}
	}
	cfg.ServerName = hostname
	return cfg
}
