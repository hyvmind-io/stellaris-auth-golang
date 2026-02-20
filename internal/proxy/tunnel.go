package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// tunnelHandler creates a transparent bidirectional TCP tunnel between the
// client and the upstream for hosts that have no registered credentials.
// No TLS interception occurs — bytes are copied verbatim in both directions.
type tunnelHandler struct {
	logger      *slog.Logger
	dialTimeout time.Duration
}

// Handle establishes the tunnel:
//
//  1. Dials the upstream host.
//  2. Hijacks the client connection.
//  3. Sends "200 Connection Established".
//  4. Bidirectionally pipes data between client and upstream.
func (h *tunnelHandler) Handle(w http.ResponseWriter, r *http.Request, host string) {
	// ── 1. Dial upstream ─────────────────────────────────────────────────────
	upstream, err := net.DialTimeout("tcp", host, h.dialTimeout)
	if err != nil {
		h.logger.Error("tunnel: dial upstream", "host", host, "err", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	// ── 2. Hijack client ─────────────────────────────────────────────────────
	clientConn, _, err := hijackConn(w)
	if err != nil {
		h.logger.Error("tunnel: hijack", "err", err)
		return
	}
	defer clientConn.Close()

	// ── 3. 200 Connection Established ────────────────────────────────────────
	if _, err := fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		h.logger.Error("tunnel: write 200", "err", err)
		return
	}

	// ── 4. Bidirectional pipe ─────────────────────────────────────────────────
	pipe(clientConn, upstream)
}

// pipe copies data between a and b simultaneously. It blocks until both
// directions have been drained (one direction EOF causes CloseWrite on the
// other side so the remote end also terminates cleanly).
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)

	copyHalf := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		_, _ = io.Copy(dst, src)
		// Signal half-close so the remote peer sees EOF on its read side.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}

	go copyHalf(a, b)
	go copyHalf(b, a)

	// Wait for both directions.
	<-done
	<-done
}
