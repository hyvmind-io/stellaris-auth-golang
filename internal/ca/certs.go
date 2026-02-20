package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"sync"
	"time"
)

// Cache is a thread-safe in-memory cache of per-host leaf TLS certificates.
// Certificates are generated on first access and reused for subsequent
// connections to the same hostname.
type Cache struct {
	mu    sync.RWMutex
	certs map[string]*tls.Certificate
}

// NewCache creates a new, empty Cache ready for use.
func NewCache() *Cache {
	return &Cache{
		certs: make(map[string]*tls.Certificate),
	}
}

// GetOrCreate returns a leaf TLS certificate for the given hostname. If a
// certificate already exists in the cache it is returned immediately. If not,
// a new one is generated using the provided CA, stored, and returned.
//
// The method is safe for concurrent use. A double-checked lock ensures that
// only one certificate is generated per hostname even under high concurrency.
func (c *Cache) GetOrCreate(hostname string, ca *CA) (*tls.Certificate, error) {
	// Fast path: read lock.
	c.mu.RLock()
	if cert, ok := c.certs[hostname]; ok {
		c.mu.RUnlock()
		return cert, nil
	}
	c.mu.RUnlock()

	// Slow path: write lock with double-check.
	c.mu.Lock()
	defer c.mu.Unlock()

	// Another goroutine may have created the cert while we were waiting.
	if cert, ok := c.certs[hostname]; ok {
		return cert, nil
	}

	cert, err := GenerateLeafCert(hostname, ca)
	if err != nil {
		return nil, err
	}

	c.certs[hostname] = cert
	return cert, nil
}

// GenerateLeafCert generates a new RSA 2048-bit leaf certificate for hostname,
// signed by the provided CA. The certificate includes a Subject Alternative
// Name (SAN) for hostname, which is required by Go's TLS stack since Go 1.15.
func GenerateLeafCert(hostname string, ca *CA) (*tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("ca: generate leaf RSA key for %q: %w", hostname, err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("ca: generate leaf serial for %q: %w", hostname, err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		// SAN is mandatory — Go's x509 verification requires it since Go 1.15.
		DNSNames:    []string{hostname},
		NotBefore:   now.Add(-1 * time.Minute),
		NotAfter:    now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	signingKey := ca.TLSCert.PrivateKey

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, &privateKey.PublicKey, signingKey)
	if err != nil {
		return nil, fmt.Errorf("ca: create leaf certificate for %q: %w", hostname, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("ca: parse leaf key pair for %q: %w", hostname, err)
	}

	// Pre-parse the leaf to avoid repeated parsing on each TLS handshake.
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("ca: parse leaf certificate for %q: %w", hostname, err)
	}
	tlsCert.Leaf = leaf

	return &tlsCert, nil
}

// Note: randomSerial() is defined in manager.go and shared within the package.
