// Package ca provides Certificate Authority lifecycle management for the
// stellaris-auth transparent HTTPS forward proxy.
//
// It handles generating the root CA certificate, storing it on disk, loading
// it back on subsequent starts, and issuing per-host leaf certificates used
// for MITM TLS interception.
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	// CACertFile is the filename for the CA certificate PEM file.
	CACertFile = "stellaris-auth-ca.crt"
	// CAKeyFile is the filename for the CA private key PEM file.
	CAKeyFile = "stellaris-auth-ca.key"
)

// CA holds the loaded or generated Certificate Authority material.
type CA struct {
	// Certificate is the parsed x509 CA certificate.
	Certificate *x509.Certificate
	// TLSCert is the tls.Certificate containing both cert and private key,
	// ready for use as a signing parent.
	TLSCert tls.Certificate
	// CertPEM is the raw PEM-encoded certificate bytes.
	CertPEM []byte
	// KeyPEM is the raw PEM-encoded private key bytes.
	// NEVER log this value.
	KeyPEM []byte
}

// Manager manages CA certificate lifecycle: generation, storage, and loading.
type Manager struct {
	caDir  string
	logger *slog.Logger
}

// NewManager creates a new Manager that stores CA files in caDir.
func NewManager(caDir string, logger *slog.Logger) *Manager {
	return &Manager{
		caDir:  caDir,
		logger: logger,
	}
}

// CertPath returns the absolute path to the CA certificate file.
func (m *Manager) CertPath() string {
	return filepath.Join(m.caDir, CACertFile)
}

// KeyPath returns the absolute path to the CA private key file.
func (m *Manager) KeyPath() string {
	return filepath.Join(m.caDir, CAKeyFile)
}

// Exists reports whether both the CA certificate and key files exist on disk.
func (m *Manager) Exists() bool {
	_, certErr := os.Stat(m.CertPath())
	_, keyErr := os.Stat(m.KeyPath())
	return certErr == nil && keyErr == nil
}

// EnsureCA returns the CA, loading it from disk if it already exists or
// generating a new one if it does not. This is the primary method called
// during proxy startup.
func (m *Manager) EnsureCA() (*CA, error) {
	if m.Exists() {
		m.logger.Info("loading existing CA certificate", "path", m.CertPath())
		return m.LoadCA()
	}
	m.logger.Info("generating new CA certificate", "dir", m.caDir)
	return m.GenerateCA(false)
}

// GenerateCA generates a new RSA 4096-bit self-signed CA certificate and
// writes it to disk. If force is false and the files already exist, it
// returns an error. If force is true, existing files are overwritten.
func (m *Manager) GenerateCA(force bool) (*CA, error) {
	if err := os.MkdirAll(m.caDir, 0700); err != nil {
		return nil, fmt.Errorf("ca: create directory %q: %w", m.caDir, err)
	}

	if !force && m.Exists() {
		return nil, fmt.Errorf("ca: CA already exists at %q; use force=true to overwrite", m.caDir)
	}

	m.logger.Info("generating RSA 4096-bit CA key pair")

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("ca: generate RSA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("ca: generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "stellaris-auth CA",
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	// Self-signed: parent == template, signing key == generated key.
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("ca: create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	if err := os.WriteFile(m.CertPath(), certPEM, 0644); err != nil {
		return nil, fmt.Errorf("ca: write cert file: %w", err)
	}
	if err := os.WriteFile(m.KeyPath(), keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("ca: write key file: %w", err)
	}

	m.logger.Info("CA certificate written to disk",
		"cert", m.CertPath(),
		"key", m.KeyPath(),
		"serial", serial.String(),
		"not_before", template.NotBefore,
		"not_after", template.NotAfter,
	)

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("ca: parse generated certificate: %w", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}

	return &CA{
		Certificate: cert,
		TLSCert:     tlsCert,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// LoadCA reads the CA certificate and key from disk and returns a populated CA.
// It warns (via slog) if the key file has permissions more permissive than 0600.
func (m *Manager) LoadCA() (*CA, error) {
	certPEM, err := os.ReadFile(m.CertPath())
	if err != nil {
		return nil, fmt.Errorf("ca: read cert file: %w", err)
	}

	keyPEM, err := os.ReadFile(m.KeyPath())
	if err != nil {
		return nil, fmt.Errorf("ca: read key file: %w", err)
	}

	// Check key file permissions — warn if more permissive than 0600.
	if info, statErr := os.Stat(m.KeyPath()); statErr == nil {
		mode := info.Mode().Perm()
		if mode&0177 != 0 {
			m.logger.Warn("CA key file has overly permissive permissions; restrict to 0600",
				"path", m.KeyPath(),
				"mode", fmt.Sprintf("%04o", mode),
			)
		}
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("ca: parse key pair: %w", err)
	}

	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("ca: parse certificate: %w", err)
	}
	tlsCert.Leaf = cert

	m.logger.Info("CA certificate loaded from disk",
		"cert", m.CertPath(),
		"serial", cert.SerialNumber.String(),
		"not_after", cert.NotAfter,
	)

	return &CA{
		Certificate: cert,
		TLSCert:     tlsCert,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// PrintTrustInstructions writes OS-specific instructions for trusting the CA
// certificate to w. certPath should be the absolute path to the CA cert file.
func PrintTrustInstructions(w io.Writer, certPath string) {
	fmt.Fprintln(w, "To trust the stellaris-auth CA certificate, run one of the following:")
	fmt.Fprintln(w)

	switch runtime.GOOS {
	case "darwin":
		fmt.Fprintf(w, "  macOS (Keychain):\n")
		fmt.Fprintf(w, "    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n", certPath)
	case "linux":
		fmt.Fprintf(w, "  Linux (system trust store):\n")
		fmt.Fprintf(w, "    sudo cp %s /usr/local/share/ca-certificates/\n", certPath)
		fmt.Fprintf(w, "    sudo update-ca-certificates\n")
	case "windows":
		fmt.Fprintf(w, "  Windows (Certificate Store):\n")
		fmt.Fprintf(w, "    certutil -addstore Root %s\n", certPath)
	default:
		fmt.Fprintf(w, "  See your OS documentation for adding a trusted root CA certificate.\n")
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Alternative (environment variable, works on all platforms):\n")
	fmt.Fprintf(w, "    export SSL_CERT_FILE=%s\n", certPath)
	fmt.Fprintln(w)
}

// randomSerial generates a cryptographically random 128-bit serial number.
func randomSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}
