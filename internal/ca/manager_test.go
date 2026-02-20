package ca

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

// newTestManager creates a Manager backed by t.TempDir() with a discard logger.
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return NewManager(t.TempDir(), logger)
}

// -------------------------------------------------------------------------
// GenerateCA tests
// -------------------------------------------------------------------------

func TestGenerateCA_attributes(t *testing.T) {
	m := newTestManager(t)
	ca, err := m.GenerateCA(false)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	cert := ca.Certificate

	// Key type and size.
	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("expected RSA public key")
	}
	if rsaKey.N.BitLen() != 4096 {
		t.Errorf("key size = %d, want 4096", rsaKey.N.BitLen())
	}

	// IsCA flag.
	if !cert.IsCA {
		t.Error("IsCA = false, want true")
	}
	if !cert.BasicConstraintsValid {
		t.Error("BasicConstraintsValid = false, want true")
	}

	// Common name.
	if got := cert.Subject.CommonName; got != "stellaris-auth CA" {
		t.Errorf("CN = %q, want %q", got, "stellaris-auth CA")
	}

	// Validity period: roughly 365 days (allow ±5 minutes for test timing).
	wantDuration := 365 * 24 * time.Hour
	gotDuration := cert.NotAfter.Sub(cert.NotBefore)
	delta := gotDuration - wantDuration
	if delta < -5*time.Minute || delta > 5*time.Minute {
		t.Errorf("validity duration = %v, want ~%v", gotDuration, wantDuration)
	}

	// NotBefore should be slightly in the past (clock-skew buffer).
	if cert.NotBefore.After(time.Now()) {
		t.Errorf("NotBefore %v is in the future", cert.NotBefore)
	}

	// Signature algorithm must be SHA-256 (RSA with SHA256).
	if cert.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Errorf("SignatureAlgorithm = %v, want SHA256WithRSA", cert.SignatureAlgorithm)
	}

	// KeyUsage.
	want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if cert.KeyUsage&want != want {
		t.Errorf("KeyUsage = %v, want CertSign|CRLSign", cert.KeyUsage)
	}
}

func TestGenerateCA_selfSigned(t *testing.T) {
	m := newTestManager(t)
	ca, err := m.GenerateCA(false)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	cert := ca.Certificate

	// Issuer must equal Subject for a self-signed cert.
	if cert.Issuer.String() != cert.Subject.String() {
		t.Errorf("Issuer %q != Subject %q", cert.Issuer, cert.Subject)
	}

	// The cert should verify against a pool containing itself.
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := cert.Verify(opts); err != nil {
		t.Errorf("self-verification failed: %v", err)
	}
}

func TestGenerateCA_filePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on Windows")
	}

	m := newTestManager(t)
	if _, err := m.GenerateCA(false); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	// Key file: must be 0600.
	keyInfo, err := os.Stat(m.KeyPath())
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if got := keyInfo.Mode().Perm(); got != 0600 {
		t.Errorf("key perm = %04o, want 0600", got)
	}

	// Cert file: must be 0644.
	certInfo, err := os.Stat(m.CertPath())
	if err != nil {
		t.Fatalf("stat cert: %v", err)
	}
	if got := certInfo.Mode().Perm(); got != 0644 {
		t.Errorf("cert perm = %04o, want 0644", got)
	}
}

func TestGenerateCA_forceRegenerate(t *testing.T) {
	m := newTestManager(t)

	first, err := m.GenerateCA(false)
	if err != nil {
		t.Fatalf("first GenerateCA: %v", err)
	}

	second, err := m.GenerateCA(true)
	if err != nil {
		t.Fatalf("force GenerateCA: %v", err)
	}

	// Serials must differ (regenerated).
	if first.Certificate.SerialNumber.Cmp(second.Certificate.SerialNumber) == 0 {
		t.Error("serial numbers are identical after force regeneration")
	}
}

func TestGenerateCA_noForceExisting(t *testing.T) {
	m := newTestManager(t)

	if _, err := m.GenerateCA(false); err != nil {
		t.Fatalf("first GenerateCA: %v", err)
	}

	_, err := m.GenerateCA(false)
	if err == nil {
		t.Fatal("expected error when force=false and CA already exists, got nil")
	}
}

// -------------------------------------------------------------------------
// LoadCA tests
// -------------------------------------------------------------------------

func TestLoadCA_reuse(t *testing.T) {
	m := newTestManager(t)

	gen, err := m.GenerateCA(false)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	loaded, err := m.LoadCA()
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	// Serial numbers must match.
	if gen.Certificate.SerialNumber.Cmp(loaded.Certificate.SerialNumber) != 0 {
		t.Errorf("serial mismatch: generated=%s loaded=%s",
			gen.Certificate.SerialNumber, loaded.Certificate.SerialNumber)
	}

	// Raw DER bytes must match.
	if string(gen.Certificate.Raw) != string(loaded.Certificate.Raw) {
		t.Error("certificate DER bytes differ between generated and loaded")
	}
}

func TestLoadCA_permissiveKeyWarn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on Windows")
	}

	m := newTestManager(t)
	if _, err := m.GenerateCA(false); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	// Deliberately loosen permissions on the key file.
	if err := os.Chmod(m.KeyPath(), 0644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	// LoadCA must still succeed (it warns, does not fail).
	loaded, err := m.LoadCA()
	if err != nil {
		t.Fatalf("LoadCA with permissive key should succeed, got: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadCA returned nil CA")
	}
	// The warning is emitted to the logger; we trust slog to output it.
	// Functional correctness (load succeeds) is what we assert here.
}

// -------------------------------------------------------------------------
// EnsureCA tests
// -------------------------------------------------------------------------

func TestEnsureCA_missingGenerates(t *testing.T) {
	m := newTestManager(t)

	ca, err := m.EnsureCA()
	if err != nil {
		t.Fatalf("EnsureCA on empty dir: %v", err)
	}
	if ca == nil {
		t.Fatal("EnsureCA returned nil")
	}
	if !m.Exists() {
		t.Error("files not created on disk after EnsureCA")
	}
}

func TestEnsureCA_existingReused(t *testing.T) {
	m := newTestManager(t)

	first, err := m.EnsureCA()
	if err != nil {
		t.Fatalf("first EnsureCA: %v", err)
	}

	second, err := m.EnsureCA()
	if err != nil {
		t.Fatalf("second EnsureCA: %v", err)
	}

	// Both calls must return the same certificate (same serial).
	if first.Certificate.SerialNumber.Cmp(second.Certificate.SerialNumber) != 0 {
		t.Errorf("serial changed between calls: first=%s second=%s",
			first.Certificate.SerialNumber, second.Certificate.SerialNumber)
	}
}

// -------------------------------------------------------------------------
// Leaf certificate tests
// -------------------------------------------------------------------------

func TestGenerateLeafCert_attributes(t *testing.T) {
	m := newTestManager(t)
	ca, err := m.GenerateCA(false)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	hostname := "example.com"
	leaf, err := GenerateLeafCert(hostname, ca)
	if err != nil {
		t.Fatalf("GenerateLeafCert: %v", err)
	}

	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	// Key size: 2048.
	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("expected RSA public key")
	}
	if rsaKey.N.BitLen() != 2048 {
		t.Errorf("leaf key size = %d, want 2048", rsaKey.N.BitLen())
	}

	// Common name.
	if cert.Subject.CommonName != hostname {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, hostname)
	}

	// SAN must include hostname.
	found := false
	for _, san := range cert.DNSNames {
		if san == hostname {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("SAN DNSNames %v does not contain %q", cert.DNSNames, hostname)
	}

	// Validity: ~24 hours.
	wantDuration := 24 * time.Hour
	gotDuration := cert.NotAfter.Sub(cert.NotBefore)
	delta := gotDuration - wantDuration
	if delta < -5*time.Minute || delta > 5*time.Minute {
		t.Errorf("leaf validity = %v, want ~%v", gotDuration, wantDuration)
	}

	// ExtKeyUsage: ServerAuth.
	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth {
		t.Errorf("ExtKeyUsage %v does not contain ServerAuth", cert.ExtKeyUsage)
	}

	// KeyUsage: DigitalSignature.
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Errorf("KeyUsage missing DigitalSignature: %v", cert.KeyUsage)
	}
}

func TestGenerateLeafCert_caChain(t *testing.T) {
	m := newTestManager(t)
	ca, err := m.GenerateCA(false)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	hostname := "registry.terraform.io"
	leaf, err := GenerateLeafCert(hostname, ca)
	if err != nil {
		t.Fatalf("GenerateLeafCert: %v", err)
	}

	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	// Build a root pool containing only our CA.
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)

	opts := x509.VerifyOptions{
		DNSName: hostname,
		Roots:   roots,
	}
	if _, err := leafCert.Verify(opts); err != nil {
		t.Errorf("leaf verification against CA pool failed: %v", err)
	}
}

// -------------------------------------------------------------------------
// Cache tests
// -------------------------------------------------------------------------

func TestCache_sameHostCached(t *testing.T) {
	m := newTestManager(t)
	ca, err := m.GenerateCA(false)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	cache := NewCache()
	hostname := "example.com"

	first, err := cache.GetOrCreate(hostname, ca)
	if err != nil {
		t.Fatalf("first GetOrCreate: %v", err)
	}

	second, err := cache.GetOrCreate(hostname, ca)
	if err != nil {
		t.Fatalf("second GetOrCreate: %v", err)
	}

	// Must be the exact same pointer.
	if first != second {
		t.Error("expected same *tls.Certificate pointer for same hostname")
	}
}

func TestCache_differentHosts(t *testing.T) {
	m := newTestManager(t)
	ca, err := m.GenerateCA(false)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	cache := NewCache()

	certA, err := cache.GetOrCreate("a.example.com", ca)
	if err != nil {
		t.Fatalf("GetOrCreate a: %v", err)
	}

	certB, err := cache.GetOrCreate("b.example.com", ca)
	if err != nil {
		t.Fatalf("GetOrCreate b: %v", err)
	}

	if certA == certB {
		t.Error("different hostnames returned the same *tls.Certificate pointer")
	}

	// Verify each cert has the correct SAN.
	for _, tc := range []struct {
		cert     *tls.Certificate
		hostname string
	}{
		{certA, "a.example.com"},
		{certB, "b.example.com"},
	} {
		parsed, err := x509.ParseCertificate(tc.cert.Certificate[0])
		if err != nil {
			t.Fatalf("parse cert for %s: %v", tc.hostname, err)
		}
		found := false
		for _, san := range parsed.DNSNames {
			if san == tc.hostname {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("cert for %s has DNSNames %v, expected to contain hostname", tc.hostname, parsed.DNSNames)
		}
	}
}

func TestCache_concurrent(t *testing.T) {
	m := newTestManager(t)
	ca, err := m.GenerateCA(false)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	cache := NewCache()
	hostname := "concurrent.example.com"

	const goroutines = 100
	results := make([]*tls.Certificate, goroutines)
	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			results[i], errs[i] = cache.GetOrCreate(hostname, ca)
		}()
	}

	wg.Wait()

	// All goroutines must succeed.
	for i, e := range errs {
		if e != nil {
			t.Errorf("goroutine %d error: %v", i, e)
		}
	}

	// All results must be the same pointer.
	expected := results[0]
	for i, r := range results {
		if r != expected {
			t.Errorf("goroutine %d got different pointer", i)
		}
	}
}
