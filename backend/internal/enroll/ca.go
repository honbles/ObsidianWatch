// Package enroll issues agent identity certificates (spec A1, A4).
package enroll

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"obsidianwatch/backend/pkg/agentid"
)

// CA signs agent client certificates. Its key never leaves the ingest backend.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     crypto.Signer
}

// LoadOrCreateCA reads the agent CA from certFile/keyFile, creating a new
// ECDSA P-256 CA (10 years) when neither file exists. The key is written 0600.
func LoadOrCreateCA(certFile, keyFile string) (*CA, bool, error) {
	_, cErr := os.Stat(certFile)
	_, kErr := os.Stat(keyFile)
	switch {
	case cErr == nil && kErr == nil:
		ca, err := LoadCA(certFile, keyFile)
		return ca, false, err
	case os.IsNotExist(cErr) && os.IsNotExist(kErr):
		ca, certPEM, keyPEM, err := NewCA("ObsidianWatch Agent CA", 10*365*24*time.Hour)
		if err != nil {
			return nil, false, err
		}
		if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
			return nil, false, err
		}
		if err := os.MkdirAll(filepath.Dir(certFile), 0o755); err != nil {
			return nil, false, err
		}
		if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
			return nil, false, err
		}
		if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
			return nil, false, err
		}
		return ca, true, nil
	default:
		return nil, false, fmt.Errorf("enroll: agent CA is half present (%s / %s); restore both files or remove both", certFile, keyFile)
	}
}

// LoadCA reads an existing CA certificate and private key.
func LoadCA(certFile, keyFile string) (*CA, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, errors.New("enroll: CA certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("enroll: CA key is not PEM")
	}
	var key any
	if key, err = x509.ParsePKCS8PrivateKey(kb.Bytes); err != nil {
		if key, err = x509.ParseECPrivateKey(kb.Bytes); err != nil {
			return nil, errors.New("enroll: CA key: unsupported format")
		}
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("enroll: CA key cannot sign")
	}
	if !cert.IsCA {
		return nil, errors.New("enroll: CA certificate is not a CA")
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: signer}, nil
}

// NewCA creates a self-signed CA in memory.
func NewCA(name string, ttl time.Duration) (*CA, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               pkix.Name{CommonName: name, Organization: []string{"ObsidianWatch"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
	return &CA{Cert: cert, CertPEM: certPEM, key: key}, certPEM, keyPEM, nil
}

// Pool returns a cert pool holding only this CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// ParseCSR decodes and checks a PEM certificate request: valid self-signature
// and an acceptable key (ECDSA P-256 or P-384, or RSA of at least 2048 bits;
// Ed25519 is left out because not every agent TLS stack offers it). Whatever names the CSR asks for
// are ignored; the CA decides the identity.
func ParseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("csr: not a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("csr: signature does not match its key")
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, errors.New("csr: ECDSA key must be P-256 or P-384")
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, errors.New("csr: RSA key must be at least 2048 bits")
		}
	default:
		return nil, errors.New("csr: unsupported key type")
	}
	return csr, nil
}

// Issue signs a client certificate for agentID over the CSR's public key.
func (ca *CA) Issue(csr *x509.CertificateRequest, agentID string, ttl time.Duration, now time.Time) (*x509.Certificate, []byte, error) {
	if !agentid.Valid(agentID) {
		return nil, nil, errors.New("enroll: invalid agent id")
	}
	notAfter := now.Add(ttl)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: agentID, Organization: []string{"ObsidianWatch Agent"}},
		URIs:         []*url.URL{agentid.URI(agentID)},
		NotBefore:    now.Add(-5 * time.Minute), // tolerate small clock skew on the host
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func randSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n.Add(n, big.NewInt(1))
}
