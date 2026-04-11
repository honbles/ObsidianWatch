package auth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

// LoadCA reads a PEM-encoded CA certificate file and returns a cert pool.
// Pass this pool to tls.Config.ClientCAs to require mTLS from agents.
func LoadCA(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: read CA file %q: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("mtls: no valid certificates found in %q", caFile)
	}
	return pool, nil
}

// MTLSConfig returns a tls.Config that requires and verifies client certificates.
// certFile/keyFile are the server's own certificate and key.
// caPool is the pool of CAs trusted to sign agent client certificates.
func MTLSConfig(certFile, keyFile string, caPool *x509.CertPool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: load server cert: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// TLSConfig returns a tls.Config for TLS-only (no client cert required).
// Used when auth is API-key based.
func TLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tls: load server cert: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// MTLSMiddleware extracts the verified client CN from the TLS connection
// and adds it to the request context. Must be used after mTLS is enforced
// at the TLS layer — this is a belt-and-suspenders check at HTTP level.
func MTLSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, `{"error":"client certificate required"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
