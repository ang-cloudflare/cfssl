package selfsign

import (
	"crypto/mldsa"
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
)

// TestSignMLDSADefaultProfileKeyUsage verifies that a self-signed ML-DSA
// certificate issued under the default profile does not carry
// keyEncipherment, which RFC 9881 prohibits for ML-DSA subject keys.
func TestSignMLDSADefaultProfileKeyUsage(t *testing.T) {
	tests := []struct {
		name   string
		params mldsa.Parameters
	}{
		{"MLDSA44", mldsa.MLDSA44()},
		{"MLDSA65", mldsa.MLDSA65()},
		{"MLDSA87", mldsa.MLDSA87()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, err := mldsa.GenerateKey(tt.params)
			if err != nil {
				t.Fatalf("generating ML-DSA key: %v", err)
			}
			csrPEM, err := csr.Generate(priv, &csr.CertificateRequest{
				CN:    "mldsa.example.com",
				Hosts: []string{"mldsa.example.com"},
			})
			if err != nil {
				t.Fatalf("generating CSR: %v", err)
			}

			certPEM, err := Sign(priv, csrPEM, config.DefaultConfig())
			if err != nil {
				t.Fatalf("Sign() failed: %v", err)
			}
			cert, err := helpers.ParseCertificatePEM(certPEM)
			if err != nil {
				t.Fatalf("parsing certificate: %v", err)
			}

			if cert.KeyUsage != x509.KeyUsageDigitalSignature {
				t.Errorf("KeyUsage = %#b, want %#b (digitalSignature only)", cert.KeyUsage, x509.KeyUsageDigitalSignature)
			}
			wantEKU := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
			if !reflect.DeepEqual(cert.ExtKeyUsage, wantEKU) {
				t.Errorf("ExtKeyUsage = %v, want %v", cert.ExtKeyUsage, wantEKU)
			}
		})
	}
}
