package bundler

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestMLDSABundle(t *testing.T) {
	tests := []struct {
		name    string
		params  mldsa.Parameters
		sigAlgo x509.SignatureAlgorithm
		keyType string
	}{
		{name: "MLDSA44", params: mldsa.MLDSA44(), sigAlgo: x509.MLDSA44, keyType: "ML-DSA-44"},
		{name: "MLDSA65", params: mldsa.MLDSA65(), sigAlgo: x509.MLDSA65, keyType: "ML-DSA-65"},
		{name: "MLDSA87", params: mldsa.MLDSA87(), sigAlgo: x509.MLDSA87, keyType: "ML-DSA-87"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, cert := newMLDSASelfSignedCertificate(t, tt.params, tt.sigAlgo)
			bundler := new(Bundler)

			bundle, err := bundler.Bundle([]*x509.Certificate{cert}, key, Force)
			if err != nil {
				t.Fatalf("bundling with private key: %v", err)
			}

			if _, err := bundler.Bundle([]*x509.Certificate{cert}, nil, Force); err != nil {
				t.Fatalf("bundling without private key: %v", err)
			}

			mismatchedKey, err := mldsa.GenerateKey(tt.params)
			if err != nil {
				t.Fatalf("generating mismatched key: %v", err)
			}
			if _, err := bundler.Bundle([]*x509.Certificate{cert}, mismatchedKey, Force); err == nil {
				t.Fatal("bundling accepted a mismatched ML-DSA key")
			}

			encoded, err := json.Marshal(bundle)
			if err != nil {
				t.Fatalf("marshaling bundle: %v", err)
			}
			var metadata struct {
				Key       string `json:"key"`
				KeyType   string `json:"key_type"`
				KeySize   int    `json:"key_size"`
				Signature string `json:"signature"`
			}
			if err := json.Unmarshal(encoded, &metadata); err != nil {
				t.Fatalf("unmarshaling bundle metadata: %v", err)
			}
			if metadata.KeyType != tt.keyType {
				t.Fatalf("key type = %q, want %q", metadata.KeyType, tt.keyType)
			}
			if metadata.KeySize != tt.params.PublicKeySize() {
				t.Fatalf("key size = %d, want %d", metadata.KeySize, tt.params.PublicKeySize())
			}
			if metadata.Signature != tt.name {
				t.Fatalf("signature = %q, want %q", metadata.Signature, tt.name)
			}

			block, _ := pem.Decode([]byte(metadata.Key))
			if block == nil {
				t.Fatal("bundle key is not PEM encoded")
			}
			if block.Type != "PRIVATE KEY" {
				t.Fatalf("PEM block type = %q, want PRIVATE KEY", block.Type)
			}

			var privateKeyInfo struct {
				Version    int
				Algorithm  pkix.AlgorithmIdentifier
				PrivateKey []byte
			}
			rest, err := asn1.Unmarshal(block.Bytes, &privateKeyInfo)
			if err != nil {
				t.Fatalf("parsing PKCS#8 structure: %v", err)
			}
			if len(rest) != 0 {
				t.Fatalf("parsing PKCS#8 structure left %d trailing bytes", len(rest))
			}
			wantSeed := append([]byte{0x80, byte(mldsa.PrivateKeySize)}, key.Bytes()...)
			if !bytes.Equal(privateKeyInfo.PrivateKey, wantSeed) {
				t.Fatal("PKCS#8 key is not the RFC 9881 seed-only representation")
			}

			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Fatalf("parsing PKCS#8 key: %v", err)
			}
			parsedKey, ok := parsed.(*mldsa.PrivateKey)
			if !ok {
				t.Fatalf("parsed key type = %T, want *mldsa.PrivateKey", parsed)
			}
			if !parsedKey.PublicKey().Equal(key.PublicKey()) {
				t.Fatal("public key changed after PKCS#8 round-trip")
			}
		})
	}
}

func newMLDSASelfSignedCertificate(t *testing.T, params mldsa.Parameters, sigAlgo x509.SignatureAlgorithm) (*mldsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := mldsa.GenerateKey(params)
	if err != nil {
		t.Fatalf("generating ML-DSA key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: params.String()},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    sigAlgo,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("creating ML-DSA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing ML-DSA certificate: %v", err)
	}
	return key, cert
}
