package bench_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

// Case is a single benchmark case
type Case struct {
	Name      string
	Pretest   func(*testing.B) error
	SkipShort bool // Skip benchmark on short mode
	Test      func(*testing.B) error
}

func (c *Case) Run(b *testing.B) {
	b.Helper()
	b.Run(c.Name, func(b *testing.B) {
		if testing.Short() && c.SkipShort {
			b.SkipNow()
		}

		b.Helper()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if pretest := c.Pretest; pretest != nil {
				b.StopTimer()
				if err := pretest(b); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
			}
			if err := c.Test(b); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func generateRsaJwk() (jwk.Key, error) {
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return jwk.Import[jwk.Key](raw)
}

func generateEcdsaJwk() (jwk.Key, error) {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return jwk.Import[jwk.Key](raw)
}

func generateSymmetricJwk() (jwk.Key, error) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return jwk.Import[jwk.Key](key)
}

func generateEd25519Jwk() (jwk.Key, error) {
	_, raw, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return jwk.Import[jwk.Key](raw)
}

// mldsaCase is one ML-DSA parameter set with a freshly generated key pair.
// The public key is carried separately so verification benchmarks can hand
// jws/jwt exactly what a verifier would hold.
type mldsaCase struct {
	Name    string
	Alg     jwa.SignatureAlgorithm
	Private *mldsa.PrivateKey
	Public  *mldsa.PublicKey
}

// mldsaCases returns the three FIPS 204 parameter sets. ML-DSA is native to
// jwx from Go 1.27 on, so no companion module is involved here.
func mldsaCases(b *testing.B) []mldsaCase {
	b.Helper()

	entries := []struct {
		name   string
		alg    jwa.SignatureAlgorithm
		params mldsa.Parameters
	}{
		{"ML-DSA-44", jwa.MLDSA44(), mldsa.MLDSA44()},
		{"ML-DSA-65", jwa.MLDSA65(), mldsa.MLDSA65()},
		{"ML-DSA-87", jwa.MLDSA87(), mldsa.MLDSA87()},
	}

	cases := make([]mldsaCase, 0, len(entries))
	for _, entry := range entries {
		priv, err := mldsa.GenerateKey(entry.params)
		if err != nil {
			b.Fatal(err)
		}
		cases = append(cases, mldsaCase{
			Name:    entry.name,
			Alg:     entry.alg,
			Private: priv,
			Public:  priv.PublicKey(),
		})
	}
	return cases
}
