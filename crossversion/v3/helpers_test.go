package bench_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
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
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			if pretest := c.Pretest; pretest != nil {
				if err := pretest(b); err != nil {
					b.Fatal(err)
				}
			}
			b.StartTimer()
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
	return jwk.Import(raw)
}

func generateEcdsaJwk() (jwk.Key, error) {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return jwk.Import(raw)
}

func generateSymmetricJwk() (jwk.Key, error) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return jwk.Import(key)
}
