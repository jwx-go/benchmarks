package bench_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	hmacKey    []byte
	rsaKey     *rsa.PrivateKey
	ecP256Key  *ecdsa.PrivateKey
	ecP384Key  *ecdsa.PrivateKey
	ecP521Key  *ecdsa.PrivateKey
	edKey      ed25519.PrivateKey
	edPubKey   ed25519.PublicKey
)

func init() {
	hmacKey = make([]byte, 64) // 64 bytes covers HS256/384/512
	if _, err := rand.Read(hmacKey); err != nil {
		panic(err)
	}

	var err error
	rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	ecP256Key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	ecP384Key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}

	ecP521Key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}

	edPubKey, edKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
}

type algCase struct {
	name      string
	method    jwt.SigningMethod
	key       any
	pubkey    any
	skipShort bool
}

func algCases() []algCase {
	return []algCase{
		{"HS256", jwt.SigningMethodHS256, hmacKey, hmacKey, false},
		{"HS384", jwt.SigningMethodHS384, hmacKey, hmacKey, true},
		{"HS512", jwt.SigningMethodHS512, hmacKey, hmacKey, true},
		{"RS256", jwt.SigningMethodRS256, rsaKey, &rsaKey.PublicKey, false},
		{"RS384", jwt.SigningMethodRS384, rsaKey, &rsaKey.PublicKey, true},
		{"RS512", jwt.SigningMethodRS512, rsaKey, &rsaKey.PublicKey, true},
		{"PS256", jwt.SigningMethodPS256, rsaKey, &rsaKey.PublicKey, false},
		{"PS384", jwt.SigningMethodPS384, rsaKey, &rsaKey.PublicKey, true},
		{"PS512", jwt.SigningMethodPS512, rsaKey, &rsaKey.PublicKey, true},
		{"ES256", jwt.SigningMethodES256, ecP256Key, &ecP256Key.PublicKey, false},
		{"ES384", jwt.SigningMethodES384, ecP384Key, &ecP384Key.PublicKey, true},
		{"ES512", jwt.SigningMethodES512, ecP521Key, &ecP521Key.PublicKey, true},
		{"EdDSA", jwt.SigningMethodEdDSA, edKey, edPubKey, false},
	}
}

func makeClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}
}

func BenchmarkJWT_Sign(b *testing.B) {
	claims := makeClaims()
	for _, ac := range algCases() {
		b.Run(ac.name, func(b *testing.B) {
			if ac.skipShort && testing.Short() {
				b.Skip("skipping extended algorithm in short mode")
			}
			token := jwt.NewWithClaims(ac.method, claims)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := token.SignedString(ac.key)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJWT_Parse(b *testing.B) {
	claims := makeClaims()
	for _, ac := range algCases() {
		token := jwt.NewWithClaims(ac.method, claims)
		signed, err := token.SignedString(ac.key)
		if err != nil {
			b.Fatal(err)
		}
		pubkey := ac.pubkey
		b.Run(ac.name, func(b *testing.B) {
			if ac.skipShort && testing.Short() {
				b.Skip("skipping extended algorithm in short mode")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				t, err := jwt.Parse(signed, func(_ *jwt.Token) (any, error) {
					return pubkey, nil
				})
				if err != nil {
					b.Fatal(err)
				}
				if !t.Valid {
					b.Fatal("token is not valid")
				}
			}
		})
	}
}

func BenchmarkJWT_Verify(b *testing.B) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	claims := makeClaims()
	for _, ac := range algCases() {
		token := jwt.NewWithClaims(ac.method, claims)
		signed, err := token.SignedString(ac.key)
		if err != nil {
			b.Fatal(err)
		}
		pubkey := ac.pubkey
		b.Run(ac.name, func(b *testing.B) {
			if ac.skipShort && testing.Short() {
				b.Skip("skipping extended algorithm in short mode")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := parser.Parse(signed, func(_ *jwt.Token) (any, error) {
					return pubkey, nil
				})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJWT_VerifyValidate(b *testing.B) {
	claims := makeClaims()
	for _, ac := range algCases() {
		token := jwt.NewWithClaims(ac.method, claims)
		signed, err := token.SignedString(ac.key)
		if err != nil {
			b.Fatal(err)
		}
		pubkey := ac.pubkey
		b.Run(ac.name, func(b *testing.B) {
			if ac.skipShort && testing.Short() {
				b.Skip("skipping extended algorithm in short mode")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				t, err := jwt.Parse(signed, func(_ *jwt.Token) (any, error) {
					return pubkey, nil
				})
				if err != nil {
					b.Fatal(err)
				}
				if !t.Valid {
					b.Fatal("token is not valid")
				}
			}
		})
	}
}
