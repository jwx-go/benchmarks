package bench_test

import (
	"context"
	"crypto/mldsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	jwtpqc "github.com/salrashid123/golang-jwt-pqc"
	pqcmldsa "github.com/salrashid123/golang-jwt-pqc/mldsa"
)

// golang-jwt/v5 has no post-quantum signing methods of its own, so this suite
// measures salrashid123/golang-jwt-pqc, which registers ML-DSA-44/65/87 with
// golang-jwt and signs through crypto/mldsa. Benchmark names match the
// BenchmarkJWT_*_MLDSA functions in the jwx-v4 suite so benchstat can compare
// the two directly.

type mldsaCase struct {
	name    string
	method  jwt.SigningMethod
	signCtx context.Context
	pubkey  *mldsa.PublicKey
}

// mldsaCases returns the three FIPS 204 parameter sets. golang-jwt-pqc takes
// the private key through a context rather than through the key argument, so
// the signing context is built once per case and reused as the "key".
func mldsaCases(b *testing.B) []mldsaCase {
	b.Helper()

	entries := []struct {
		name   string
		method jwt.SigningMethod
		params mldsa.Parameters
	}{
		{"ML-DSA-44", jwtpqc.SigningMethodMLDSA44, mldsa.MLDSA44()},
		{"ML-DSA-65", jwtpqc.SigningMethodMLDSA65, mldsa.MLDSA65()},
		{"ML-DSA-87", jwtpqc.SigningMethodMLDSA87, mldsa.MLDSA87()},
	}

	cases := make([]mldsaCase, 0, len(entries))
	for _, entry := range entries {
		priv, err := mldsa.GenerateKey(entry.params)
		if err != nil {
			b.Fatal(err)
		}
		signer := &pqcmldsa.MLDSA{PrivateKey: priv}
		ctx, err := jwtpqc.NewSignerContext(context.Background(), &jwtpqc.SignerConfig{Signer: signer})
		if err != nil {
			b.Fatal(err)
		}
		cases = append(cases, mldsaCase{
			name:    entry.name,
			method:  entry.method,
			signCtx: ctx,
			pubkey:  priv.PublicKey(),
		})
	}
	return cases
}

func makeClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}
}

func BenchmarkJWT_Sign_MLDSA(b *testing.B) {
	claims := makeClaims()
	for _, mc := range mldsaCases(b) {
		token := jwt.NewWithClaims(mc.method, claims)
		signCtx := mc.signCtx
		b.Run(mc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := token.SignedString(signCtx)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJWT_Parse_MLDSA(b *testing.B) {
	claims := makeClaims()
	for _, mc := range mldsaCases(b) {
		signed, err := jwt.NewWithClaims(mc.method, claims).SignedString(mc.signCtx)
		if err != nil {
			b.Fatal(err)
		}
		pubkey := mc.pubkey
		b.Run(mc.name, func(b *testing.B) {
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

func BenchmarkJWT_Verify_MLDSA(b *testing.B) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	claims := makeClaims()
	for _, mc := range mldsaCases(b) {
		signed, err := jwt.NewWithClaims(mc.method, claims).SignedString(mc.signCtx)
		if err != nil {
			b.Fatal(err)
		}
		pubkey := mc.pubkey
		b.Run(mc.name, func(b *testing.B) {
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

func BenchmarkJWT_VerifyValidate_MLDSA(b *testing.B) {
	claims := makeClaims()
	for _, mc := range mldsaCases(b) {
		signed, err := jwt.NewWithClaims(mc.method, claims).SignedString(mc.signCtx)
		if err != nil {
			b.Fatal(err)
		}
		pubkey := mc.pubkey
		b.Run(mc.name, func(b *testing.B) {
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
