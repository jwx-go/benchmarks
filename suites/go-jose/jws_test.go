package bench_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

var (
	jwsHMACKey  []byte
	jwsRSAKey   *rsa.PrivateKey
	jwsECDSAKey *ecdsa.PrivateKey
	jwsPayload  = []byte(`{"iss":"bench","sub":"1234567890","iat":1516239022}`)

	jwsCompactHS256 string
	jwsCompactRS256 string
	jwsCompactES256 string
)

func init() {
	jwsHMACKey = make([]byte, 32)
	if _, err := rand.Read(jwsHMACKey); err != nil {
		panic(err)
	}

	var err error
	jwsRSAKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	jwsECDSAKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Pre-sign for verify benchmarks
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: jwsHMACKey}, nil)
	if err != nil {
		panic(err)
	}
	obj, err := signer.Sign(jwsPayload)
	if err != nil {
		panic(err)
	}
	jwsCompactHS256, err = obj.CompactSerialize()
	if err != nil {
		panic(err)
	}

	signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwsRSAKey}, nil)
	if err != nil {
		panic(err)
	}
	obj, err = signer.Sign(jwsPayload)
	if err != nil {
		panic(err)
	}
	jwsCompactRS256, err = obj.CompactSerialize()
	if err != nil {
		panic(err)
	}

	signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwsECDSAKey}, nil)
	if err != nil {
		panic(err)
	}
	obj, err = signer.Sign(jwsPayload)
	if err != nil {
		panic(err)
	}
	jwsCompactES256, err = obj.CompactSerialize()
	if err != nil {
		panic(err)
	}
}

func BenchmarkJWS_Sign(b *testing.B) {
	b.Run("HS256", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: jwsHMACKey}, nil)
			if err != nil {
				b.Fatal(err)
			}
			_, err = signer.Sign(jwsPayload)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RS256", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwsRSAKey}, nil)
			if err != nil {
				b.Fatal(err)
			}
			_, err = signer.Sign(jwsPayload)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ES256", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwsECDSAKey}, nil)
			if err != nil {
				b.Fatal(err)
			}
			_, err = signer.Sign(jwsPayload)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkJWS_Verify(b *testing.B) {
	b.Run("HS256", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			jws, err := jose.ParseSigned(jwsCompactHS256, []jose.SignatureAlgorithm{jose.HS256})
			if err != nil {
				b.Fatal(err)
			}
			_, err = jws.Verify(jwsHMACKey)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RS256", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			jws, err := jose.ParseSigned(jwsCompactRS256, []jose.SignatureAlgorithm{jose.RS256})
			if err != nil {
				b.Fatal(err)
			}
			_, err = jws.Verify(&jwsRSAKey.PublicKey)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ES256", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			jws, err := jose.ParseSigned(jwsCompactES256, []jose.SignatureAlgorithm{jose.ES256})
			if err != nil {
				b.Fatal(err)
			}
			_, err = jws.Verify(&jwsECDSAKey.PublicKey)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
