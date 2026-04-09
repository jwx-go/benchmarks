package bench_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

var (
	jwkRSAKey   *rsa.PrivateKey
	jwkECDSAKey *ecdsa.PrivateKey
	jwkSymKey   []byte

	jwkRSAPublicJSON    []byte
	jwkRSAPrivateJSON   []byte
	jwkECPublicJSON     []byte
	jwkECPrivateJSON    []byte
	jwkSymmetricJSON    []byte
)

func init() {
	var err error

	jwkRSAKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	jwkECDSAKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	jwkSymKey = make([]byte, 64)
	if _, err := rand.Read(jwkSymKey); err != nil {
		panic(err)
	}

	jwkRSAPublicJSON, err = json.Marshal(jose.JSONWebKey{Key: &jwkRSAKey.PublicKey})
	if err != nil {
		panic(err)
	}

	jwkRSAPrivateJSON, err = json.Marshal(jose.JSONWebKey{Key: jwkRSAKey})
	if err != nil {
		panic(err)
	}

	jwkECPublicJSON, err = json.Marshal(jose.JSONWebKey{Key: &jwkECDSAKey.PublicKey})
	if err != nil {
		panic(err)
	}

	jwkECPrivateJSON, err = json.Marshal(jose.JSONWebKey{Key: jwkECDSAKey})
	if err != nil {
		panic(err)
	}

	jwkSymmetricJSON, err = json.Marshal(jose.JSONWebKey{Key: jwkSymKey})
	if err != nil {
		panic(err)
	}
}

func BenchmarkJWK_Parse(b *testing.B) {
	b.Run("RSA_PublicKey", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var k jose.JSONWebKey
			if err := json.Unmarshal(jwkRSAPublicJSON, &k); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RSA_PrivateKey", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var k jose.JSONWebKey
			if err := json.Unmarshal(jwkRSAPrivateJSON, &k); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("EC_PublicKey", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var k jose.JSONWebKey
			if err := json.Unmarshal(jwkECPublicJSON, &k); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("EC_PrivateKey", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var k jose.JSONWebKey
			if err := json.Unmarshal(jwkECPrivateJSON, &k); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Symmetric", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var k jose.JSONWebKey
			if err := json.Unmarshal(jwkSymmetricJSON, &k); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkJWK_Marshal(b *testing.B) {
	b.Run("RSA_PublicKey", func(b *testing.B) {
		k := jose.JSONWebKey{Key: &jwkRSAKey.PublicKey}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := json.Marshal(k)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RSA_PrivateKey", func(b *testing.B) {
		k := jose.JSONWebKey{Key: jwkRSAKey}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := json.Marshal(k)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("EC_PublicKey", func(b *testing.B) {
		k := jose.JSONWebKey{Key: &jwkECDSAKey.PublicKey}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := json.Marshal(k)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("EC_PrivateKey", func(b *testing.B) {
		k := jose.JSONWebKey{Key: jwkECDSAKey}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := json.Marshal(k)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Symmetric", func(b *testing.B) {
		k := jose.JSONWebKey{Key: jwkSymKey}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := json.Marshal(k)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
