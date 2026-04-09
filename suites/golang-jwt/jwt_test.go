package bench_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	hmacKey    []byte
	rsaKey     *rsa.PrivateKey
	hsToken    string
	rsToken    string
)

func init() {
	hmacKey = make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		panic(err)
	}

	var err error
	rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	claims := jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	hsToken, err = token.SignedString(hmacKey)
	if err != nil {
		panic(err)
	}

	tokenRS := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	rsToken, err = tokenRS.SignedString(rsaKey)
	if err != nil {
		panic(err)
	}
}

func BenchmarkJWT_Sign(b *testing.B) {
	claims := jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}

	b.Run("HS256", func(b *testing.B) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := token.SignedString(hmacKey)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RS256", func(b *testing.B) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := token.SignedString(rsaKey)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkJWT_Parse(b *testing.B) {
	b.Run("HS256", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			token, err := jwt.Parse(hsToken, func(_ *jwt.Token) (any, error) {
				return hmacKey, nil
			})
			if err != nil {
				b.Fatal(err)
			}
			if !token.Valid {
				b.Fatal("token is not valid")
			}
		}
	})

	b.Run("RS256", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			token, err := jwt.Parse(rsToken, func(_ *jwt.Token) (any, error) {
				return &rsaKey.PublicKey, nil
			})
			if err != nil {
				b.Fatal(err)
			}
			if !token.Valid {
				b.Fatal("token is not valid")
			}
		}
	})
}

func BenchmarkJWT_RoundTrip(b *testing.B) {
	claims := jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}

	b.Run("HS256", func(b *testing.B) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tokenString, err := token.SignedString(hmacKey)
			if err != nil {
				b.Fatal(err)
			}

			parsedToken, err := jwt.Parse(tokenString, func(_ *jwt.Token) (any, error) {
				return hmacKey, nil
			})
			if err != nil {
				b.Fatal(err)
			}
			if !parsedToken.Valid {
				b.Fatal("token is not valid")
			}
		}
	})
}
