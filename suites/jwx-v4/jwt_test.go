package bench_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

func BenchmarkJWT_Sign(b *testing.B) {
	hmacRaw := make([]byte, 32)
	rand.Read(hmacRaw)
	hmacKey, err := jwk.Import[jwk.Key](hmacRaw)
	if err != nil {
		b.Fatal(err)
	}

	rsaRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	rsaKey, err := jwk.Import[jwk.Key](rsaRaw)
	if err != nil {
		b.Fatal(err)
	}

	now := time.Now()
	tok := jwt.New()
	tok.Set(jwt.SubjectKey, "1234567890")
	tok.Set("name", "John Doe")
	tok.Set(jwt.IssuedAtKey, now.Unix())
	tok.Set(jwt.ExpirationKey, now.Add(time.Hour).Unix())

	b.Run("HS256", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), hmacKey))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RS256", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), rsaKey))
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkJWT_Parse(b *testing.B) {
	hmacRaw := make([]byte, 32)
	rand.Read(hmacRaw)
	hmacKey, err := jwk.Import[jwk.Key](hmacRaw)
	if err != nil {
		b.Fatal(err)
	}

	rsaRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	rsaKey, err := jwk.Import[jwk.Key](rsaRaw)
	if err != nil {
		b.Fatal(err)
	}
	rsaPubKey, err := jwk.PublicKeyOf(rsaKey)
	if err != nil {
		b.Fatal(err)
	}

	now := time.Now()
	tok := jwt.New()
	tok.Set(jwt.SubjectKey, "1234567890")
	tok.Set("name", "John Doe")
	tok.Set(jwt.IssuedAtKey, now.Unix())
	tok.Set(jwt.ExpirationKey, now.Add(time.Hour).Unix())

	hmacSigned, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), hmacKey))
	if err != nil {
		b.Fatal(err)
	}

	rsaSigned, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), rsaKey))
	if err != nil {
		b.Fatal(err)
	}

	b.Run("HS256", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := jwt.Parse(hmacSigned, jwt.WithKey(jwa.HS256(), hmacKey))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RS256", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := jwt.Parse(rsaSigned, jwt.WithKey(jwa.RS256(), rsaPubKey))
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkJWT_RoundTrip(b *testing.B) {
	hmacRaw := make([]byte, 32)
	rand.Read(hmacRaw)
	hmacKey, err := jwk.Import[jwk.Key](hmacRaw)
	if err != nil {
		b.Fatal(err)
	}

	now := time.Now()
	tok := jwt.New()
	tok.Set(jwt.SubjectKey, "1234567890")
	tok.Set("name", "John Doe")
	tok.Set(jwt.IssuedAtKey, now.Unix())
	tok.Set(jwt.ExpirationKey, now.Add(time.Hour).Unix())

	b.Run("HS256", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), hmacKey))
			if err != nil {
				b.Fatal(err)
			}
			_, err = jwt.Parse(signed, jwt.WithKey(jwa.HS256(), hmacKey))
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkJWT_Serialization(b *testing.B) {
	alg := jwa.RS256()

	key, err := generateRsaJwk()
	if err != nil {
		b.Fatal(err)
	}
	pubkey, err := jwk.PublicKeyOf(key)
	if err != nil {
		b.Fatal(err)
	}

	t1 := jwt.New()
	t1.Set(jwt.IssuedAtKey, time.Now().Unix())
	t1.Set(jwt.ExpirationKey, time.Now().Add(time.Hour).Unix())

	b.Run("Compact", func(b *testing.B) {
		testcases := []Case{
			{
				Name:      "jwt.Sign",
				SkipShort: true,
				Test: func(b *testing.B) error {
					_, err := jwt.Sign(t1, jwt.WithKey(alg, key))
					return err
				},
			},
		}
		for _, tc := range testcases {
			tc.Run(b)
		}
	})
	b.Run("JSON", func(b *testing.B) {
		testcases := []Case{
			{
				Name:      "json.Marshal",
				SkipShort: true,
				Test: func(b *testing.B) error {
					_, err := json.Marshal(t1)
					return err
				},
			},
		}
		for _, tc := range testcases {
			tc.Run(b)
		}
	})

	signedBuf, err := jwt.Sign(t1, jwt.WithKey(alg, key))
	if err != nil {
		b.Fatal(err)
	}

	signedString := string(signedBuf)
	signedReader := bytes.NewReader(signedBuf)
	jsonBuf, _ := json.Marshal(t1)
	jsonString := string(jsonBuf)
	jsonReader := bytes.NewReader(jsonBuf)

	b.Run("Compact (With Verify)", func(b *testing.B) {
		testcases := []Case{
			{
				Name:      "jwt.ParseString",
				SkipShort: true,
				Test: func(b *testing.B) error {
					_, err := jwt.ParseString(signedString, jwt.WithKey(alg, pubkey))
					return err
				},
			},
			{
				Name:      "jwt.Parse",
				SkipShort: true,
				Test: func(b *testing.B) error {
					_, err := jwt.Parse(signedBuf, jwt.WithKey(alg, pubkey))
					return err
				},
			},
			{
				Name:      "jwt.ParseReader",
				SkipShort: true,
				Pretest: func(b *testing.B) error {
					_, err := signedReader.Seek(0, 0)
					return err
				},
				Test: func(b *testing.B) error {
					_, err := jwt.ParseReader(signedReader, jwt.WithKey(alg, pubkey))
					return err
				},
			},
		}
		for _, tc := range testcases {
			tc.Run(b)
		}
	})
	b.Run("Compact (No Verify)", func(b *testing.B) {
		testcases := []Case{
			{
				Name:      "jwt.ParseString",
				SkipShort: true,
				Test: func(b *testing.B) error {
					_, err := jwt.ParseString(signedString, jwt.WithVerify(false), jwt.WithValidate(false))
					return err
				},
			},
			{
				Name:      "jwt.Parse",
				SkipShort: true,
				Test: func(b *testing.B) error {
					_, err := jwt.Parse(signedBuf, jwt.WithVerify(false), jwt.WithValidate(false))
					return err
				},
			},
			{
				Name:      "jwt.ParseReader",
				SkipShort: true,
				Pretest: func(b *testing.B) error {
					_, err := signedReader.Seek(0, 0)
					return err
				},
				Test: func(b *testing.B) error {
					_, err := jwt.ParseReader(signedReader, jwt.WithVerify(false), jwt.WithValidate(false))
					return err
				},
			},
		}
		for _, tc := range testcases {
			tc.Run(b)
		}
	})
	b.Run("JSON", func(b *testing.B) {
		testcases := []Case{
			{
				Name:      "jwt.ParseString",
				SkipShort: true,
				Test: func(b *testing.B) error {
					_, err := jwt.ParseString(jsonString, jwt.WithVerify(false), jwt.WithValidate(false))
					return err
				},
			},
			{
				Name:      "jwt.Parse",
				SkipShort: true,
				Test: func(b *testing.B) error {
					_, err := jwt.Parse(jsonBuf, jwt.WithVerify(false), jwt.WithValidate(false))
					return err
				},
			},
			{
				Name:      "jwt.ParseReader",
				SkipShort: true,
				Pretest: func(b *testing.B) error {
					_, err := jsonReader.Seek(0, 0)
					return err
				},
				Test: func(b *testing.B) error {
					_, err := jwt.ParseReader(jsonReader, jwt.WithVerify(false), jwt.WithValidate(false))
					return err
				},
			},
			{
				Name:      "json.Unmarshal",
				SkipShort: true,
				Test: func(b *testing.B) error {
					tok := jwt.New()
					return json.Unmarshal(jsonBuf, tok)
				},
			},
		}
		for _, tc := range testcases {
			tc.Run(b)
		}
	})
}
