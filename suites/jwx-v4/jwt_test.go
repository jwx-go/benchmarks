package bench_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

type jwtAlgCase struct {
	name   string
	alg    jwa.SignatureAlgorithm
	key    jwk.Key // signing key
	pubkey jwk.Key // verification key
}

func jwtAlgCases(b *testing.B) []jwtAlgCase {
	b.Helper()

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
	rsaPub, err := jwk.PublicKeyOf(rsaKey)
	if err != nil {
		b.Fatal(err)
	}

	ecRaw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	ecKey, err := jwk.Import[jwk.Key](ecRaw)
	if err != nil {
		b.Fatal(err)
	}
	ecPub, err := jwk.PublicKeyOf(ecKey)
	if err != nil {
		b.Fatal(err)
	}

	_, edRaw, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	edKey, err := jwk.Import[jwk.Key](edRaw)
	if err != nil {
		b.Fatal(err)
	}
	edPub, err := jwk.PublicKeyOf(edKey)
	if err != nil {
		b.Fatal(err)
	}

	return []jwtAlgCase{
		{"HS256", jwa.HS256(), hmacKey, hmacKey},
		{"RS256", jwa.RS256(), rsaKey, rsaPub},
		{"ES256", jwa.ES256(), ecKey, ecPub},
		{"PS256", jwa.PS256(), rsaKey, rsaPub},
		{"EdDSA", jwa.EdDSA(), edKey, edPub},
	}
}

func makeJwtToken() jwt.Token {
	now := time.Now()
	tok := jwt.New()
	tok.Set(jwt.SubjectKey, "1234567890")
	tok.Set("name", "John Doe")
	tok.Set(jwt.IssuedAtKey, now.Unix())
	tok.Set(jwt.ExpirationKey, now.Add(time.Hour).Unix())
	return tok
}

func BenchmarkJWT_Sign(b *testing.B) {
	tok := makeJwtToken()
	for _, ac := range jwtAlgCases(b) {
		b.Run(ac.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := jwt.Sign(tok, jwt.WithKey(ac.alg, ac.key))
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJWT_Parse(b *testing.B) {
	tok := makeJwtToken()
	for _, ac := range jwtAlgCases(b) {
		signed, err := jwt.Sign(tok, jwt.WithKey(ac.alg, ac.key))
		if err != nil {
			b.Fatal(err)
		}
		b.Run(ac.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := jwt.Parse(signed, jwt.WithKey(ac.alg, ac.pubkey))
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJWT_Verify(b *testing.B) {
	tok := makeJwtToken()
	for _, ac := range jwtAlgCases(b) {
		signed, err := jwt.Sign(tok, jwt.WithKey(ac.alg, ac.key))
		if err != nil {
			b.Fatal(err)
		}
		b.Run(ac.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := jwt.Parse(signed, jwt.WithKey(ac.alg, ac.pubkey))
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
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
