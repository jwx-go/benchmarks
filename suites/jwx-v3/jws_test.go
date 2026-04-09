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

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func BenchmarkJWS_Sign(b *testing.B) {
	payload := []byte(`{"iss":"bench","sub":"1234567890","iat":1516239022}`)

	hmacKey := make([]byte, 32)
	rand.Read(hmacKey)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("HS256", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), hmacKey))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RS256", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), rsaKey))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ES256", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), ecKey))
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkJWS_Verify(b *testing.B) {
	payload := []byte(`{"iss":"bench","sub":"1234567890","iat":1516239022}`)

	hmacKey := make([]byte, 32)
	rand.Read(hmacKey)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	hmacSigned, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), hmacKey))
	if err != nil {
		b.Fatal(err)
	}
	rsaSigned, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), rsaKey))
	if err != nil {
		b.Fatal(err)
	}
	ecSigned, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), ecKey))
	if err != nil {
		b.Fatal(err)
	}

	b.Run("HS256", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := jws.Verify(hmacSigned, jws.WithKey(jwa.HS256(), hmacKey))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RS256", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := jws.Verify(rsaSigned, jws.WithKey(jwa.RS256(), &rsaKey.PublicKey))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ES256", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := jws.Verify(ecSigned, jws.WithKey(jwa.ES256(), &ecKey.PublicKey))
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkJWS_Sign_All(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping extended algorithm matrix in short mode")
	}

	payload := []byte(`{"iss":"bench","sub":"1234567890","iat":1516239022}`)

	hmacKey := make([]byte, 64)
	rand.Read(hmacKey)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}

	ec384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	ec521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	testcases := []struct {
		name string
		alg  jwa.SignatureAlgorithm
		key  interface{}
	}{
		{"HS384", jwa.HS384(), hmacKey[:48]},
		{"HS512", jwa.HS512(), hmacKey},
		{"RS384", jwa.RS384(), rsaKey},
		{"RS512", jwa.RS512(), rsaKey},
		{"PS256", jwa.PS256(), rsaKey},
		{"PS384", jwa.PS384(), rsaKey},
		{"PS512", jwa.PS512(), rsaKey},
		{"ES384", jwa.ES384(), ec384Key},
		{"ES512", jwa.ES512(), ec521Key},
		{"Ed25519", jwa.EdDSA(), edKey},
	}

	for _, tc := range testcases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := jws.Sign(payload, jws.WithKey(tc.alg, tc.key))
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJWS_Verify_All(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping extended algorithm matrix in short mode")
	}

	payload := []byte(`{"iss":"bench","sub":"1234567890","iat":1516239022}`)

	hmacKey := make([]byte, 64)
	rand.Read(hmacKey)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}

	ec384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	ec521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	testcases := []struct {
		name      string
		alg       jwa.SignatureAlgorithm
		signKey   interface{}
		verifyKey interface{}
	}{
		{"HS384", jwa.HS384(), hmacKey[:48], hmacKey[:48]},
		{"HS512", jwa.HS512(), hmacKey, hmacKey},
		{"RS384", jwa.RS384(), rsaKey, &rsaKey.PublicKey},
		{"RS512", jwa.RS512(), rsaKey, &rsaKey.PublicKey},
		{"PS256", jwa.PS256(), rsaKey, &rsaKey.PublicKey},
		{"PS384", jwa.PS384(), rsaKey, &rsaKey.PublicKey},
		{"PS512", jwa.PS512(), rsaKey, &rsaKey.PublicKey},
		{"ES384", jwa.ES384(), ec384Key, &ec384Key.PublicKey},
		{"ES512", jwa.ES512(), ec521Key, &ec521Key.PublicKey},
		{"Ed25519", jwa.EdDSA(), edPriv, edPub},
	}

	for _, tc := range testcases {
		signed, err := jws.Sign(payload, jws.WithKey(tc.alg, tc.signKey))
		if err != nil {
			b.Fatal(err)
		}

		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := jws.Verify(signed, jws.WithKey(tc.alg, tc.verifyKey))
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJWS_Serialization(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping serialization benchmarks in short mode")
	}

	const compactStr = `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
	compactBuf := []byte(compactStr)
	compactRdr := bytes.NewReader(compactBuf)

	const jsonStr = `{
    "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
    "signatures":[
      {
        "header": {"kid":"2010-12-29"},
        "protected":"eyJhbGciOiJSUzI1NiJ9",
        "signature": "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
      },
      {
        "header": {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
        "protected":"eyJhbGciOiJFUzI1NiJ9",
        "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
      }
    ]
  }`
	jsonBuf := []byte(jsonStr)
	jsonRdr := bytes.NewReader(jsonBuf)

	b.Run("Compact", func(b *testing.B) {
		testcases := []Case{
			{
				Name:      "jws.Parse",
				SkipShort: true,
				Test: func(b *testing.B) error {
					_, err := jws.Parse(compactBuf)
					return err
				},
			},
			{
				Name:      "jws.ParseString",
				SkipShort: true,
				Test: func(b *testing.B) error {
					_, err := jws.ParseString(compactStr)
					return err
				},
			},
			{
				Name:      "jws.ParseReader",
				SkipShort: true,
				Pretest: func(b *testing.B) error {
					_, err := compactRdr.Seek(0, 0)
					return err
				},
				Test: func(b *testing.B) error {
					_, err := jws.ParseReader(compactRdr)
					return err
				},
			},
		}
		for _, tc := range testcases {
			tc.Run(b)
		}
	})
	b.Run("JSON", func(b *testing.B) {
		m, _ := jws.Parse([]byte(jsonStr))
		testcases := []Case{
			{
				Name:      "jws.Parse",
				SkipShort: true,
				Test: func(b *testing.B) error {
					_, err := jws.Parse(jsonBuf)
					return err
				},
			},
			{
				Name:      "jws.ParseString",
				SkipShort: true,
				Test: func(b *testing.B) error {
					_, err := jws.ParseString(jsonStr)
					return err
				},
			},
			{
				Name:      "jws.ParseReader",
				SkipShort: true,
				Pretest: func(b *testing.B) error {
					_, err := jsonRdr.Seek(0, 0)
					return err
				},
				Test: func(b *testing.B) error {
					_, err := jws.ParseReader(jsonRdr)
					return err
				},
			},
			{
				Name:      "json.Marshal",
				SkipShort: true,
				Test: func(b *testing.B) error {
					_, err := json.Marshal(m)
					return err
				},
			},
		}
		for _, tc := range testcases {
			tc.Run(b)
		}
	})
}
