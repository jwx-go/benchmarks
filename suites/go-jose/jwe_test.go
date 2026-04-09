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
	jweRSAKey   *rsa.PrivateKey
	jweECDSAKey *ecdsa.PrivateKey
	jweAESKey32 []byte // 32-byte key for A256KW and DIRECT
	jweAESKey16 []byte // 16-byte key for A128GCMKW
	jwePayload  = []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")

	jweCompactRSAOAEP       string
	jweCompactRSA15         string
	jweCompactA256KW        string
	jweCompactA128GCMKW     string
	jweCompactECDHES        string
	jweCompactECDHESA256KW  string
	jweCompactDIRECT        string
)

func init() {
	var err error

	jweRSAKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	jweECDSAKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	jweAESKey32 = make([]byte, 32)
	if _, err := rand.Read(jweAESKey32); err != nil {
		panic(err)
	}

	jweAESKey16 = make([]byte, 16)
	if _, err := rand.Read(jweAESKey16); err != nil {
		panic(err)
	}

	// Pre-encrypt for decrypt benchmarks
	jweCompactRSAOAEP = mustEncrypt(jose.RSA_OAEP, jose.A256GCM, &jweRSAKey.PublicKey)
	jweCompactRSA15 = mustEncrypt(jose.RSA1_5, jose.A128CBC_HS256, &jweRSAKey.PublicKey)
	jweCompactA256KW = mustEncrypt(jose.A256KW, jose.A256GCM, jweAESKey32)
	jweCompactA128GCMKW = mustEncrypt(jose.A128GCMKW, jose.A128GCM, jweAESKey16)
	jweCompactECDHES = mustEncrypt(jose.ECDH_ES, jose.A256GCM, &jweECDSAKey.PublicKey)
	jweCompactECDHESA256KW = mustEncrypt(jose.ECDH_ES_A256KW, jose.A256GCM, &jweECDSAKey.PublicKey)
	jweCompactDIRECT = mustEncrypt(jose.DIRECT, jose.A256GCM, jweAESKey32)
}

func mustEncrypt(keyAlg jose.KeyAlgorithm, contentEnc jose.ContentEncryption, key any) string {
	enc, err := jose.NewEncrypter(contentEnc, jose.Recipient{Algorithm: keyAlg, Key: key}, nil)
	if err != nil {
		panic(err)
	}
	obj, err := enc.Encrypt(jwePayload)
	if err != nil {
		panic(err)
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return compact
}

func BenchmarkJWE_Encrypt(b *testing.B) {
	type encryptCase struct {
		name       string
		contentEnc jose.ContentEncryption
		keyAlg     jose.KeyAlgorithm
		key        any
	}
	testcases := []encryptCase{
		{"RSA-OAEP/A256GCM", jose.A256GCM, jose.RSA_OAEP, &jweRSAKey.PublicKey},
		{"RSA1_5/A128CBC-HS256", jose.A128CBC_HS256, jose.RSA1_5, &jweRSAKey.PublicKey},
		{"A256KW/A256GCM", jose.A256GCM, jose.A256KW, jweAESKey32},
		{"A128GCMKW/A128GCM", jose.A128GCM, jose.A128GCMKW, jweAESKey16},
		{"ECDH-ES/A256GCM", jose.A256GCM, jose.ECDH_ES, &jweECDSAKey.PublicKey},
		{"ECDH-ES+A256KW/A256GCM", jose.A256GCM, jose.ECDH_ES_A256KW, &jweECDSAKey.PublicKey},
		{"DIRECT/A256GCM", jose.A256GCM, jose.DIRECT, jweAESKey32},
	}

	for _, tc := range testcases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				enc, err := jose.NewEncrypter(tc.contentEnc, jose.Recipient{Algorithm: tc.keyAlg, Key: tc.key}, nil)
				if err != nil {
					b.Fatal(err)
				}
				_, err = enc.Encrypt(jwePayload)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJWE_Decrypt(b *testing.B) {
	b.Run("RSA-OAEP/A256GCM", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			obj, err := jose.ParseEncrypted(jweCompactRSAOAEP, []jose.KeyAlgorithm{jose.RSA_OAEP}, []jose.ContentEncryption{jose.A256GCM})
			if err != nil {
				b.Fatal(err)
			}
			_, err = obj.Decrypt(jweRSAKey)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RSA1_5/A128CBC-HS256", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			obj, err := jose.ParseEncrypted(jweCompactRSA15, []jose.KeyAlgorithm{jose.RSA1_5}, []jose.ContentEncryption{jose.A128CBC_HS256})
			if err != nil {
				b.Fatal(err)
			}
			_, err = obj.Decrypt(jweRSAKey)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("A256KW/A256GCM", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			obj, err := jose.ParseEncrypted(jweCompactA256KW, []jose.KeyAlgorithm{jose.A256KW}, []jose.ContentEncryption{jose.A256GCM})
			if err != nil {
				b.Fatal(err)
			}
			_, err = obj.Decrypt(jweAESKey32)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("A128GCMKW/A128GCM", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			obj, err := jose.ParseEncrypted(jweCompactA128GCMKW, []jose.KeyAlgorithm{jose.A128GCMKW}, []jose.ContentEncryption{jose.A128GCM})
			if err != nil {
				b.Fatal(err)
			}
			_, err = obj.Decrypt(jweAESKey16)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ECDH-ES/A256GCM", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			obj, err := jose.ParseEncrypted(jweCompactECDHES, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
			if err != nil {
				b.Fatal(err)
			}
			_, err = obj.Decrypt(jweECDSAKey)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ECDH-ES+A256KW/A256GCM", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			obj, err := jose.ParseEncrypted(jweCompactECDHESA256KW, []jose.KeyAlgorithm{jose.ECDH_ES_A256KW}, []jose.ContentEncryption{jose.A256GCM})
			if err != nil {
				b.Fatal(err)
			}
			_, err = obj.Decrypt(jweECDSAKey)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("DIRECT/A256GCM", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			obj, err := jose.ParseEncrypted(jweCompactDIRECT, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A256GCM})
			if err != nil {
				b.Fatal(err)
			}
			_, err = obj.Decrypt(jweAESKey32)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
