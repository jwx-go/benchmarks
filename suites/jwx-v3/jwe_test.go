package bench_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
)

func setupKeys() (*rsa.PrivateKey, *ecdsa.PrivateKey, []byte) {
	// RSA key for RSA-OAEP
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// ECDSA key for ECDH-ES
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Symmetric key for AES-KW
	symKey := make([]byte, 32)
	rand.Read(symKey)

	return rsaKey, ecKey, symKey
}

func BenchmarkJWE_Encrypt(b *testing.B) {
	rsaKey, ecKey, symKey := setupKeys()
	payload := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")

	testcases := []struct {
		name string
		alg  jwa.KeyEncryptionAlgorithm
		enc  jwa.ContentEncryptionAlgorithm
		key  interface{}
	}{
		{
			name: "RSA-OAEP/A256GCM",
			alg:  jwa.RSA_OAEP(),
			enc:  jwa.A256GCM(),
			key:  &rsaKey.PublicKey,
		},
		{
			name: "RSA1_5/A128CBC-HS256",
			alg:  jwa.RSA1_5(),
			enc:  jwa.A128CBC_HS256(),
			key:  &rsaKey.PublicKey,
		},
		{
			name: "A256KW/A256GCM",
			alg:  jwa.A256KW(),
			enc:  jwa.A256GCM(),
			key:  symKey,
		},
		{
			name: "A128GCMKW/A128GCM",
			alg:  jwa.A128GCMKW(),
			enc:  jwa.A128GCM(),
			key:  symKey[:16],
		},
		{
			name: "ECDH-ES/A256GCM",
			alg:  jwa.ECDH_ES(),
			enc:  jwa.A256GCM(),
			key:  &ecKey.PublicKey,
		},
		{
			name: "ECDH-ES+A256KW/A256GCM",
			alg:  jwa.ECDH_ES_A256KW(),
			enc:  jwa.A256GCM(),
			key:  &ecKey.PublicKey,
		},
		{
			name: "DIRECT/A256GCM",
			alg:  jwa.DIRECT(),
			enc:  jwa.A256GCM(),
			key:  symKey,
		},
	}

	for _, tc := range testcases {
		withKey := jwe.WithKey(tc.alg, tc.key)
		withEnc := jwe.WithContentEncryption(tc.enc)
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := jwe.Encrypt(payload, withKey, withEnc)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJWE_Decrypt(b *testing.B) {
	rsaKey, ecKey, symKey := setupKeys()
	payload := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")

	testcases := []struct {
		name   string
		alg    jwa.KeyEncryptionAlgorithm
		enc    jwa.ContentEncryptionAlgorithm
		encKey interface{}
		decKey interface{}
	}{
		{
			name:   "RSA-OAEP/A256GCM",
			alg:    jwa.RSA_OAEP(),
			enc:    jwa.A256GCM(),
			encKey: &rsaKey.PublicKey,
			decKey: rsaKey,
		},
		{
			name:   "RSA1_5/A128CBC-HS256",
			alg:    jwa.RSA1_5(),
			enc:    jwa.A128CBC_HS256(),
			encKey: &rsaKey.PublicKey,
			decKey: rsaKey,
		},
		{
			name:   "A256KW/A256GCM",
			alg:    jwa.A256KW(),
			enc:    jwa.A256GCM(),
			encKey: symKey,
			decKey: symKey,
		},
		{
			name:   "A128GCMKW/A128GCM",
			alg:    jwa.A128GCMKW(),
			enc:    jwa.A128GCM(),
			encKey: symKey[:16],
			decKey: symKey[:16],
		},
		{
			name:   "ECDH-ES/A256GCM",
			alg:    jwa.ECDH_ES(),
			enc:    jwa.A256GCM(),
			encKey: &ecKey.PublicKey,
			decKey: ecKey,
		},
		{
			name:   "ECDH-ES+A256KW/A256GCM",
			alg:    jwa.ECDH_ES_A256KW(),
			enc:    jwa.A256GCM(),
			encKey: &ecKey.PublicKey,
			decKey: ecKey,
		},
		{
			name:   "DIRECT/A256GCM",
			alg:    jwa.DIRECT(),
			enc:    jwa.A256GCM(),
			encKey: symKey,
			decKey: symKey,
		},
	}

	for _, tc := range testcases {
		b.Run(tc.name, func(b *testing.B) {
			// Pre-encrypt the payload
			encrypted, err := jwe.Encrypt(payload,
				jwe.WithKey(tc.alg, tc.encKey),
				jwe.WithContentEncryption(tc.enc),
			)
			if err != nil {
				b.Fatal(err)
			}

			withKey := jwe.WithKey(tc.alg, tc.decKey)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := jwe.Decrypt(encrypted, withKey)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJWE_Encrypt_All(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping extended algorithm matrix in short mode")
	}

	rsaKey, ecKey, _ := setupKeys()
	payload := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")

	sym24 := make([]byte, 24)
	rand.Read(sym24)

	passphrase := []byte("super-secret-passphrase")

	testcases := []struct {
		name string
		alg  jwa.KeyEncryptionAlgorithm
		enc  jwa.ContentEncryptionAlgorithm
		key  interface{}
	}{
		{"RSA-OAEP-256/A256GCM", jwa.RSA_OAEP_256(), jwa.A256GCM(), &rsaKey.PublicKey},
		{"RSA-OAEP-384/A256GCM", jwa.RSA_OAEP_384(), jwa.A256GCM(), &rsaKey.PublicKey},
		{"RSA-OAEP-512/A256GCM", jwa.RSA_OAEP_512(), jwa.A256GCM(), &rsaKey.PublicKey},
		{"A192KW/A192GCM", jwa.A192KW(), jwa.A192GCM(), sym24},
		{"A192GCMKW/A192GCM", jwa.A192GCMKW(), jwa.A192GCM(), sym24},
		{"ECDH-ES+A128KW/A256GCM", jwa.ECDH_ES_A128KW(), jwa.A256GCM(), &ecKey.PublicKey},
		{"ECDH-ES+A192KW/A256GCM", jwa.ECDH_ES_A192KW(), jwa.A256GCM(), &ecKey.PublicKey},
		{"PBES2-HS256+A128KW/A256GCM", jwa.PBES2_HS256_A128KW(), jwa.A256GCM(), passphrase},
		{"PBES2-HS384+A192KW/A256GCM", jwa.PBES2_HS384_A192KW(), jwa.A256GCM(), passphrase},
		{"PBES2-HS512+A256KW/A256GCM", jwa.PBES2_HS512_A256KW(), jwa.A256GCM(), passphrase},
		{"RSA-OAEP/A128GCM", jwa.RSA_OAEP(), jwa.A128GCM(), &rsaKey.PublicKey},
		{"RSA-OAEP/A192GCM", jwa.RSA_OAEP(), jwa.A192GCM(), &rsaKey.PublicKey},
		{"RSA-OAEP/A192CBC-HS384", jwa.RSA_OAEP(), jwa.A192CBC_HS384(), &rsaKey.PublicKey},
		{"RSA-OAEP/A256CBC-HS512", jwa.RSA_OAEP(), jwa.A256CBC_HS512(), &rsaKey.PublicKey},
	}

	for _, tc := range testcases {
		withKey := jwe.WithKey(tc.alg, tc.key)
		withEnc := jwe.WithContentEncryption(tc.enc)
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := jwe.Encrypt(payload, withKey, withEnc)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJWE_Decrypt_All(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping extended algorithm matrix in short mode")
	}

	rsaKey, ecKey, _ := setupKeys()
	payload := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")

	sym24 := make([]byte, 24)
	rand.Read(sym24)

	passphrase := []byte("super-secret-passphrase")

	testcases := []struct {
		name   string
		alg    jwa.KeyEncryptionAlgorithm
		enc    jwa.ContentEncryptionAlgorithm
		encKey interface{}
		decKey interface{}
	}{
		{"RSA-OAEP-256/A256GCM", jwa.RSA_OAEP_256(), jwa.A256GCM(), &rsaKey.PublicKey, rsaKey},
		{"RSA-OAEP-384/A256GCM", jwa.RSA_OAEP_384(), jwa.A256GCM(), &rsaKey.PublicKey, rsaKey},
		{"RSA-OAEP-512/A256GCM", jwa.RSA_OAEP_512(), jwa.A256GCM(), &rsaKey.PublicKey, rsaKey},
		{"A192KW/A192GCM", jwa.A192KW(), jwa.A192GCM(), sym24, sym24},
		{"A192GCMKW/A192GCM", jwa.A192GCMKW(), jwa.A192GCM(), sym24, sym24},
		{"ECDH-ES+A128KW/A256GCM", jwa.ECDH_ES_A128KW(), jwa.A256GCM(), &ecKey.PublicKey, ecKey},
		{"ECDH-ES+A192KW/A256GCM", jwa.ECDH_ES_A192KW(), jwa.A256GCM(), &ecKey.PublicKey, ecKey},
		{"PBES2-HS256+A128KW/A256GCM", jwa.PBES2_HS256_A128KW(), jwa.A256GCM(), passphrase, passphrase},
		{"PBES2-HS384+A192KW/A256GCM", jwa.PBES2_HS384_A192KW(), jwa.A256GCM(), passphrase, passphrase},
		{"PBES2-HS512+A256KW/A256GCM", jwa.PBES2_HS512_A256KW(), jwa.A256GCM(), passphrase, passphrase},
		{"RSA-OAEP/A128GCM", jwa.RSA_OAEP(), jwa.A128GCM(), &rsaKey.PublicKey, rsaKey},
		{"RSA-OAEP/A192GCM", jwa.RSA_OAEP(), jwa.A192GCM(), &rsaKey.PublicKey, rsaKey},
		{"RSA-OAEP/A192CBC-HS384", jwa.RSA_OAEP(), jwa.A192CBC_HS384(), &rsaKey.PublicKey, rsaKey},
		{"RSA-OAEP/A256CBC-HS512", jwa.RSA_OAEP(), jwa.A256CBC_HS512(), &rsaKey.PublicKey, rsaKey},
	}

	for _, tc := range testcases {
		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(tc.alg, tc.encKey),
			jwe.WithContentEncryption(tc.enc),
		)
		if err != nil {
			b.Fatal(err)
		}

		withKey := jwe.WithKey(tc.alg, tc.decKey)
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := jwe.Decrypt(encrypted, withKey)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJWE_RoundTrip(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping in short mode (covered by separate encrypt/decrypt benchmarks)")
	}
	rsaKey, ecKey, symKey := setupKeys()
	payload := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")

	testcases := []struct {
		name   string
		alg    jwa.KeyEncryptionAlgorithm
		enc    jwa.ContentEncryptionAlgorithm
		encKey interface{}
		decKey interface{}
	}{
		{
			name:   "RSA-OAEP/A256GCM",
			alg:    jwa.RSA_OAEP(),
			enc:    jwa.A256GCM(),
			encKey: &rsaKey.PublicKey,
			decKey: rsaKey,
		},
		{
			name:   "A256KW/A256GCM",
			alg:    jwa.A256KW(),
			enc:    jwa.A256GCM(),
			encKey: symKey,
			decKey: symKey,
		},
		{
			name:   "ECDH-ES/A256GCM",
			alg:    jwa.ECDH_ES(),
			enc:    jwa.A256GCM(),
			encKey: &ecKey.PublicKey,
			decKey: ecKey,
		},
	}

	for _, tc := range testcases {
		withEncKey := jwe.WithKey(tc.alg, tc.encKey)
		withEnc := jwe.WithContentEncryption(tc.enc)
		withDecKey := jwe.WithKey(tc.alg, tc.decKey)
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				// Encrypt
				encrypted, err := jwe.Encrypt(payload, withEncKey, withEnc)
				if err != nil {
					b.Fatal(err)
				}

				// Decrypt
				decrypted, err := jwe.Decrypt(encrypted, withDecKey)
				if err != nil {
					b.Fatal(err)
				}

				// Verify payload
				if string(decrypted) != string(payload) {
					b.Fatal("payload mismatch")
				}
			}
		})
	}
}

func BenchmarkJWE_PayloadSizes(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping in short mode (covered by encrypt/decrypt with standard payload)")
	}
	rsaKey, _, _ := setupKeys()

	payloadSizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"10KB", 10 * 1024},
		{"100KB", 100 * 1024},
		{"1MB", 1024 * 1024},
	}

	withEncKey := jwe.WithKey(jwa.RSA_OAEP(), &rsaKey.PublicKey)
	withEnc := jwe.WithContentEncryption(jwa.A256GCM())
	withDecKey := jwe.WithKey(jwa.RSA_OAEP(), rsaKey)

	for _, ps := range payloadSizes {
		payload := make([]byte, ps.size)
		rand.Read(payload)

		b.Run("Encrypt_"+ps.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := jwe.Encrypt(payload, withEncKey, withEnc)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run("Decrypt_"+ps.name, func(b *testing.B) {
			// Pre-encrypt
			encrypted, err := jwe.Encrypt(payload, withEncKey, withEnc)
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := jwe.Decrypt(encrypted, withDecKey)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJWE_Parallel(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping in short mode (concurrency test, not algorithm comparison)")
	}
	rsaKey, _, _ := setupKeys()
	payload := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")

	withEncKey := jwe.WithKey(jwa.RSA_OAEP(), &rsaKey.PublicKey)
	withEnc := jwe.WithContentEncryption(jwa.A256GCM())
	withDecKey := jwe.WithKey(jwa.RSA_OAEP(), rsaKey)

	b.Run("Encrypt_Parallel", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := jwe.Encrypt(payload, withEncKey, withEnc)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})

	b.Run("Decrypt_Parallel", func(b *testing.B) {
		// Pre-encrypt
		encrypted, err := jwe.Encrypt(payload, withEncKey, withEnc)
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := jwe.Decrypt(encrypted, withDecKey)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}

func BenchmarkJWE_Serialization(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping in short mode (JSON serialization, not encrypt/decrypt)")
	}
	const s = `eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ`

	m, _ := jwe.Parse([]byte(s))
	js, _ := json.Marshal(m)

	b.Run("JSON_Marshal", func(b *testing.B) {
		testcases := []Case{
			{
				Name:      "json.Marshal",
				SkipShort: true,
				Test: func(b *testing.B) error {
					_, err := json.Marshal(m)
					return err
				},
			},
			{
				Name:      "json.Unmarshal",
				SkipShort: true,
				Test: func(b *testing.B) error {
					msg := jwe.NewMessage()
					return json.Unmarshal(js, msg)
				},
			},
		}
		for _, tc := range testcases {
			tc.Run(b)
		}
	})
}
