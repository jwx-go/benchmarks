package bench_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

func BenchmarkJWK_Parse(b *testing.B) {
	rsaKey, err := generateRsaJwk()
	if err != nil {
		b.Fatal(err)
	}
	rsaPubKey, err := jwk.PublicKeyOf(rsaKey)
	if err != nil {
		b.Fatal(err)
	}

	ecKey, err := generateEcdsaJwk()
	if err != nil {
		b.Fatal(err)
	}
	ecPubKey, err := jwk.PublicKeyOf(ecKey)
	if err != nil {
		b.Fatal(err)
	}

	symKey, err := generateSymmetricJwk()
	if err != nil {
		b.Fatal(err)
	}

	keys := []struct {
		name string
		key  jwk.Key
	}{
		{"RSA_PublicKey", rsaPubKey},
		{"RSA_PrivateKey", rsaKey},
		{"EC_PublicKey", ecPubKey},
		{"EC_PrivateKey", ecKey},
		{"Symmetric", symKey},
	}

	for _, k := range keys {
		buf, err := json.Marshal(k.key)
		if err != nil {
			b.Fatal(err)
		}

		b.Run(k.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := jwk.Parse(buf)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJWK_Marshal(b *testing.B) {
	rsaKey, err := generateRsaJwk()
	if err != nil {
		b.Fatal(err)
	}
	rsaPubKey, err := jwk.PublicKeyOf(rsaKey)
	if err != nil {
		b.Fatal(err)
	}

	ecKey, err := generateEcdsaJwk()
	if err != nil {
		b.Fatal(err)
	}
	ecPubKey, err := jwk.PublicKeyOf(ecKey)
	if err != nil {
		b.Fatal(err)
	}

	symKey, err := generateSymmetricJwk()
	if err != nil {
		b.Fatal(err)
	}

	keys := []struct {
		name string
		key  jwk.Key
	}{
		{"RSA_PublicKey", rsaPubKey},
		{"RSA_PrivateKey", rsaKey},
		{"EC_PublicKey", ecPubKey},
		{"EC_PrivateKey", ecKey},
		{"Symmetric", symKey},
	}

	for _, k := range keys {
		b.Run(k.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := json.Marshal(k.key)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJWK_Parse_OKP(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping OKP key benchmarks in short mode")
	}

	edKey, err := generateEd25519Jwk()
	if err != nil {
		b.Fatal(err)
	}
	edPubKey, err := jwk.PublicKeyOf(edKey)
	if err != nil {
		b.Fatal(err)
	}

	x25519Raw, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	x25519Key, err := jwk.Import[jwk.Key](x25519Raw)
	if err != nil {
		b.Fatal(err)
	}
	x25519PubKey, err := jwk.Import[jwk.Key](x25519Raw.PublicKey())
	if err != nil {
		b.Fatal(err)
	}

	keys := []struct {
		name string
		key  jwk.Key
	}{
		{"Ed25519_PublicKey", edPubKey},
		{"Ed25519_PrivateKey", edKey},
		{"X25519_PublicKey", x25519PubKey},
		{"X25519_PrivateKey", x25519Key},
	}

	for _, k := range keys {
		buf, err := json.Marshal(k.key)
		if err != nil {
			b.Fatal(err)
		}

		b.Run(k.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := jwk.Parse(buf)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJWK_Marshal_OKP(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping OKP key benchmarks in short mode")
	}

	edKey, err := generateEd25519Jwk()
	if err != nil {
		b.Fatal(err)
	}
	edPubKey, err := jwk.PublicKeyOf(edKey)
	if err != nil {
		b.Fatal(err)
	}

	x25519Raw, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	x25519Key, err := jwk.Import[jwk.Key](x25519Raw)
	if err != nil {
		b.Fatal(err)
	}
	x25519PubKey, err := jwk.Import[jwk.Key](x25519Raw.PublicKey())
	if err != nil {
		b.Fatal(err)
	}

	keys := []struct {
		name string
		key  jwk.Key
	}{
		{"Ed25519_PublicKey", edPubKey},
		{"Ed25519_PrivateKey", edKey},
		{"X25519_PublicKey", x25519PubKey},
		{"X25519_PrivateKey", x25519Key},
	}

	for _, k := range keys {
		b.Run(k.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := json.Marshal(k.key)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func runJSONBench(b *testing.B, privkey jwk.Key) {
	b.Helper()

	_ = privkey.Set("mykey", "1234567890")
	pubkey, err := jwk.PublicKeyOf(privkey)
	if err != nil {
		b.Fatal(err)
	}

	keytypes := []struct {
		Name string
		Key  jwk.Key
	}{
		{Name: "PublicKey", Key: pubkey},
		{Name: "PrivateKey", Key: privkey},
	}

	for _, keytype := range keytypes {
		key := keytype.Key
		b.Run(keytype.Name, func(b *testing.B) {
			buf, _ := json.Marshal(key)
			s := string(buf)
			rdr := bytes.NewReader(buf)

			testcases := []Case{
				{
					Name:      "jwk.Parse",
					SkipShort: true,
					Test: func(b *testing.B) error {
						_, err := jwk.Parse(buf)
						return err
					},
				},
				{
					Name:      "jwk.ParseString",
					SkipShort: true,
					Test: func(b *testing.B) error {
						_, err := jwk.ParseString(s)
						return err
					},
				},
				{
					Name:      "jwk.ParseReader",
					SkipShort: true,
					Pretest: func(b *testing.B) error {
						_, err := rdr.Seek(0, 0)
						return err
					},
					Test: func(b *testing.B) error {
						_, err := jwk.ParseReader(rdr)
						return err
					},
				},
				{
					Name:      "json.Marshal",
					SkipShort: true,
					Test: func(b *testing.B) error {
						_, err := json.Marshal(key)
						return err
					},
				},
			}
			for _, tc := range testcases {
				tc.Run(b)
			}
		})
	}
}

func BenchmarkJWK_Serialization(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping serialization benchmarks in short mode")
	}

	b.Run("RSA", func(b *testing.B) {
		rsakey, _ := generateRsaJwk()
		runJSONBench(b, rsakey)
	})
	b.Run("EC", func(b *testing.B) {
		eckey, _ := generateEcdsaJwk()
		runJSONBench(b, eckey)
	})
	b.Run("Symmetric", func(b *testing.B) {
		symkey, _ := generateSymmetricJwk()
		runJSONBench(b, symkey)
	})
}
