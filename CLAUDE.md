# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Repo Is

Benchmark suite comparing JWT/JWS/JWE/JWK implementations across Go libraries: jwx v3, jwx v4, golang-jwt/v5, and go-jose/v4. All suites use identical benchmark names so benchstat can compare results across any pair.

## Running Benchmarks

```bash
make quick              # smoke test: count=1, -short
make compare            # production: count=8, -short
make full               # everything: count=3, no -short (includes extended alg matrices)
make bench SUITE=jwx-v4 BENCH=BenchmarkJWE COUNT=5   # flexible mode
make summary BASELINE=jwx-v3                          # generate markdown summary
```

Results land in `results/<suite>.txt`. Scripts in `scripts/` generate comparisons and summaries.

## Suite-Specific Build Requirements

| Suite | Go version | Special flags |
|-------|-----------|---------------|
| jwx-v3 | 1.25 | Always `-tags jwx_goccy` (handled by Makefile/CI) |
| jwx-v4 | 1.26 | Always `GOEXPERIMENT=jsonv2` (handled by Makefile/CI) |
| golang-jwt | 1.25 | None |
| go-jose | 1.25 | None |

Always use `GOWORK=off` when running benchmarks directly (Makefile handles this).

## Running a Single Suite Manually

```bash
# v3
cd suites/jwx-v3 && GOWORK=off go test -tags jwx_goccy -run '^$' -bench BenchmarkJWT_Sign -benchmem -count 1

# v4
cd suites/jwx-v4 && GOWORK=off GOEXPERIMENT=jsonv2 go test -run '^$' -bench BenchmarkJWT_Sign -benchmem -count 1

# golang-jwt / go-jose
cd suites/golang-jwt && go test -run '^$' -bench BenchmarkJWT_Sign -benchmem -count 1
```

## Architecture

Each suite under `suites/` is an independent Go module with `_test.go` files only (no library code). Benchmark functions follow the pattern `BenchmarkCategory_Operation/Algorithm` (e.g., `BenchmarkJWT_Sign/ES256`).

**jwx-v3 and jwx-v4** have the most comprehensive coverage: JWT, JWS, JWE, JWK with extended algorithm matrices, serialization formats, payload sizes, and parallel tests. v4 adds HPKE and ML-KEM benchmarks.

**golang-jwt** covers JWT only (Sign/Parse/Verify) across 13 algorithms — all supported signing methods.

**go-jose** covers JWS, JWE, and JWK (no JWT layer).

### Benchmarks by Run Mode

`quick` and `compare` use `-short`; `full` disables it. All four suites run in every mode.

**JWT** (jwx-v3, jwx-v4, golang-jwt)

| Benchmark | quick/compare | full |
|-----------|:---:|:---:|
| JWT_Sign/{HS256,RS256,ES256,PS256,EdDSA} | yes | yes |
| JWT_Parse/{HS256,RS256,ES256,PS256,EdDSA} | yes | yes |
| JWT_Verify/{same} — signature verification only, no claims validation | yes | yes |
| JWT_VerifyValidate/{same} — signature verification + claims validation | yes | yes |
| JWT_Serialization (Compact/JSON formats) | — | yes |

golang-jwt additionally benchmarks HS384/512, RS384/512, PS384/512, ES384/512 in full mode only (short-gated like jwx suites).

**JWS** (jwx-v3, jwx-v4, go-jose)

| Benchmark | quick/compare | full |
|-----------|:---:|:---:|
| JWS_Sign/{HS256,RS256,ES256} | yes | yes |
| JWS_Verify/{HS256,RS256,ES256} | yes | yes |
| JWS_Sign_All (HS384/512, RS384/512, PS256/384/512, ES384/512, Ed25519) | — | yes |
| JWS_Verify_All (same extended set) | — | yes |
| JWS_Serialization (Compact/JSON parse variants) | — | yes |

**JWE** (jwx-v3, jwx-v4, go-jose)

| Benchmark | quick/compare | full |
|-----------|:---:|:---:|
| JWE_Encrypt/{RSA-OAEP, RSA1_5, A256KW, A128GCMKW, ECDH-ES, ECDH-ES+A256KW, DIRECT} | yes | yes |
| JWE_Decrypt/{same 7 algorithms} | yes | yes |
| JWE_Encrypt_All (RSA-OAEP-256/384/512, A192KW, A192GCMKW, ECDH-ES+A128/192KW, PBES2 variants, extra content-enc combos) | — | yes |
| JWE_Decrypt_All (same extended set) | — | yes |
| JWE_RoundTrip, JWE_PayloadSizes (1K-1M), JWE_Parallel | — | yes |
| JWE_Serialization (JSON marshal/unmarshal) | — | yes |
| JWE_Encrypt_HPKE / JWE_Decrypt_HPKE (HPKE-0/1/2/3/4/7, v4 only) | — | yes |
| JWE_Encrypt_MLKEM / JWE_Decrypt_MLKEM (ML-KEM-768/1024 +/- AES-KW, v4 only) | — | yes |

**JWK** (jwx-v3, jwx-v4, go-jose)

| Benchmark | quick/compare | full |
|-----------|:---:|:---:|
| JWK_Parse/{RSA_PublicKey, RSA_PrivateKey, EC_PublicKey, EC_PrivateKey, Symmetric} | yes | yes |
| JWK_Marshal/{same 5 key types} | yes | yes |
| JWK_Parse_OKP / JWK_Marshal_OKP (Ed25519, X25519) | — | yes |
| JWK_Serialization (JSON parse/marshal/string variants) | — | yes |

### Benchmark infrastructure

Both jwx suites share a `Case` struct in `helpers_test.go` with `Pretest` (setup outside timer), `SkipShort`, and `Test` fields. Key generation helpers: `generateRsaJwk()`, `generateEcdsaJwk()`, `generateSymmetricJwk()`, `generateEd25519Jwk()`.

v3 uses `jwk.Import(raw)`, v4 uses `jwk.Import[jwk.Key](raw)` (generics).

## CI

Single workflow `.github/workflows/benchmarks.yml`: weekly schedule + manual dispatch with mode/baseline/suite selection. Generates markdown summary in GitHub Step Summary with percentage deltas against a baseline suite (auto-detects jwx-v4). Raw results uploaded as artifacts.

## Opt-in Algorithms (Build Tags)

`bench_es256k`, `bench_ed448`, `bench_mldsa`, `bench_x448` — referenced in README but no `optin_*_test.go` files exist yet.
