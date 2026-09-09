# jwx Benchmarks

Benchmarks for [github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx).

## Structure

| Directory | Purpose |
|-----------|---------|
| `suites/jwx-v3/` | jwx v3 benchmarks (JWT, JWS, JWE, JWK) |
| `suites/jwx-v4/` | jwx v4 benchmarks (includes HPKE, ML-KEM, ML-DSA) |
| `suites/golang-jwt/` | golang-jwt/v5 benchmarks (JWT only) |
| `suites/golang-jwt-pqc/` | salrashid123/golang-jwt-pqc benchmarks (JWT, ML-DSA only) |
| `suites/go-jose/` | go-jose/v4 benchmarks (JWS, JWE, JWK) |

All suites use identical benchmark names so [benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat) can directly compare results across any pair.

Every suite builds with Go 1.27 or later. ML-DSA benchmarks need `crypto/mldsa`, which joined the standard library in Go 1.27, and jwx v4 registers ML-DSA natively from that release on.

## Post-Quantum Algorithms

| Benchmark | Suites |
|-----------|--------|
| `JWS_Sign_MLDSA` / `JWS_Verify_MLDSA` (ML-DSA-44/65/87) | jwx-v4 |
| `JWT_Sign_MLDSA` / `JWT_Parse_MLDSA` / `JWT_Verify_MLDSA` / `JWT_VerifyValidate_MLDSA` | jwx-v4, golang-jwt-pqc |
| `JWE_Encrypt_MLKEM` / `JWE_Decrypt_MLKEM` (ML-KEM-768/1024, with and without AES-KW) | jwx-v4 |

These run in every mode, including `quick` and `compare`.

golang-jwt/v5 has no post-quantum signing methods of its own, so the PQC comparison for it goes through [salrashid123/golang-jwt-pqc](https://github.com/salrashid123/golang-jwt-pqc), which registers ML-DSA with golang-jwt and signs through `crypto/mldsa`. Its published ML-DSA submodule pins its own parent at an untagged `v0.0.0`, so `suites/golang-jwt-pqc/go.mod` carries a `replace` directive pointing the parent at a real release.

## Running

```bash
# Smoke test (count=1, cross-suite benchmarks only)
make quick

# Production comparison (count=8, cross-suite benchmarks only)
make compare

# Everything including opt-in algorithms (count=3)
make full

# Flexible: pick suite, pattern, count, tags
make bench SUITE=jwx-v4 BENCH=BenchmarkJWE COUNT=5 TAGS=bench_es256k SHORT=
```

## Opt-in Algorithms

Some algorithms require opt-in build tags:

| Tag | v3 | v4 | Algorithms |
|-----|----|----|------------|
| `jwx_es256k` / `bench_es256k` | yes | yes | ES256K (secp256k1) |
| `bench_ed448` | — | yes | Ed448 |
| `bench_x448` | — | yes | HPKE-5/6, ECDH-ES X448 |

v3 always uses `-tags jwx_goccy` (handled automatically by the Makefile).

## Benchmarking Local Changes

To benchmark unreleased jwx code, add a replace directive:

```bash
cd suites/jwx-v3
go mod edit -replace github.com/lestrrat-go/jwx/v3=/path/to/local/checkout
GOWORK=off go test -tags jwx_goccy -bench . -benchmem -count 1 -short
go mod edit -dropreplace github.com/lestrrat-go/jwx/v3
```

For v4, substitute `v3` with `v4` and drop the `-tags jwx_goccy` flag.
