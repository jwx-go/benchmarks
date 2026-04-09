# jwx Benchmarks

Benchmarks for [github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx).

## Structure

| Directory | Purpose |
|-----------|---------|
| `suites/jwx-v3/` | jwx v3 benchmarks (JWT, JWS, JWE, JWK) |
| `suites/jwx-v4/` | jwx v4 benchmarks (includes HPKE, ML-KEM) |
| `suites/golang-jwt/` | golang-jwt/v5 benchmarks (JWT only) |
| `suites/go-jose/` | go-jose/v4 benchmarks (JWS, JWE, JWK) |

All suites use identical benchmark names so [benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat) can directly compare results across any pair.

## Running

```bash
# Smoke test (count=1, cross-suite benchmarks only)
make quick

# Production comparison (count=8, cross-suite benchmarks only)
make compare

# Everything including opt-in algorithms (count=3)
make full

# Flexible: pick suite, pattern, count, tags
make bench SUITE=jwx-v4 BENCH=BenchmarkJWE COUNT=5 TAGS=bench_mldsa SHORT=
```

## Opt-in Algorithms

Some algorithms require opt-in build tags:

| Tag | v3 | v4 | Algorithms |
|-----|----|----|------------|
| `jwx_es256k` / `bench_es256k` | yes | yes | ES256K (secp256k1) |
| `bench_ed448` | — | yes | Ed448 |
| `bench_mldsa` | — | yes | ML-DSA-44/65/87 |
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

For v4, substitute `v3` with `v4` and add `GOEXPERIMENT=jsonv2`.
