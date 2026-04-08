# Cross-Version Benchmarks

Compares performance between jwx v3 and v4.

## Setup

The `v3/go.mod` and `v4/go.mod` contain `replace` directives pointing at local jwx checkouts. Update these paths to match your environment:

```bash
# v3/go.mod
replace github.com/lestrrat-go/jwx/v3 => /path/to/your/jwx/v3/checkout

# v4/go.mod
replace github.com/lestrrat-go/jwx/v3 => /path/to/your/jwx/v4/checkout
```

## Running

```bash
make compare          # default: 8 iterations, short mode (~10-15 min)
make compare-full     # comprehensive: 8 iterations, all benchmarks (~30-60 min)
make compare-quick    # smoke test: 1 iteration, short mode (~2 min)
make compare-jwt      # JWT only
make compare-jws      # JWS only
make compare-jwe      # JWE only
make compare-jwk      # JWK only
make compare-goccy    # with jwx_goccy build tag
```

Or directly: `./compare.sh -count 5 -bench "BenchmarkJWS" -short -timeout 5m`

## Requirements

- **GOWORK=off** is set automatically by `compare.sh`
- **GOEXPERIMENT=jsonv2** is set automatically for v4 runs
- **benchstat** is auto-installed if missing
