# jwx Benchmarks

Benchmarks for [github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx).

## Structure

| Directory | Purpose |
|-----------|---------|
| `performance/` | Measures jwx operation performance (JWE, JWS, JWT, JWK) with different JSON backends |
| `comparison/` | Compares jwx against other JWT libraries (golang-jwt) |
| `crossversion/` | Compares performance between jwx versions (v3 vs v4) |

## Running

```bash
# Performance benchmarks (stdlib JSON)
make performance

# Comparison against other libraries
make comparison

# Cross-version comparison (v3 vs v4)
make crossversion
```

See each subdirectory's README for more options.

## Benchmarking Local Changes

To benchmark unreleased jwx code, add a replace directive to the relevant `go.mod`:

```bash
cd performance
go mod edit -replace github.com/lestrrat-go/jwx/v3=/path/to/your/jwx/checkout
go test -bench . -benchmem
# When done:
go mod edit -dropreplace github.com/lestrrat-go/jwx/v3
```
