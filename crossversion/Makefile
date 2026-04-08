SHELL := /bin/bash

compare:
	./compare.sh

compare-full:
	./compare.sh -full

compare-quick:
	./compare.sh -count 1

compare-jwt:
	./compare.sh -bench BenchmarkJWT

compare-jws:
	./compare.sh -bench BenchmarkJWS

compare-jwe:
	./compare.sh -bench BenchmarkJWE

compare-jwk:
	./compare.sh -bench BenchmarkJWK

compare-goccy:
	./compare.sh -tags jwx_goccy

.PHONY: compare compare-full compare-quick compare-jwt compare-jws compare-jwe compare-jwk compare-goccy
