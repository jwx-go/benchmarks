.PHONY: quick compare full bench run-suite compare-results

SUITES     := jwx-v3 jwx-v4 golang-jwt go-jose
RESULTS    := results

# Flexible mode defaults
SUITE      ?= $(SUITES)
BENCH      ?= .
COUNT      ?= 8
TAGS       ?=
SHORT      ?= -short

# --- Rigid modes ---

# Smoke test: cross-suite benchmarks, count=1
quick:
	$(MAKE) run-suite SUITE="$(SUITES)" BENCH="." COUNT=1 SHORT="-short" TAGS=""
	$(MAKE) compare-results

# Production comparison: cross-suite benchmarks, count=8
compare:
	$(MAKE) run-suite SUITE="$(SUITES)" BENCH="." COUNT=8 SHORT="-short" TAGS=""
	$(MAKE) compare-results

# Everything: all benchmarks including opt-in, count=3
# Opt-in tags (bench_es256k,bench_ed448,bench_mldsa,bench_x448) can be added
# once the corresponding optin_*_test.go files are created in each suite.
full:
	$(MAKE) run-suite SUITE="$(SUITES)" BENCH="." COUNT=3 SHORT="" TAGS=""
	$(MAKE) compare-results

# --- Flexible mode ---

# Run selected suites with custom parameters
# Usage: make bench SUITE=jwx-v4 BENCH=BenchmarkJWE COUNT=5 TAGS=bench_mldsa SHORT=
bench:
	$(MAKE) run-suite
	$(MAKE) compare-results

# --- Internal targets ---

run-suite:
	@mkdir -p $(RESULTS)
	@for suite in $(SUITE); do \
		echo "--- Running $$suite ---"; \
		tags=""; \
		goexperiment=""; \
		if [ "$$suite" = "jwx-v3" ]; then \
			tags="jwx_goccy"; \
			if [ -n "$(TAGS)" ]; then tags="$$tags,$(TAGS)"; fi; \
		elif [ "$$suite" = "jwx-v4" ]; then \
			goexperiment="GOEXPERIMENT=jsonv2"; \
			if [ -n "$(TAGS)" ]; then tags="$(TAGS)"; fi; \
		fi; \
		tagflag=""; \
		if [ -n "$$tags" ]; then tagflag="-tags $$tags"; fi; \
		GOWORK=off $$goexperiment go test -C suites/$$suite \
			-run '^$$' -bench "$(BENCH)" -benchmem \
			-count $(COUNT) -timeout 60m $(SHORT) \
			$$tagflag > $(RESULTS)/$$suite.txt 2>&1 || exit 1; \
		echo "  Saved $(RESULTS)/$$suite.txt"; \
	done

compare-results:
	@./scripts/compare.sh
