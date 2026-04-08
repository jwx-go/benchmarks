#!/bin/bash

set -euo pipefail

# Defaults
COUNT=8
BENCH="."
TAGS=""
TIMEOUT="30m"
SHORT="-short"

usage() {
	echo "Usage: $0 [options]"
	echo ""
	echo "Compare benchmarks between v3 and v4 of jwx."
	echo ""
	echo "Options:"
	echo "  -count N        Number of benchmark iterations (default: 8)"
	echo "  -bench PATTERN  Benchmark pattern to run (default: .)"
	echo "  -tags TAGS      Build tags (e.g. jwx_goccy)"
	echo "  -timeout DUR    Timeout duration (default: 30m, 60m with -full)"
	echo "  -short          Run in short mode (skip slow benchmarks) [default]"
	echo "  -full           Run all benchmarks including slow ones (disables -short, timeout 60m)"
	echo "  -h, -help       Show this help"
	exit 0
}

while [ $# -gt 0 ]; do
	case "$1" in
		-count)
			COUNT="$2"
			shift 2
			;;
		-bench)
			BENCH="$2"
			shift 2
			;;
		-tags)
			TAGS="$2"
			shift 2
			;;
		-timeout)
			TIMEOUT="$2"
			shift 2
			;;
		-short)
			SHORT="-short"
			shift
			;;
		-full)
			SHORT=""
			TIMEOUT="60m"
			shift
			;;
		-h|-help|--help)
			usage
			;;
		*)
			echo "Unknown option: $1" >&2
			usage
			;;
	esac
done

# Resolve paths relative to this script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
V3_BENCH="$SCRIPT_DIR/v3"
V4_BENCH="$SCRIPT_DIR/v4"

if [ ! -d "$V3_BENCH" ]; then
	echo "ERROR: v3 bench directory not found at $V3_BENCH" >&2
	exit 1
fi

if [ ! -d "$V4_BENCH" ]; then
	echo "ERROR: v4 bench directory not found at $V4_BENCH" >&2
	exit 1
fi

# Ensure benchstat is available.
if ! command -v benchstat >/dev/null 2>&1; then
	echo "Installing benchstat..."
	go install golang.org/x/perf/cmd/benchstat@latest
fi

# Build the flags.
TAGS_FLAG=""
if [ -n "$TAGS" ]; then
	TAGS_FLAG="-tags $TAGS"
fi

RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$RESULTS_DIR"

echo "=== v3 vs v4 Benchmark Comparison ==="
echo "  Count:   $COUNT"
echo "  Bench:   $BENCH"
echo "  Tags:    ${TAGS:-<none>}"
echo "  Short:   ${SHORT:-no}"
echo "  Timeout: $TIMEOUT"
echo ""
echo "  v3 bench: $V3_BENCH"
echo "  v4 bench: $V4_BENCH"
echo ""

# Disable go.work so each bench module uses its own go.mod replace directive.
export GOWORK=off

# Run v3 benchmarks.
echo "--- Running v3 benchmarks ---"
# shellcheck disable=SC2086
(cd "$V3_BENCH" && go test -run '^$' -bench "$BENCH" -benchmem -count "$COUNT" -timeout "$TIMEOUT" $TAGS_FLAG $SHORT) > "$RESULTS_DIR/v3.txt" 2>&1
echo "  Saved to $RESULTS_DIR/v3.txt"

# Run v4 benchmarks.
# v4 uses encoding/json/v2 which requires the jsonv2 experiment.
echo "--- Running v4 benchmarks ---"
# shellcheck disable=SC2086
(cd "$V4_BENCH" && GOEXPERIMENT=jsonv2 go test -run '^$' -bench "$BENCH" -benchmem -count "$COUNT" -timeout "$TIMEOUT" $TAGS_FLAG $SHORT) > "$RESULTS_DIR/v4.txt" 2>&1
echo "  Saved to $RESULTS_DIR/v4.txt"

echo ""
echo "=== Results ==="
benchstat "$RESULTS_DIR/v3.txt" "$RESULTS_DIR/v4.txt" | sed "s|$RESULTS_DIR/v3.txt|v3|g; s|$RESULTS_DIR/v4.txt|v4|g"
