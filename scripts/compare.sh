#!/bin/bash

set -euo pipefail

RESULTS_DIR="${RESULTS_DIR:-results}"

# Ensure benchstat is available.
if ! command -v benchstat >/dev/null 2>&1; then
	echo "Installing benchstat..."
	go install golang.org/x/perf/cmd/benchstat@latest
fi

# All meaningful pairwise comparisons. golang-jwt-pqc is paired only with
# jwx-v4: those are the two suites that carry ML-DSA benchmarks, and a pair
# with no shared benchmark names gives benchstat nothing to report.
comparisons=(
	"jwx-v3:jwx-v4"
	"jwx-v3:golang-jwt"
	"jwx-v3:go-jose"
	"jwx-v4:golang-jwt"
	"jwx-v4:golang-jwt-pqc"
	"jwx-v4:go-jose"
)

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

for pair in "${comparisons[@]}"; do
	IFS=':' read -r left right <<< "$pair"
	left_file="$RESULTS_DIR/$left.txt"
	right_file="$RESULTS_DIR/$right.txt"

	if [[ -f "$left_file" && -f "$right_file" ]]; then
		echo "=== $left vs $right ==="
		# Inject name metadata for benchstat v2 column labeling. The "pkg" line
		# is dropped because every suite is its own module: benchstat splits the
		# output into one table per distinct configuration, so leaving "pkg" in
		# gives two single-column tables instead of one side-by-side comparison.
		{ echo "name: $left"; grep -v '^pkg: ' "$left_file" || true; } > "$tmpdir/left.txt"
		{ echo "name: $right"; grep -v '^pkg: ' "$right_file" || true; } > "$tmpdir/right.txt"
		benchstat -col name "$tmpdir/left.txt" "$tmpdir/right.txt"
		echo ""
	fi
done
