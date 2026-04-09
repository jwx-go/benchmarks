#!/bin/bash
#
# Generates a markdown summary comparing benchmark results across suites.
# Reads raw go test -bench output from results/<suite>.txt files.
#
# Usage: ./scripts/summary.sh [results-dir]

set -euo pipefail

RESULTS_DIR="${1:-results}"
SUITES=(jwx-v3 jwx-v4 golang-jwt go-jose)

# Collect available suites.
available=()
for s in "${SUITES[@]}"; do
	if [[ -f "$RESULTS_DIR/$s.txt" ]]; then
		available+=("$s")
	fi
done

if [[ ${#available[@]} -eq 0 ]]; then
	echo "No result files found in $RESULTS_DIR" >&2
	exit 1
fi

# Parse benchmark results: extract median ns/op and B/op for each benchmark.
# Output: benchmark_name<TAB>ns_op<TAB>b_op<TAB>allocs_op
parse_results() {
	local file="$1"
	awk '
	/^Benchmark/ {
		# Extract benchmark name (strip -N suffix)
		name = $1
		sub(/-[0-9]+$/, "", name)
		sub(/^Benchmark/, "", name)

		nsop = $3
		# Find B/op and allocs/op
		bop = ""
		allocsop = ""
		for (i = 4; i <= NF; i++) {
			if ($(i) == "B/op") bop = $(i-1)
			if ($(i) == "allocs/op") allocsop = $(i-1)
		}

		# Accumulate values for median calculation
		count[name]++
		values[name][count[name]] = nsop
		bvalues[name][count[name]] = bop
		avalues[name][count[name]] = allocsop
	}
	END {
		for (name in count) {
			n = count[name]
			# Use the middle value as median approximation
			mid = int((n + 1) / 2)

			# Sort values to get median
			for (i = 1; i <= n; i++) sorted[i] = values[name][i]
			for (i = 1; i <= n; i++)
				for (j = i + 1; j <= n; j++)
					if (sorted[i]+0 > sorted[j]+0) {
						t = sorted[i]; sorted[i] = sorted[j]; sorted[j] = t
					}
			nsmed = sorted[mid]

			for (i = 1; i <= n; i++) sorted[i] = bvalues[name][i]
			for (i = 1; i <= n; i++)
				for (j = i + 1; j <= n; j++)
					if (sorted[i]+0 > sorted[j]+0) {
						t = sorted[i]; sorted[i] = sorted[j]; sorted[j] = t
					}
			bmed = sorted[mid]

			for (i = 1; i <= n; i++) sorted[i] = avalues[name][i]
			for (i = 1; i <= n; i++)
				for (j = i + 1; j <= n; j++)
					if (sorted[i]+0 > sorted[j]+0) {
						t = sorted[i]; sorted[i] = sorted[j]; sorted[j] = t
					}
			amed = sorted[mid]

			print name "\t" nsmed "\t" bmed "\t" amed
		}
	}
	' "$file"
}

# Format ns value to human-readable.
format_ns() {
	awk -v ns="$1" 'BEGIN {
		v = ns + 0
		if (v >= 1000000000) printf "%.2fs", v / 1000000000
		else if (v >= 1000000) printf "%.2fms", v / 1000000
		else if (v >= 1000) printf "%.1fµs", v / 1000
		else printf "%.0fns", v
	}'
}

# Format bytes to human-readable.
format_bytes() {
	awk -v b="$1" 'BEGIN {
		v = b + 0
		if (v >= 1048576) printf "%.1fMiB", v / 1048576
		else if (v >= 1024) printf "%.1fKiB", v / 1024
		else printf "%dB", v
	}'
}

# Parse all suites into temp files.
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

all_benchmarks=""
for s in "${available[@]}"; do
	parse_results "$RESULTS_DIR/$s.txt" > "$tmpdir/$s.tsv"
	# Collect all benchmark names.
	all_benchmarks="$all_benchmarks$(cut -f1 "$tmpdir/$s.tsv")
"
done

# Get unique sorted benchmark names.
sorted_benchmarks=$(echo "$all_benchmarks" | sort -u | grep -v '^$')

# Group benchmarks by category.
categories="JWT JWS JWE JWK"

for cat in $categories; do
	cat_benchmarks=$(echo "$sorted_benchmarks" | grep "^${cat}_" || true)
	if [[ -z "$cat_benchmarks" ]]; then
		continue
	fi

	echo "### $cat"
	echo ""

	# Build header.
	header="| Benchmark |"
	separator="| --- |"
	for s in "${available[@]}"; do
		header="$header $s |"
		separator="$separator ---: |"
	done
	echo "$header"
	echo "$separator"

	# Build rows.
	while IFS= read -r bench; do
		row="| \`$bench\` |"
		for s in "${available[@]}"; do
			val=$(grep "^${bench}	" "$tmpdir/$s.tsv" 2>/dev/null || true)
			if [[ -n "$val" ]]; then
				nsop=$(echo "$val" | cut -f2)
				bop=$(echo "$val" | cut -f3)
				allocsop=$(echo "$val" | cut -f4)
				formatted_ns=$(format_ns "$nsop")
				formatted_b=$(format_bytes "$bop")
				row="$row ${formatted_ns} (${formatted_b}, ${allocsop}a) |"
			else
				row="$row — |"
			fi
		done
		echo "$row"
	done <<< "$cat_benchmarks"

	echo ""
done
