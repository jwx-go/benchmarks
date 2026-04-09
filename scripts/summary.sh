#!/bin/bash
#
# Generates a markdown summary comparing benchmark results across suites.
# Reads raw go test -bench output from results/<suite>.txt files.
#
# Usage: ./scripts/summary.sh [results-dir] [baseline-suite]
# Env:   BASELINE=<suite-name> overrides auto-detection

set -euo pipefail

RESULTS_DIR="${1:-results}"
BASELINE="${BASELINE:-${2:-}}"
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

# Auto-detect baseline: prefer jwx-v4, fall back to jwx-v3.
if [[ -z "$BASELINE" ]]; then
	if [[ -f "$RESULTS_DIR/jwx-v4.txt" ]]; then
		BASELINE="jwx-v4"
	elif [[ -f "$RESULTS_DIR/jwx-v3.txt" ]]; then
		BASELINE="jwx-v3"
	fi
fi

# Validate baseline.
if [[ -n "$BASELINE" && ! -f "$RESULTS_DIR/$BASELINE.txt" ]]; then
	echo "Warning: baseline '$BASELINE' has no result file, skipping deltas" >&2
	BASELINE=""
fi

# Parse benchmark results: extract median ns/op and B/op for each benchmark.
parse_results() {
	local file="$1"
	awk '
	/^Benchmark/ {
		name = $1
		sub(/-[0-9]+$/, "", name)
		sub(/^Benchmark/, "", name)

		nsop = $3
		bop = ""
		allocsop = ""
		for (i = 4; i <= NF; i++) {
			if ($(i) == "B/op") bop = $(i-1)
			if ($(i) == "allocs/op") allocsop = $(i-1)
		}

		count[name]++
		values[name][count[name]] = nsop
		bvalues[name][count[name]] = bop
		avalues[name][count[name]] = allocsop
	}
	END {
		for (name in count) {
			n = count[name]
			mid = int((n + 1) / 2)

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

format_ns() {
	awk -v ns="$1" 'BEGIN {
		v = ns + 0
		if (v >= 1000000000) printf "%.2fs", v / 1000000000
		else if (v >= 1000000) printf "%.2fms", v / 1000000
		else if (v >= 1000) printf "%.1fµs", v / 1000
		else printf "%.0fns", v
	}'
}

format_bytes() {
	awk -v b="$1" 'BEGIN {
		v = b + 0
		if (v >= 1048576) printf "%.1fMiB", v / 1048576
		else if (v >= 1024) printf "%.1fKiB", v / 1024
		else printf "%dB", v
	}'
}

# Format percentage delta between current and baseline values.
format_pct() {
	awk -v cur="$1" -v base="$2" 'BEGIN {
		c = cur + 0
		b = base + 0
		if (b == 0 || c == 0) { print ""; exit }
		pct = ((c - b) / b) * 100
		if (pct > 0) sign = "+"
		else sign = ""
		if (int(pct) == pct) printf " (%s%d%%)", sign, pct
		else printf " (%s%.1f%%)", sign, pct
	}'
}

# Parse all suites into temp files.
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

all_benchmarks=""
for s in "${available[@]}"; do
	parse_results "$RESULTS_DIR/$s.txt" > "$tmpdir/$s.tsv"
	all_benchmarks="$all_benchmarks$(cut -f1 "$tmpdir/$s.tsv")
"
done

# Resolve baseline data file.
baseline_file=""
if [[ -n "$BASELINE" ]]; then
	baseline_file="$tmpdir/$BASELINE.tsv"
fi

# Get unique sorted benchmark names.
sorted_benchmarks=$(echo "$all_benchmarks" | sort -u | grep -v '^$')

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
		if [[ -n "$BASELINE" && "$s" == "$BASELINE" ]]; then
			header="$header $s (baseline) |"
		else
			header="$header $s |"
		fi
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
				if [[ -n "$baseline_file" && "$s" != "$BASELINE" ]]; then
					base_val=$(grep "^${bench}	" "$baseline_file" 2>/dev/null || true)
					if [[ -n "$base_val" ]]; then
						base_nsop=$(echo "$base_val" | cut -f2)
						base_bop=$(echo "$base_val" | cut -f3)
						base_allocsop=$(echo "$base_val" | cut -f4)
						ns_delta=$(format_pct "$nsop" "$base_nsop")
						b_delta=$(format_pct "$bop" "$base_bop")
						a_delta=$(format_pct "$allocsop" "$base_allocsop")
						row="$row ${formatted_ns}${ns_delta} (${formatted_b}${b_delta}, ${allocsop}a${a_delta}) |"
					else
						row="$row ${formatted_ns} (${formatted_b}, ${allocsop}a) |"
					fi
				else
					row="$row ${formatted_ns} (${formatted_b}, ${allocsop}a) |"
				fi
			else
				row="$row — |"
			fi
		done
		echo "$row"
	done <<< "$cat_benchmarks"

	echo ""
done
