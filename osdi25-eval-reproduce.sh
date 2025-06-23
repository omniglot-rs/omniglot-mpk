#! /usr/bin/env nix-shell
#! nix-shell -i bash --pure

set -Eeuo pipefail

echo "========== OSDI'25 Evaluation Reproduction Script =========="
SUDO="$(test -f /usr/bin/sudo && echo "/usr/bin/sudo" || which sudo)"

# Install the cargo-criterion binary to get JSON-formatted benchmark results:
cargo install cargo-criterion || true

# Ensure that we can map the foreign library domain memory:
$SUDO sysctl vm.overcommit_memory=1

# Because we're mapping large amounts of mermory, we don't want to have
# coredumps enabled -- they will take a long time. In the future, we should
# switch to trapping on page faults and dynamically mapping more pages when
# foreign code tries to access them.
$SUDO sysctl kernel.core_pattern='|/bin/false'

# From https://unix.stackexchange.com/a/366655
printarr() { declare -n __p="$1"; for k in "${!__p[@]}"; do printf "%s=%s\n" "$k" "${__p[$k]}" ; done ;  }

declare -A BENCH_RESULTS
declare -A BENCH_RESULTS_EST
declare -A BENCH_RESULTS_UNIT

function run_benchmark() {
	BENCHMARK_LABEL="$1"
	CARGO_BENCH_NAME="$2"
	RESULTS_PREFIX="$3"
	CARGO_CRITERION_FLAGS="$4"
	ALLOW_FAIL="$5"
	CHECKPOINT_JSON="${BENCHMARK_LABEL}_checkpoint.json"
	if [ ! -f "$CHECKPOINT_JSON" ]; then
		OUTPUT_JSON="${BENCHMARK_LABEL}_$(date +%s).json"
		echo "==> Running \"$BENCHMARK_LABEL\" benchmark, saving results to $CHECKPOINT_JSON"
		if [ "$ALLOW_FAIL" == "1" ]; then
			(cargo criterion --bench "$CARGO_BENCH_NAME" --message-format=json $CARGO_CRITERION_FLAGS || true) | tee "$OUTPUT_JSON"
		else
			cargo criterion --bench "$CARGO_BENCH_NAME" --message-format=json $CARGO_CRITERION_FLAGS | tee "$OUTPUT_JSON" 
		fi
		echo "Benchmark complete, saving checkpoint to $CHECKPOINT_JSON"
		cp "$OUTPUT_JSON" "$CHECKPOINT_JSON"
	else
		echo "==> Reusing \"$BENCHMARK_LABEL\" benchmark checkpoint $CHECKPOINT_JSON"
	fi

	# Analyze the $CHECKPOINT_JSON file, parsing all "benchmark-complete" messages and extracting their "typical" runtime:
	while IFS= read -r JSON_LINE; do
		if [ "$(echo "$JSON_LINE" | jq -r .reason)" == "benchmark-complete" ]; then
			BENCH_ID="$(echo "$JSON_LINE" | jq -r .id)"
			BENCH_RES_EST="$(echo "$JSON_LINE" | jq -r .typical.estimate)"
			BENCH_RES_UNIT="$(echo "$JSON_LINE" | jq -r .typical.unit)"
			BENCH_RESULTS_EST["${RESULTS_PREFIX}${BENCH_ID}"]="$BENCH_RES_EST"
			BENCH_RESULTS_UNIT["${RESULTS_PREFIX}${BENCH_ID}"]="$BENCH_RES_UNIT"
			BENCH_RESULTS["${RESULTS_PREFIX}${BENCH_ID}"]="$(printf "%13.3f %s" "$BENCH_RES_EST" "$BENCH_RES_UNIT")"
		fi
	done < "$CHECKPOINT_JSON"
}

run_benchmark "ubench_invoke" "invoke_ubench" "" "" ""
run_benchmark "ubench_setup" "process_startup_demo_nop" "" "" ""
run_benchmark "ubench_validation" "validation_ubench" "" "" ""
run_benchmark "ubench_upgrade" "upgrade_ubench" "" "" ""
run_benchmark "ubench_callback" "callback_ubench" "" "" ""
run_benchmark "brotli_checked" "brotli_compression_comparison" "brotli-checked/" "" ""
run_benchmark "brotli_unchecked" "brotli_compression_comparison" "brotli-unchecked/" \
	"--features disable_upgrade_checks,disable_validation_checks" ""
run_benchmark "sodium_checked" "sodium_hash_comparison" "sodium-checked/" "" ""
run_benchmark "sodium_unchecked" "sodium_hash_comparison" "sodium-unchecked/" \
	"--features disable_upgrade_checks,disable_validation_checks" ""
run_benchmark "libpng_checked" "libpng_decode_comparison" "libpng-checked/" "" "1"
run_benchmark "libpng_unchecked" "libpng_decode_comparison" "libpng-unchecked/" \
	"--features disable_upgrade_checks,disable_validation_checks" "1"

echo
echo
echo "========== RESULTS =========="
echo
printarr BENCH_RESULTS

echo
echo
echo "========= TABLE 3: MICROBENCHMARKS =========="
echo

cat <<EOF
(a)            | Setup                               | Invoke                              |
|              | PMP              | MPK              | PMP              | MPK              |
|------------- +------------------+------------------+------------------+------------------|
| Unsafe       | ???????????????? | ${BENCH_RESULTS["runtime_setup/unsafe"]} | ???????????????? | ${BENCH_RESULTS["ubench_invoke/unsafe/0"]} |
| Omniglot     | ???????????????? | ${BENCH_RESULTS["runtime_setup/og_mpk"]} | ???????????????? | ${BENCH_RESULTS["ubench_invoke/og_mpk/0"]} |
| Sandcrust    | ---------------- | ${BENCH_RESULTS["runtime_setup/sandcrust"]} | ---------------- | ${BENCH_RESULTS["ubench_invoke/sandcrust/0"]} |
| Tock Upcall  | ---------------- | ---------------- | ???????????????? | ---------------- |
EOF

echo
cat <<EOF
(b)            | Upgrade                             | Callback                            |
| allocs / CBs | PMP              | MPK              | PMP              | MPK              |
|--------------+------------------+------------------+------------------+------------------|
|            1 | ???????????????? | ${BENCH_RESULTS["upgrade/1"]} | ???????????????? | ${BENCH_RESULTS["callback/1"]} |
|            8 | ???????????????? | ${BENCH_RESULTS["upgrade/8"]} | ???????????????? | ${BENCH_RESULTS["callback/8"]} |
|           64 | ???????????????? | ${BENCH_RESULTS["upgrade/64"]} | ???????????????? | ${BENCH_RESULTS["callback/64"]} |
EOF

echo
cat <<EOF
| (c) Validate |           64B u8 |           8kB u8 |          64B str |          8kB str |
|--------------+------------------+------------------+------------------+------------------|
|          PMP | ???????????????? | ???????????????? | ???????????????? | ???????????????? |
|          MPK | ${BENCH_RESULTS["validation/u8/64"]} | ${BENCH_RESULTS["validation/u8/8224"]} | ${BENCH_RESULTS["validation/str/64"]} | ${BENCH_RESULTS["validation/str/8224"]} |
EOF

echo
echo
echo "========= TABLE 2: LIBRARY EVALUATIONS =========="
echo
function compute_overhead() {
	RAW_PERCENTAGE="$(echo "scale=12; ((${1} / ${2}) - 1) * 100" | bc)"
	TRIMMED="$(printf "(+%.3f%%)" "$RAW_PERCENTAGE")"
	PADDED="$(printf "%-12s" "$TRIMMED")"
	echo "$PADDED"
}

BROTLI_UNSAFE="${BENCH_RESULTS["brotli-unchecked/brotli_compress_decompress/unsafe/1024"]}"
BROTLI_ISOLATION="${BENCH_RESULTS["brotli-unchecked/brotli_compress_decompress/og_mpk/1024"]}"
BROTLI_OMNIGLOT="${BENCH_RESULTS["brotli-checked/brotli_compress_decompress/og_mpk/1024"]}"
BROTLI_ISOLATION_OVERHEAD="$(\
	compute_overhead \
		"${BENCH_RESULTS_EST["brotli-unchecked/brotli_compress_decompress/og_mpk/1024"]}" \
		"${BENCH_RESULTS_EST["brotli-unchecked/brotli_compress_decompress/unsafe/1024"]}")"
BROTLI_OMNIGLOT_OVERHEAD="$(\
	compute_overhead \
		"${BENCH_RESULTS_EST["brotli-checked/brotli_compress_decompress/og_mpk/1024"]}" \
		"${BENCH_RESULTS_EST["brotli-unchecked/brotli_compress_decompress/og_mpk/1024"]}")"

SODIUM_UNSAFE="${BENCH_RESULTS["sodium-unchecked/libsodium_hash/unsafe/32768"]}"
SODIUM_ISOLATION="${BENCH_RESULTS["sodium-unchecked/libsodium_hash/og_mpk/32768"]}"
SODIUM_OMNIGLOT="${BENCH_RESULTS["sodium-checked/libsodium_hash/og_mpk/32768"]}"
SODIUM_ISOLATION_OVERHEAD="$(\
	compute_overhead \
		"${BENCH_RESULTS_EST["sodium-unchecked/libsodium_hash/og_mpk/32768"]}" \
		"${BENCH_RESULTS_EST["sodium-unchecked/libsodium_hash/unsafe/32768"]}")"
SODIUM_OMNIGLOT_OVERHEAD="$(\
	compute_overhead \
		"${BENCH_RESULTS_EST["sodium-checked/libsodium_hash/og_mpk/32768"]}" \
		"${BENCH_RESULTS_EST["sodium-unchecked/libsodium_hash/og_mpk/32768"]}")"

LIBPNG_UNSAFE="${BENCH_RESULTS["libpng-unchecked/libpng_decode/unsafe/big_building_001.0p.png"]}"
LIBPNG_ISOLATION="${BENCH_RESULTS["libpng-unchecked/libpng_decode/og_mpk/big_building_001.0p.png"]}"
LIBPNG_OMNIGLOT="${BENCH_RESULTS["libpng-checked/libpng_decode/og_mpk/big_building_001.0p.png"]}"
LIBPNG_ISOLATION_OVERHEAD="$(\
	compute_overhead \
		"${BENCH_RESULTS_EST["libpng-unchecked/libpng_decode/og_mpk/big_building_001.0p.png"]}" \
		"${BENCH_RESULTS_EST["libpng-unchecked/libpng_decode/unsafe/big_building_001.0p.png"]}")"
LIBPNG_OMNIGLOT_OVERHEAD="$(\
	compute_overhead \
		"${BENCH_RESULTS_EST["libpng-checked/libpng_decode/og_mpk/big_building_001.0p.png"]}" \
		"${BENCH_RESULTS_EST["libpng-unchecked/libpng_decode/og_mpk/big_building_001.0p.png"]}")"

cat <<EOF
| Library   | RT  |    unsafe        |          isolation only       |            Omniglot           |
|-----------+-----+------------------+-------------------------------+-------------------------------|
| Brotli    | MPK | ${BROTLI_UNSAFE} | ${BROTLI_ISOLATION} ${BROTLI_ISOLATION_OVERHEAD} | ${BROTLI_OMNIGLOT} ${BROTLI_OMNIGLOT_OVERHEAD} |
| libsodium | MPK | ${SODIUM_UNSAFE} | ${SODIUM_ISOLATION} ${SODIUM_ISOLATION_OVERHEAD} | ${SODIUM_OMNIGLOT} ${SODIUM_OMNIGLOT_OVERHEAD} |
| libpng    | MPK | ${LIBPNG_UNSAFE} | ${LIBPNG_ISOLATION} ${LIBPNG_ISOLATION_OVERHEAD} | ${LIBPNG_OMNIGLOT} ${LIBPNG_OMNIGLOT_OVERHEAD} |
EOF

echo
echo
echo "========= FIGURE 5: libpng Sandcrust vs. Omniglot =========="
echo
./generate-libpng-sandcrust-omniglot-comparison-plot.py libpng_omniglot_sandcrust_comparison libpng_checked_checkpoint.json

