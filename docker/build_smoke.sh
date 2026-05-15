#!/usr/bin/env bash
# build_smoke.sh — parallel per-target image builder for the smoke test.
#
# Builds libafl-${target}-${fuzzer} for every (target, fuzzer) pair, but
# parallelizes ACROSS fuzzers within each target (they share libafl-base
# and the per-target source clone, so the parallel cost is just the harness
# link + small target-specific work).
#
# Usage: ./docker/build_smoke.sh [--fuzzers "..."] [--targets "..."]
set -euo pipefail

FUZZERS="${FUZZERS:-naive_ngram4 naive_ctx mopt mopt_cmplog grimoire fast}"
TARGETS="${TARGETS:-lcms bloaty sqlite3 mbedtls woff2 libxml2 libpng harfbuzz}"
LOG_DIR="${LOG_DIR:-/tmp/libafl-build-logs}"

while [[ $# -gt 0 ]]; do
    case $1 in
        --fuzzers) FUZZERS="$2"; shift 2 ;;
        --targets) TARGETS="$2"; shift 2 ;;
        --log-dir) LOG_DIR="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

mkdir -p "$LOG_DIR"
declare -a failed=()

for target in $TARGETS; do
    echo "==> Building all fuzzers for target=$target in parallel..."
    pids=()
    names=()
    for fuzzer in $FUZZERS; do
        image="libafl-${target}-${fuzzer}"
        log="${LOG_DIR}/${target}-${fuzzer}.log"
        echo "    -> $image (log: $log)"
        (
            docker build \
                --build-arg FUZZER="${fuzzer}" \
                -f "docker/targets/Dockerfile.${target}" \
                -t "${image}" \
                . > "$log" 2>&1
        ) &
        pids+=($!)
        names+=("$image")
    done

    # Wait for all parallel builds for this target
    i=0
    for pid in "${pids[@]}"; do
        if wait "$pid"; then
            echo "    OK  ${names[$i]}"
        else
            echo "    !!! FAIL ${names[$i]} (see ${LOG_DIR}/${names[$i]#libafl-}.log)"
            failed+=("${names[$i]}")
        fi
        i=$((i + 1))
    done
done

echo ""
echo "==> Build summary"
echo "    Targets:  $TARGETS"
echo "    Fuzzers:  $FUZZERS"
echo "    Failed:   ${#failed[@]}"
for img in "${failed[@]}"; do echo "      - $img"; done

[[ ${#failed[@]} -eq 0 ]]
