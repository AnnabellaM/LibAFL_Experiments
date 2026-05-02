#!/usr/bin/env bash
# run_coverage_timeseries.sh — generate time-series branch coverage reports
#
# Usage:
#   ./docker/run_coverage_timeseries.sh [--targets "a b c"] [--fuzzers "x y"] [--trials N] [--interval 30]
#
# Output:
#   ./out/coverage_ts/<target>/<fuzzer>/trial<N>/coverage_timeseries.csv

set -euo pipefail

TARGETS="bloaty lcms libpcap mbedtls sqlite3"
FUZZERS="naive cmplog value_profile value_profile_cmplog"
TRIALS=3
INTERVAL_MIN=30
RESULTS_DIR="$(pwd)/out"
COV_DIR="${RESULTS_DIR}/coverage_ts"

while [[ $# -gt 0 ]]; do
    case $1 in
        --targets)  TARGETS="$2";      shift 2 ;;
        --fuzzers)  FUZZERS="$2";      shift 2 ;;
        --trials)   TRIALS="$2";       shift 2 ;;
        --interval) INTERVAL_MIN="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ── step 1: build coverage base image ────────────────────────────────────────
echo "==> Building coverage base image..."
docker build -f docker/Dockerfile.coverage-base -t libafl-coverage-base .

# ── step 2: build per-target coverage images ──────────────────────────────────
failed_builds=()
for target in $TARGETS; do
    echo "==> Building coverage image for ${target}..."
    if ! docker build \
        -f "docker/targets/Dockerfile.${target}.cov" \
        -t "libafl-${target}-cov" \
        .; then
        echo "!!! Coverage build failed for ${target}, skipping."
        failed_builds+=("${target}")
    fi
done

# ── step 3: run timeseries coverage for each (target, fuzzer, trial) ──────────
for target in $TARGETS; do
    if [[ " ${failed_builds[*]} " == *" ${target} "* ]]; then
        continue
    fi

    for fuzzer in $FUZZERS; do
        for trial in $(seq 1 "$TRIALS"); do
            corpus="${RESULTS_DIR}/${target}/${fuzzer}/trial${trial}/queue"
            out_dir="${COV_DIR}/${target}/${fuzzer}/trial${trial}"

            if [ ! -d "${corpus}" ]; then
                echo "  Skipping ${target}/${fuzzer}/trial${trial}: no queue dir"
                continue
            fi

            mkdir -p "${out_dir}"
            echo "==> Timeseries: ${target}/${fuzzer}/trial${trial} (interval=${INTERVAL_MIN}min)..."

            docker run --rm \
                -v "${corpus}:/corpus:ro" \
                -v "${out_dir}:/cov_out" \
                --entrypoint python3 \
                "libafl-${target}-cov" \
                /run_coverage_timeseries.py /corpus /cov_out "${INTERVAL_MIN}"
        done
    done
done

echo ""
echo "==> Done. Reports under ${COV_DIR}/"
done
