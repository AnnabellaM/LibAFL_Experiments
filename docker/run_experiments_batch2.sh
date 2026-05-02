#!/usr/bin/env bash
# run_experiments_batch2.sh — second batch: seed-scheduling fuzzers
#
# Runs (fuzzer × target × trial) experiments for fuzzers that vary the
# corpus scheduler (weighted / rand_scheduler / cov_accounting). Mirrors
# run_experiments.sh but writes to a separate results directory so it
# won't collide with batch 1 (Section 5.1 roadblock bypass).
#
# Usage:
#   ./docker/run_experiments_batch2.sh
#   ./docker/run_experiments_batch2.sh --trials 5 --duration 86400
#
# Defaults match the batch-1 Section 5.1 setup:
#   --fuzzers "weighted rand_scheduler cov_accounting"
#   --targets "bloaty lcms libpcap sqlite3 mbedtls"
#   --trials 3  --duration 86400

set -euo pipefail

# ── defaults ────────────────────────────────────────────────────────────────
TRIALS=3
DURATION=86400        # 24 hours
FUZZERS="weighted rand_scheduler cov_accounting minimizer"
TARGETS="bloaty lcms libpcap sqlite3 mbedtls"
RESULTS_DIR="$(pwd)/out"
SEEDS_DIR="$(pwd)/docker/seeds"

# ── arg parsing ─────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --trials)       TRIALS="$2";       shift 2 ;;
        --duration)     DURATION="$2";     shift 2 ;;
        --fuzzers)      FUZZERS="$2";      shift 2 ;;
        --targets)      TARGETS="$2";      shift 2 ;;
        --results-dir)  RESULTS_DIR="$2";  shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

mkdir -p "$RESULTS_DIR"

# ── step 1: build base image ─────────────────────────────────────────────────
echo "==> Building base image (libafl-base)..."
docker build \
    -f docker/Dockerfile.base \
    -t libafl-base \
    .

# ── step 2: build per-(fuzzer, target) images ────────────────────────────────
failed_builds=()
for target in $TARGETS; do
    for fuzzer in $FUZZERS; do
        image="libafl-${target}-${fuzzer}"
        echo "==> Building ${image}..."
        if ! docker build \
            --build-arg FUZZER="${fuzzer}" \
            -f "docker/targets/Dockerfile.${target}" \
            -t "${image}" \
            .; then
            echo "!!! Build failed for ${image}, skipping."
            failed_builds+=("${image}")
        fi
    done
done

if [[ ${#failed_builds[@]} -gt 0 ]]; then
    echo ""
    echo "==> The following images failed to build and will be skipped:"
    for img in "${failed_builds[@]}"; do echo "    ${img}"; done
fi

# ── step 3: launch experiments ───────────────────────────────────────────────
cpu=0
pids=()

for target in $TARGETS; do
    for fuzzer in $FUZZERS; do
        for trial in $(seq 1 "$TRIALS"); do
            image="libafl-${target}-${fuzzer}"
            name="${target}-${fuzzer}-trial${trial}"
            corpus="${RESULTS_DIR}/${target}/${fuzzer}/trial${trial}"
            seeds="${SEEDS_DIR}/${target}"

            if [[ " ${failed_builds[*]} " == *" ${image} "* ]]; then
                continue
            fi

            mkdir -p "$corpus"

            echo "==> Starting ${name} on CPU ${cpu}..."
            seed_vol=()
            if [ -d "${seeds}" ] && [ -n "$(ls -A "${seeds}" 2>/dev/null)" ]; then
                seed_vol=(-v "${seeds}:/seeds:ro")
            fi

            cid=$(docker run -d \
                --name "${name}" \
                --cpuset-cpus "${cpu}" \
                --memory "4g" \
                -v "${corpus}:/corpus" \
                "${seed_vol[@]}" \
                -e DURATION="${DURATION}" \
                "${image}")
            docker logs -f "${cid}" 2>&1 | tee "${RESULTS_DIR}/${name}.log" &

            pids+=($!)
            (( cpu++ )) || true
        done
    done
done

echo ""
echo "==> All experiments launched. Containers running:"
docker ps --filter "name=${TARGETS// /|}" --format "table {{.Names}}\t{{.Status}}\t{{.CPUPerc}}"

echo ""
echo "To follow logs:    docker logs -f <container-name>"
echo "To stop all:       docker stop \$(docker ps -q --filter name=libafl)"
echo "Results at:        ${RESULTS_DIR}/"
