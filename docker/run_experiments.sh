#!/usr/bin/env bash
# run_experiments.sh — build images and run all (fuzzer × target × trial) experiments
#
# Usage:
#   ./docker/run_experiments.sh [--trials N] [--duration SECONDS] [--fuzzers "a b c"] [--targets "x y"]
#
# Examples:
#   ./docker/run_experiments.sh
#   ./docker/run_experiments.sh --trials 5 --duration 86400 --fuzzers "generic fast cmplog"
#
# Section 5.1 experiment (roadblock bypass):
#   ./docker/run_experiments.sh --trials 5 --duration 86400 \
#       --fuzzers "naive cmplog value_profile value_profile_cmplog" \
#       --targets "bloaty lcms libpcap sqlite3 mbedtls"

set -euo pipefail

# ── defaults ────────────────────────────────────────────────────────────────
TRIALS=3
DURATION=86400        # 24 hours in seconds
FUZZERS="generic fast naive cmplog mopt"
TARGETS="harfbuzz bloaty"
RESULTS_DIR="$(pwd)/out"
SEEDS_DIR="$(pwd)/docker/seeds"
# ── arg parsing ─────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --trials)   TRIALS="$2";   shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --fuzzers)  FUZZERS="$2";  shift 2 ;;
        --targets)  TARGETS="$2";  shift 2 ;;
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
# Assign each container its own CPU core to avoid interference.
cpu=0
pids=()

for target in $TARGETS; do
    for fuzzer in $FUZZERS; do
        for trial in $(seq 1 "$TRIALS"); do
            image="libafl-${target}-${fuzzer}"
            name="${target}-${fuzzer}-trial${trial}"
            corpus="${RESULTS_DIR}/${target}/${fuzzer}/trial${trial}"
            seeds="${SEEDS_DIR}/${target}"

            # Skip if the image failed to build
            if [[ " ${failed_builds[*]} " == *" ${image} "* ]]; then
                continue
            fi

            mkdir -p "$corpus"

            echo "==> Starting ${name} on CPU ${cpu}..."
            # Only mount the seeds volume if the directory exists and is non-empty;
            # otherwise let the container use the seeds embedded in the image.
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
