#!/usr/bin/env bash
# Launch-only variant of run_experiments_batch2.sh — skips image build steps since
# all per-target images have been pre-built. Use when apt mirrors are flaky.
set -euo pipefail

TRIALS=3
DURATION=${DURATION:-43200}
FUZZERS="weighted rand_scheduler cov_accounting minimizer"
TARGETS="bloaty lcms libpcap sqlite3 mbedtls"
RESULTS_DIR="$(pwd)/out"
SEEDS_DIR="$(pwd)/docker/seeds"

while [[ $# -gt 0 ]]; do
    case $1 in
        --trials)      TRIALS="$2";      shift 2 ;;
        --duration)    DURATION="$2";    shift 2 ;;
        --fuzzers)     FUZZERS="$2";     shift 2 ;;
        --targets)     TARGETS="$2";     shift 2 ;;
        --results-dir) RESULTS_DIR="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

mkdir -p "$RESULTS_DIR"

cpu=0
pids=()

for target in $TARGETS; do
    for fuzzer in $FUZZERS; do
        for trial in $(seq 1 "$TRIALS"); do
            image="libafl-${target}-${fuzzer}"
            name="${target}-${fuzzer}-trial${trial}"
            corpus="${RESULTS_DIR}/${target}/${fuzzer}/trial${trial}"
            seeds="${SEEDS_DIR}/${target}"
            mkdir -p "$corpus"

            if ! docker image inspect "$image" >/dev/null 2>&1; then
                echo "!! SKIP ${name}: image ${image} missing"
                (( cpu++ )) || true
                continue
            fi

            # Remove stale container with this name
            docker rm -f "${name}" >/dev/null 2>&1 || true

            seed_vol=()
            if [ -d "${seeds}" ] && [ -n "$(ls -A "${seeds}" 2>/dev/null)" ]; then
                seed_vol=(-v "${seeds}:/seeds:ro")
            fi

            # libpcap needs more memory due to power-schedule metadata +
            # target-resident state; other targets work fine at 4g (matches
            # April 15 baseline).
            mem_limit="4g"
            if [ "$target" = "libpcap" ]; then
                mem_limit="12g"
            fi

            echo "==> Starting ${name} on CPU ${cpu} (mem=${mem_limit})..."
            cid=$(docker run -d \
                --name "${name}" \
                --cpuset-cpus "${cpu}" \
                --memory "${mem_limit}" \
                -v "${corpus}:/corpus" \
                "${seed_vol[@]}" \
                -e DURATION="${DURATION}" \
                "${image}")
            docker logs -f "${cid}" 2>&1 | tee "${RESULTS_DIR}/${name}.log" >/dev/null &
            pids+=($!)
            (( cpu++ )) || true
        done
    done
done

echo ""
echo "==> Launched $((cpu)) containers. DURATION=${DURATION}s"
echo "==> Running containers:"
docker ps --filter "name=trial" --format "table {{.Names}}\t{{.Status}}" | head -20
echo "..."
echo ""
echo "To follow a specific log: tail -f ${RESULTS_DIR}/<target>-<fuzzer>-trial<N>.log"
echo "To stop all: docker ps -q --filter name=trial | xargs docker stop"
