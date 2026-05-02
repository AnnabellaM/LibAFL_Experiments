#!/bin/bash
set -euo pipefail
CORPUS_DIR="${1:-/corpus}"
OUT_DIR="${2:-/cov_out}"
BATCH_SIZE="${BATCH_SIZE:-500}"

mkdir -p "${OUT_DIR}/profraw"

# Collect all non-hidden corpus files
files=()
for f in "${CORPUS_DIR}"/*; do
    [ -f "$f" ] || continue
    [[ "$(basename "$f")" == .* ]] && continue
    files+=("$f")
done

count=${#files[@]}
echo "Processing $count inputs (batch size ${BATCH_SIZE})..."

if [ "$count" -eq 0 ]; then
    echo "Warning: no inputs found in ${CORPUS_DIR}" >&2
    exit 1
fi

# Run in batches: each batch is one process invocation covering BATCH_SIZE files.
# This avoids ARG_MAX limits and per-process fork/exec overhead.
batch=0
i=0
while [ "$i" -lt "$count" ]; do
    batch_files=("${files[@]:$i:$BATCH_SIZE}")
    export LLVM_PROFILE_FILE="${OUT_DIR}/profraw/${batch}.profraw"
    "${FUZZ_BIN}" "${batch_files[@]}" >/dev/null 2>&1 || true
    i=$((i + BATCH_SIZE))
    batch=$((batch + 1))
done

echo "Ran $batch batches, merging profiles..."

llvm-profdata-18 merge -sparse "${OUT_DIR}/profraw"/*.profraw \
    -o "${OUT_DIR}/merged.profdata"

llvm-cov-18 report "${FUZZ_BIN}" \
    -instr-profile="${OUT_DIR}/merged.profdata" \
    --show-branch-summary \
    > "${OUT_DIR}/branch_coverage_summary.txt"

llvm-cov-18 show "${FUZZ_BIN}" \
    -instr-profile="${OUT_DIR}/merged.profdata" \
    -show-branches=count \
    -show-line-counts \
    -format=text \
    > "${OUT_DIR}/branch_coverage_show.txt"

echo "Summary report:  ${OUT_DIR}/branch_coverage_summary.txt"
echo "Detailed report: ${OUT_DIR}/branch_coverage_show.txt"
