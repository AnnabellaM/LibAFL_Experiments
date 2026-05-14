#!/usr/bin/env python3
"""
Time-series coverage entrypoint.

Reads LibAFL corpus metadata to extract per-input timestamps (elapsed_ms),
then replays inputs in chronological order and records branch coverage at
regular checkpoints.  Outputs two CSVs:

    coverage_timeseries.csv     — time_s, branch_covered, branch_total

Usage (inside container):
    python3 /run_coverage_timeseries.py /corpus /cov_out [interval_min]

Environment variables:
    FUZZ_BIN         path to instrumented fuzz target (required)
    BATCH_SIZE       max files per binary invocation (default 500)
"""

import csv
import json
import os
import shutil
import subprocess
import sys

CORPUS_DIR = sys.argv[1] if len(sys.argv) > 1 else "/corpus"
OUT_DIR    = sys.argv[2] if len(sys.argv) > 2 else "/cov_out"
INTERVAL_MIN = int(sys.argv[3]) if len(sys.argv) > 3 else 30

FUZZ_BIN   = os.environ["FUZZ_BIN"]
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "500"))

os.makedirs(OUT_DIR, exist_ok=True)
profraw_dir = os.path.join(OUT_DIR, "profraw_ts")
os.makedirs(profraw_dir, exist_ok=True)

# Clean stale profdata from any previous run so coverage accumulates from scratch
_stale = os.path.join(profraw_dir, "running.profdata")
if os.path.exists(_stale):
    os.remove(_stale)


# ── helpers ──────────────────────────────────────────────────────────────────

def get_elapsed_ms(meta_path: str):
    """Return elapsed_ms recorded in a LibAFL .metadata file, or None."""
    try:
        with open(meta_path) as f:
            meta = json.load(f)
        for val in meta.get("metadata", {}).get("map", {}).values():
            if isinstance(val, list) and len(val) == 2 and isinstance(val[1], dict):
                e = val[1].get("elapsed_ms")
                if e is not None:
                    return int(e)
    except Exception:
        pass
    return None


def run_binary(files: list[str], profraw_out: str) -> None:
    """Run the instrumented binary on `files`, writing a profraw."""
    env = os.environ.copy()
    env["LLVM_PROFILE_FILE"] = profraw_out
    for i in range(0, len(files), BATCH_SIZE):
        batch = files[i : i + BATCH_SIZE]
        subprocess.run(
            [FUZZ_BIN] + batch,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def merge_into_running(new_profraw: str, running: str) -> None:
    """Merge new_profraw into the running accumulated profdata."""
    inputs = [new_profraw]
    if os.path.exists(running):
        inputs.append(running)
    subprocess.run(
        ["llvm-profdata-18", "merge", "-sparse"] + inputs + ["-o", running],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def get_branch_coverage(running: str, report_dir: str = None):
    """Run llvm-cov report and return (branch_covered, branch_total) or (None, None).
    If report_dir is given, save full summary and show reports there."""
    r = subprocess.run(
        ["llvm-cov-18", "report", FUZZ_BIN,
         f"-instr-profile={running}", "--show-branch-summary"],
        capture_output=True, text=True,
    )

    if report_dir is not None:
        os.makedirs(report_dir, exist_ok=True)
        with open(os.path.join(report_dir, "branch_coverage_summary.txt"), "w") as f:
            f.write(r.stdout)
        # Snapshot the profdata so `llvm-cov show` can be rendered later on demand,
        # without paying the per-checkpoint show cost during replay.
        shutil.copyfile(running, os.path.join(report_dir, "running.profdata"))

    for line in reversed(r.stdout.splitlines()):
        if line.startswith("TOTAL"):
            parts = line.split()
            try:
                total   = int(parts[-3])
                missed  = int(parts[-2])
                covered = total - missed
                return covered, total
            except (IndexError, ValueError):
                pass
    return None, None


# ── main ─────────────────────────────────────────────────────────────────────

# 1. Collect all corpus inputs with timestamps
inputs = []  # (elapsed_ms, filepath)
for fname in os.listdir(CORPUS_DIR):
    if fname.startswith("."):
        continue
    fpath = os.path.join(CORPUS_DIR, fname)
    if not os.path.isfile(fpath):
        continue
    meta_path = os.path.join(CORPUS_DIR, f".{fname}.metadata")
    elapsed = get_elapsed_ms(meta_path) if os.path.exists(meta_path) else None
    inputs.append((elapsed if elapsed is not None else 0, fpath))

inputs.sort()
if not inputs:
    print("No inputs found.", file=sys.stderr)
    sys.exit(1)

max_elapsed_ms = inputs[-1][0]
print(f"Found {len(inputs)} inputs, max elapsed: {max_elapsed_ms/3600000:.2f}h")

# 2. Build checkpoint list
interval_ms  = INTERVAL_MIN * 60 * 1000
checkpoints  = list(range(interval_ms, max_elapsed_ms + interval_ms, interval_ms))

# 3. Replay in checkpoint windows (incremental)
running = os.path.join(profraw_dir, "running.profdata")
results = []          # (time_s, covered, total)

prev_idx   = 0
batch_num  = 0
have_data  = False

for cp_ms in checkpoints:
    # Gather files discovered in this window
    window_files = []
    while prev_idx < len(inputs) and inputs[prev_idx][0] <= cp_ms:
        window_files.append(inputs[prev_idx][1])
        prev_idx += 1

    if window_files:
        profraw_out = os.path.join(profraw_dir, f"batch_{batch_num}.profraw")
        print(f"  t={cp_ms/3600000:.2f}h: +{len(window_files)} inputs", flush=True)
        run_binary(window_files, profraw_out)
        merge_into_running(profraw_out, running)
        os.remove(profraw_out)
        batch_num += 1
        have_data = True

    if have_data:
        time_s = cp_ms // 1000
        report_dir = os.path.join(OUT_DIR, "reports", str(time_s))

        covered, total = get_branch_coverage(running, report_dir)
        if covered is not None:
            results.append((time_s, covered, total))
            pct = 100 * covered / total if total else 0
            print(f"    branch coverage: {covered}/{total} = {pct:.2f}%", flush=True)

# 4. Write CSV
csv_path = os.path.join(OUT_DIR, "coverage_timeseries.csv")
with open(csv_path, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["time_s", "branch_covered", "branch_total"])
    w.writerows(results)
print(f"\nTimeseries written to {csv_path}")
