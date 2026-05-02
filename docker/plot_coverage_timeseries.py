#!/usr/bin/env python3
"""
Plot coverage timeseries for multiple fuzzers on a single target.

Usage:
    python3 docker/plot_coverage_timeseries.py [--target lcms] [--trials 3] [--out plot.png]

Reads from: out/coverage_ts/<target>/<fuzzer>/trial<N>/coverage_timeseries.csv
Plots mean branch coverage across trials with min/max shading.
"""

import argparse
import csv
import os
from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np

parser = argparse.ArgumentParser()
parser.add_argument("--target", default="lcms")
parser.add_argument("--fuzzers", nargs="+",
                    default=["naive", "cmplog", "value_profile", "value_profile_cmplog"])
parser.add_argument("--trials", type=int, default=3)
parser.add_argument("--results-dir", default="out/coverage_ts")
parser.add_argument("--out", default="out/coverage_ts_plot.png")
args = parser.parse_args()


def read_csv(path):
    """Return list of (time_h, branch_covered)."""
    rows = []
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            time_h = int(row["time_s"]) / 3600
            covered = int(row["branch_covered"])
            rows.append((time_h, covered))
    return rows


# First pass: collect all trial data and find the global max time
all_fuzzer_data = {}  # fuzzer -> list of trial rows
global_max_time = 0

for fuzzer in args.fuzzers:
    trial_data = []
    for trial in range(1, args.trials + 1):
        csv_path = os.path.join(
            args.results_dir, args.target, fuzzer, f"trial{trial}",
            "coverage_timeseries.csv"
        )
        if not os.path.exists(csv_path):
            print(f"  Skipping {fuzzer}/trial{trial}: {csv_path} not found")
            continue
        rows = read_csv(csv_path)
        trial_data.append(rows)
        if rows:
            global_max_time = max(global_max_time, max(t for t, _ in rows))
    if trial_data:
        all_fuzzer_data[fuzzer] = trial_data

# Build a global time axis (union of all time points across all fuzzers)
global_times = sorted(set(
    t for trial_data in all_fuzzer_data.values()
    for trial in trial_data for t, _ in trial
))

# Ensure the axis extends to the global max
if global_times and global_times[-1] < global_max_time:
    global_times.append(global_max_time)

fig, ax = plt.subplots(figsize=(10, 6))

for fuzzer in args.fuzzers:
    if fuzzer not in all_fuzzer_data:
        print(f"  No data for {fuzzer}, skipping")
        continue

    trial_data = all_fuzzer_data[fuzzer]

    # For each trial, step-interpolate onto the global time axis
    matrix = []
    for trial in trial_data:
        trial_dict = dict(trial)
        values = []
        last = 0
        for t in global_times:
            if t in trial_dict:
                last = trial_dict[t]
            values.append(last)
        matrix.append(values)

    matrix = np.array(matrix)
    mean = matrix.mean(axis=0)
    lo = matrix.min(axis=0)
    hi = matrix.max(axis=0)

    ax.plot(global_times, mean, label=fuzzer, linewidth=2)
    ax.fill_between(global_times, lo, hi, alpha=0.15)

ax.set_xlabel("Time (hours)")
ax.set_ylabel("Branches Covered")
ax.set_title(f"Branch Coverage Over Time — {args.target}")
ax.legend()
ax.grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig(args.out, dpi=150)
print(f"Plot saved to {args.out}")
