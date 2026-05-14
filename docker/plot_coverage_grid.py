#!/usr/bin/env python3
"""
Plot coverage timeseries for all targets as one figure with subplots.

Usage:
    python3 docker/plot_coverage_grid.py [--targets a b c] [--trials 10] [--out grid.png]
"""

import argparse
import csv
import math
import os

import matplotlib.pyplot as plt
import numpy as np

parser = argparse.ArgumentParser()
parser.add_argument("--targets", nargs="+",
                    default=["curl", "harfbuzz", "jsoncpp", "libpng",
                             "libxml2", "openthread", "woff2"])
parser.add_argument("--fuzzers", nargs="+",
                    default=["naive", "cmplog", "value_profile", "value_profile_cmplog"])
parser.add_argument("--trials", type=int, default=10)
parser.add_argument("--results-dir", default="out/coverage_ts")
parser.add_argument("--out", default="out/coverage_grid.png")
parser.add_argument("--cols", type=int, default=4)
args = parser.parse_args()


def read_csv(path):
    rows = []
    with open(path) as f:
        for row in csv.DictReader(f):
            rows.append((int(row["time_s"]) / 3600, int(row["branch_covered"])))
    return rows


def load_target(target):
    fuzzer_data = {}
    max_time = 0
    for fuzzer in args.fuzzers:
        trials = []
        for trial in range(1, args.trials + 1):
            p = os.path.join(args.results_dir, target, fuzzer,
                             f"trial{trial}", "coverage_timeseries.csv")
            if not os.path.exists(p):
                continue
            rows = read_csv(p)
            trials.append(rows)
            if rows:
                max_time = max(max_time, max(t for t, _ in rows))
        if trials:
            fuzzer_data[fuzzer] = trials
    return fuzzer_data, max_time


# Color per fuzzer, consistent across panels
fuzzer_colors = {
    "naive":                "#1f77b4",
    "cmplog":               "#ff7f0e",
    "value_profile":        "#2ca02c",
    "value_profile_cmplog": "#d62728",
}

n = len(args.targets)
cols = args.cols
rows = math.ceil(n / cols)

fig, axes = plt.subplots(rows, cols, figsize=(4.5 * cols, 3.5 * rows),
                         squeeze=False)

for idx, target in enumerate(args.targets):
    ax = axes[idx // cols][idx % cols]
    fuzzer_data, max_time = load_target(target)

    if not fuzzer_data:
        ax.text(0.5, 0.5, f"no data\n{target}",
                ha="center", va="center", transform=ax.transAxes)
        ax.set_title(target)
        continue

    global_times = sorted(set(
        t for trials in fuzzer_data.values() for trial in trials for t, _ in trial
    ))
    if global_times and global_times[-1] < max_time:
        global_times.append(max_time)

    for fuzzer in args.fuzzers:
        if fuzzer not in fuzzer_data:
            continue
        matrix = []
        for trial in fuzzer_data[fuzzer]:
            d = dict(trial)
            last = 0
            row = []
            for t in global_times:
                if t in d:
                    last = d[t]
                row.append(last)
            matrix.append(row)
        matrix = np.array(matrix)
        c = fuzzer_colors.get(fuzzer)
        ax.plot(global_times, matrix.mean(axis=0), label=fuzzer,
                linewidth=2, color=c)
        ax.fill_between(global_times, matrix.min(axis=0), matrix.max(axis=0),
                        alpha=0.15, color=c)

    ax.set_title(target)
    ax.set_xlabel("Time (h)")
    ax.set_ylabel("Branches covered")
    ax.grid(True, alpha=0.3)

# Hide unused panels
for idx in range(n, rows * cols):
    axes[idx // cols][idx % cols].set_visible(False)

# Single legend at the figure level
handles, labels = [], []
for ax_row in axes:
    for ax in ax_row:
        if ax.get_visible():
            h, l = ax.get_legend_handles_labels()
            for hh, ll in zip(h, l):
                if ll not in labels:
                    handles.append(hh)
                    labels.append(ll)
            if handles:
                break
    if handles:
        break
fig.legend(handles, labels, loc="lower center", ncol=len(labels),
           bbox_to_anchor=(0.5, -0.02))

fig.suptitle("Branch coverage over time — all targets", fontsize=14)
plt.tight_layout(rect=[0, 0.03, 1, 0.97])
plt.savefig(args.out, dpi=150, bbox_inches="tight")
print(f"Plot saved to {args.out}")
