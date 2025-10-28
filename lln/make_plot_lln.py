#!/usr/bin/env python3
"""
make_plots_lln.py — Generate plots for the Law of Large Numbers (LLN)

This script simulates m independent Bernoulli trajectories,
each with n trials and success probability p, and produces:
  - lln/output/trajectories.png
  - lln/output/final_histogram.png
  - lln/output/final_freqs.csv
  - lln/output/trajectories_sampled.csv

Usage:
    python make_plots_lln.py
Requirements:
    pip install numpy matplotlib
"""

import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
import csv

# ============================================================
# PARAMETERS  (you can modify them freely)
# ============================================================
p = 0.5          # Probability of success (e.g., fair coin)
m = 50           # Number of independent trajectories
n = 10_000       # Number of trials per trajectory
rng_seed = 42    # Random seed for reproducibility
# ============================================================

# Output folder (matches your HTML paths)
OUT = Path("lln/output")
OUT.mkdir(parents=True, exist_ok=True)

# Set RNG
rng = np.random.default_rng(rng_seed)

# Generate m × n Bernoulli samples
samples = rng.binomial(1, p, size=(m, n))

# Compute cumulative relative frequencies
cumsums = samples.cumsum(axis=1)
k = np.arange(1, n + 1)
freqs = cumsums / k

# ============================================================
# PLOT 1 — Trajectories of cumulative frequencies
# ============================================================
plt.figure(figsize=(11, 5))
for i in range(m):
    plt.plot(k, freqs[i], linewidth=0.9, alpha=0.7)
plt.axhline(y=p, linestyle="--", linewidth=1.2, color="black")
plt.xlabel("Number of trials (k)")
plt.ylabel("Relative frequency f_i(k)")
plt.title("LLN — Convergence of Relative Frequencies (m trajectories)")
plt.tight_layout()
plt.savefig(OUT / "trajectories.png", dpi=160)
plt.close()

# ============================================================
# PLOT 2 — Final histogram of relative frequencies
# ============================================================
final_freqs = freqs[:, -1]
plt.figure(figsize=(8.5, 5.2))
plt.hist(final_freqs, bins=12, edgecolor="black", color="#60a5fa", alpha=0.85)
plt.axvline(x=p, linestyle="--", linewidth=1.2, color="black")
plt.xlabel("Final relative frequency f_i(n)")
plt.ylabel("Count of trajectories")
plt.title(f"Distribution of Final Frequencies at n = {n}")
plt.tight_layout()
plt.savefig(OUT / "final_histogram.png", dpi=160)
plt.close()

# ============================================================
# SAVE RESULTS TO CSV FILES
# ============================================================
# Final frequencies (one per trajectory)
with open(OUT / "final_freqs.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["trajectory", "final_freq"])
    for i, v in enumerate(final_freqs):
        writer.writerow([i, v])

# Downsampled trajectories (for inspection)
step = 50  # every 50th trial
with open(OUT / "trajectories_sampled.csv", "w", newline="") as f:
    writer = csv.writer(f)
    header = ["k"] + [f"traj_{i}" for i in range(m)]
    writer.writerow(header)
    for idx in range(0, n, step):
        row = [idx + 1] + [freqs[i, idx] for i in range(m)]
        writer.writerow(row)

print(f"✅ Files generated in: {OUT.resolve()}")
print(" - trajectories.png")
print(" - final_histogram.png")
print(" - final_freqs.csv")
print(" - trajectories_sampled.csv")
