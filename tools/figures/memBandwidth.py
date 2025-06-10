#!/usr/bin/env python3

import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

# Read data from CSV file
dfMem = pd.read_csv("./tools/figures/15MembershipTotals.csv")
dfId = pd.read_csv("./tools/figures/15IndexTotals.csv")

# Extract columns
network = dfMem["Network"].values
bandwidths = ["64Kbps", "2Mbps", "1Gbps", "20Gbps"]

# Define x-ticks with powers of 2 up to 2^20
# x_ticks = [2**i for i in range(10, 21)]  # 2^10 to 2^20

# Create figure and axis
fig, ax = plt.subplots(figsize=(8, 5))

# Plotting
ax.plot(network, dfMem["Baseline"].values, marker='o', linestyle='-', label='Baseline')
ax.plot(network, dfMem["GROTE"].values, marker='s', linestyle='--', label='GROTE')
ax.plot(network, dfMem["Blind-Match"].values, marker='*', linestyle='-', label='Blind-Match')
ax.plot(network, dfMem["HERS"].values, marker='^', linestyle='--', label='HERS')
ax.plot(network, dfMem["Ours"].values, marker='v', linestyle='-', label='Ours')

# Formatting
#ax.set_xscale('log', base=2)
ax.set_yscale('log')
ax.set_xticklabels(bandwidths)  # Proper exponent notation
ax.set_xlabel("Network Bandwidth", fontsize=18)
ax.set_ylabel("End-To-End Query Time (seconds)", fontsize=18)
ax.set_title("Membership Scenario End-to-End Overhead\nover $2^{15}$ Database Subjects", fontsize=18)
ax.grid(True, which="both", linestyle="--", linewidth=0.5)
ax.legend(fontsize=16)

plt.tick_params(axis='both', labelsize=16)

# Save as PDF
pdf_filename = "/tmp/manuscript_figures/membershipBandwidthLarge.pdf"
fig.savefig(pdf_filename, format="pdf", dpi=300, bbox_inches="tight")

# Show plot
# plt.show()
# pdf_filename