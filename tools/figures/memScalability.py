#!/usr/bin/env python3

import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

# Read data from CSV file
df1 = pd.read_csv("approach1.csv")
df2 = pd.read_csv("approach2.csv")
df3 = pd.read_csv("approach3.csv")
df4 = pd.read_csv("approach4.csv")
df5 = pd.read_csv("approach5.csv")

# Extract columns
db = df1["Database size"].values

# Define x-ticks with powers of 2 up to 2^20
x_ticks = [2**i for i in range(10, 21)]  # 2^10 to 2^20

# Create figure and axis
fig, ax = plt.subplots(figsize=(8, 5))

# Plotting
ax.plot(db, df1["Average Membership Computation (seconds)"].values, marker='o', linestyle='-', label='Baseline')
ax.plot(db, df2["Average Membership Computation (seconds)"].values, marker='s', linestyle='--', label='GROTE')
ax.plot(db, df3["Average Membership Computation (seconds)"].values, marker='*', linestyle='-', label='Blind-Match')
ax.plot(db, df4["Average Membership Computation (seconds)"].values, marker='^', linestyle='--', label='HERS')
ax.plot(db, df5["Average Membership Computation (seconds)"].values, marker='v', linestyle='-', label='Ours')

# Formatting
ax.set_xscale('log', base=2)
ax.set_yscale('log')
ax.set_xticks(x_ticks)
ax.set_xticklabels([f"$2^{{{int(np.log2(x))}}}$" for x in x_ticks])  # Proper exponent notation
ax.set_xlabel("Database Size", fontsize=18)
ax.set_ylabel("Server Computation Time (seconds)", fontsize=18)
ax.set_title("Membership Scenario\nServer Overhead", fontsize=18)
ax.grid(True, which="both", linestyle="--", linewidth=0.5)
ax.legend(fontsize=14)

plt.tick_params(axis='both', labelsize=16)

# Save as PDF
pdf_filename = "membershipScalabilityLarge.pdf"
fig.savefig(pdf_filename, format="pdf", dpi=300, bbox_inches="tight")

# Show plot
plt.show()