#!/usr/bin/env python3

import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

# Read data from CSV file
df = pd.read_csv("./tools/figures/signApprox.csv")

# Extract columns
db = df["input"].values

# Define x-ticks with powers of 2 up to 2^20
#x_ticks = [2**i for i in range(10, 21)]  # 2^10 to 2^20

# Create figure and axis
fig, ax = plt.subplots(figsize=(6, 3))

# Plotting

ax.plot(db, (df["cheon"]+1).values, linestyle='-', label='Cheon et al.')
ax.plot(db, (df["chebyshev"]+1).values, linestyle='-', label='Chebyshev')
ax.plot(db, df["combined"].values, linestyle='-', label='Ours')

# Formatting
ax.legend(fontsize=10)

# Remove top and right borders
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['bottom'].set_position(('data', 0))
ax.spines['left'].set_position(('data', 0))

ax.spines['left'].set_bounds(0, 2)
ax.spines['bottom'].set_bounds(-1, 1)
ax.margins(y=0)

# Set axis limits
ax.set_xlim(-1.1, 1.1)
ax.set_ylim(-0.5, 2.5)

# Set custom tick marks
ax.set_xticks([-1.0, -0.5, 0.0, 0.5, 1.0])
ax.set_yticks([0.5, 1.0, 1.5, 2.0])

# Save as PDF
pdf_filename = "/tmp/manuscript_figures/signApproxAll.pdf"
fig.savefig(pdf_filename, format="pdf", dpi=300, bbox_inches="tight")

# Show plot
# plt.show()