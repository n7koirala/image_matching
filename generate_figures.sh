#!/usr/bin/env bash
set -euo pipefail

echo ">>> Generating all figures present in the manuscript..."

# List of Python scripts to execute in order
SCRIPTS=(
  "tools/figures/idBandwidth.py"
  "tools/figures/idScalability.py"
  "tools/figures/memBandwidth.py"
  "tools/figures/memScalability.py"
  "tools/figures/signApproxAll.py"
)

LOG_ROOT="logs"           # top‑level log directory
mkdir -p "$LOG_ROOT"      # make sure it exists

FIGURES="/tmp/manuscript_figures"
mkdir -p "$FIGURES"     # make sure it exists

echo "Saving manuscript figures to: $FIGURES"
echo ""

for script in "${SCRIPTS[@]}"; do
    if [[ -f "$script" ]]; then
        echo ">>> Running $script"

        # Build log path that mirrors the script path, but with .log extension
        log_path="$LOG_ROOT/${script%.py}.log"

        # Create parent directories (e.g., logs/tools/figures/)
        mkdir -p "$(dirname "$log_path")"

        # Run the script; all stdout/stderr go into log & console
        python3 "$script" 2>&1 | tee "$log_path"
    else
        echo "!!! $script not found – skipping."
    fi
done

echo ""
echo ">>> All figures generated and are located inside $FIGURES"
