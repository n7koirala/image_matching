#!/usr/bin/env bash
set -euxo pipefail
cd /opt/image_matching/build

echo ">>> Running smoke test on tiny dataset..."
./ImageMatching ../test/2_10.dat 1  # baseline approach
./ImageMatching ../test/2_10.dat 2  # GROTE approach
./ImageMatching ../test/2_10.dat 3  # Blind-Match approach
./ImageMatching ../test/2_10.dat 4  # HERS approach
./ImageMatching ../test/2_10.dat 5  # HyDia approach

./ImageMatchingAccuracy 0 5         # Accuracy experiment   

echo ">>> Finished OK.  For full experiments run:"
echo "    docker run --rm -it popets2025-hydia bash"
