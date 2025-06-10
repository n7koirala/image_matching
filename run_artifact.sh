#!/usr/bin/env bash
set -euxo pipefail
cd /opt/image_matching/build

echo ">>> Running smoke test on dataset with 1024 facial templates for all 5 techniques ..."
echo "Technique 1: Baseline approach"
./ImageMatching ../test/2_10.dat 1  # baseline approach
echo "Baseline approach test completed."

echo ""
echo "Technique 2: GROTE approach"
./ImageMatching ../test/2_10.dat 2  # GROTE approach
echo "GROTE approach test completed."

echo ""
echo "Technique 3: Blind-Match approach"
./ImageMatching ../test/2_10.dat 3  # Blind-Match approach
echo "Blind-Match approach test completed."

echo ""
echo "Technique 4: HERS approach"
./ImageMatching ../test/2_10.dat 4  # HERS approach
echo "HERS approach test completed."

echo ""
echo "Technique 5: HyDia (ours) approach"
./ImageMatching ../test/2_10.dat 5  # HyDia approach
echo "Hydia (ours) approach test completed."

# ./ImageMatchingAccuracy 0 5         # Accuracy experiment   

echo ">>> Finished OK.  For full experiments run:"
echo "    docker run --rm -it popets2025-hydia bash"
