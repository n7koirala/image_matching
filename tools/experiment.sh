#!/bin/bash

# run this script from build/ using
# ../tools/experiment.sh

# iterates over all standard testing datasets in test/
# performs ImageMatching experiment upon each one

# it takes much much longer for OpenFHE to rewrite over existing serial files than to write new ones
# therefore we remove old serializations after every experiment
if [[ -e "serial/" && -d "serial/" ]]; then
    rm -r serial/
fi

for dataset in ../test/2^*.dat; do
    if [[ -e "$dataset" && "$dataset" != "../test/2^20.dat" ]]; then
        for alg in 1 2 3; do
            # echo "./ImageMatching $dataset $alg > output/out.txt"
            ./ImageMatching "$dataset" "$alg" > output/out.txt
            rm -r serial/
        done
    fi
done

exit 0