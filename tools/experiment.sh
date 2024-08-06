#!/bin/bash

# run this script from build/ using
# ../tools/experiment.sh

# iterates over all standard testing datasets in test/
# performs ImageMatching experiment upon each one

# it takes much much longer for OpenFHE to rewrite over existing serial files than to write new ones
# therefore we remove old serializations after every experiment
if [[ -e "serial/" -a -d "serial/" ]]; then
    rm -r serial/
fi

for dataset in ../test/2_*.dat; do 
    if [ -e "$dataset" ]; then
        # ./ImageMatching "$dataset" > /dev/null
        ./ImageMatching "$dataset" > output/out.txt
        rm -r serial/
    fi
done

exit 0