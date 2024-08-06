#!/bin/bash

# run this script from build/ using
# ../tools/dataset.sh

# ---------- constant variables ----------
DIM=512

# ---------- shell functions ----------
write_query_vec () {
    for ((i=0; i < $DIM; i++)); do
        printf "1 " >> $FILEPATH
    done
    printf "\n" >> $FILEPATH
    return
}

write_random_vec () {
    for ((i=0; i < $DIM; i++)); do
        printf "%d " $(( $RANDOM % 199 - 99)) >> $FILEPATH
    done
    printf "\n" >> $FILEPATH
    return
}

write_matching_vec () {
    for ((i=0; i < $DIM; i++)); do
        printf "%d " $(( $RANDOM % 3 + 1)) >> $FILEPATH
    done
    printf "\n" >> $FILEPATH
    return
}

# ---------- main execution ----------

# check for necessary cmd-line args
if [[ $# -gt 1 ]]; then
    FILEPATH="$1"
    SIZE="$2"
else
    echo "Error: required arguments not included"
    exit 1
fi

# check that the vector-number param is an integer
if [[ !("$SIZE" =~ ^[0-9]+$) ]]; then
    echo "Error: dataset size must be an integer"
    exit 1
fi

# write number of vectors and query vector to filepath
printf "$SIZE\n" > $FILEPATH
$(write_query_vec)

# write database vectors to filepath
# matches at indices i=2 and i=n-1
# TODO: implement user-input for determining which vectors match
for (( i=0; i<$SIZE; i++ )); do

    if ((i == 2 || i == $SIZE - 1)); then
        $(write_matching_vec)
    else
        $(write_random_vec)
    fi

done

exit 0