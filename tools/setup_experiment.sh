FILEPATH="latency.csv"

# print .csv header for experiment file
printf "Experimental Approach," >> $FILEPATH
printf "Database Size (vectors)," >> $FILEPATH
printf "Query Encryption (seconds)," >> $FILEPATH
printf "Query Size (ciphertexts)," >> $FILEPATH
printf "Membership Computation (seconds)," >> $FILEPATH
printf "Membership Result Size (ciphertexts)," >> $FILEPATH
printf "Membership Decryption (seconds)," >> $FILEPATH
printf "Index Computation (seconds)," >> $FILEPATH
printf "Index Result Size (ciphertexts)," >> $FILEPATH
printf "Index Decryption (seconds)," >> $FILEPATH
printf "Decrypted Membership Result," >> $FILEPATH
printf "Decrypted Index Result" >> $FILEPATH
printf "\n"  >> $FILEPATH

FILEPATH="accuracy.csv"

# print .csv header for experiment file
printf "Query Subject Index," >> $FILEPATH
printf "Query Subject ID," >> $FILEPATH
printf "True Positives," >> $FILEPATH
printf "False Negatives," >> $FILEPATH
printf "True Negatives," >> $FILEPATH
printf "False Positives" >> $FILEPATH
printf "\n"  >> $FILEPATH