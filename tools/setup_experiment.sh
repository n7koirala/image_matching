FILEPATH="experiment.csv"

# print .csv header for experiment file
printf "Experimental Approach," >> $FILEPATH
printf "Database Size (vectors)," >> $FILEPATH

printf "Query Encryption (seconds)," >> $FILEPATH
printf "Query Size (ciphertexts)," >> $FILEPATH

printf "Membership Computation (seconds)," >> $FILEPATH
printf "Membership Decryption (seconds)," >> $FILEPATH
printf "Membership Result Size (ciphertexts)," >> $FILEPATH

printf "Index Computation (seconds)," >> $FILEPATH
printf "Index Decryption (seconds)," >> $FILEPATH
printf "Index Result Size (ciphertexts)," >> $FILEPATH

printf "Decrypted Membership Result," >> $FILEPATH
printf "Decrypted Index Result" >> $FILEPATH
printf "\n"  >> $FILEPATH