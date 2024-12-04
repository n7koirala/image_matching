FILEPATH="output/experiment.csv"

# print .csv header for experiment file
printf "Experimental Approach," >> $FILEPATH
printf "Database Size," >> $FILEPATH
printf "Query Encryption," >> $FILEPATH
printf "Membership Computation," >> $FILEPATH
printf "Membership Decryption," >> $FILEPATH
printf "Index Computation," >> $FILEPATH
printf "Index Decryption," >> $FILEPATH
printf "Membership Result," >> $FILEPATH
printf "Index Result" >> $FILEPATH
printf "\n"  >> $FILEPATH