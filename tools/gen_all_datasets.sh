for ((i=10; i<21; i++)); do 
    ../tools/gen_data_parallel $((2**i)) > "../test/2_${i}.dat";
done