// ** Holds configuration parameters like file paths, default values, and any
// other constant values

#pragma once

#include <string>

// TODO: make serialization into separate executable
const bool READ_FROM_SERIAL = false;

// similarity threshold value used to determine a match between vectors
const double MATCH_THRESHOLD = 0.85;

// Degree required by the sign-approximating Chebyshev polynomial
// Relationship with multiplicative depth described at the below link
// https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/FUNCTION_EVALUATION.md
const size_t SIGN_DEPTH = 10;

// dimension (length) of inputted query / database vectors
const size_t VECTOR_DIM = 512;

// Default full-sized input source, 1 query vector and 1024 database vectors (matches at indices 2 and 1023)
const std::string DEFAULT_VECTORS_FILE = "../test/2^10.dat";

// Number of threads used in multithreaded sections
const size_t RECEIVER_NUM_CORES = 32;
const size_t SENDER_NUM_CORES = 32;

// exponent used in alpha-norm approximation of max values, invokes a mult. depth of alpha
const int ALPHA = 2;