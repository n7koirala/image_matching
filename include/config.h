// ** Holds configuration parameters like file paths, default values, and any
// other constant values

#pragma once

#include <string>

// similarity threshold value used to determine a match between vectors
const double MATCH_THRESHOLD = 0.85;

// Number of times the sign-approximating polynomial should be composed with itself, increasing accuracy
// Results in a multiplicative depth of 4i
const int SIGN_COMPOSITIONS = 3;

// dimension (length) of inputted query / database vectors
const int VECTOR_DIM = 512;

// Default full-sized input source, 1 query vector and 1024 database vectors (matches at indices 2 and 1023)
const std::string DEFAULT_VECTORS_FILE = "../test/1024.dat";

// Number of threads used in multithreaded sections
const int RECEIVER_NUM_CORES = 32;
const int SENDER_NUM_CORES = 32;

// exponent used in alpha-norm approximation of max values, invokes a mult. depth of alpha
const int ALPHA = 2;

// Number of iterations of Newton's Method used by the secure-preprocessing receiver
// Results in a multiplicative depth of 3i
const int NEWTONS_ITERATIONS = 0;

