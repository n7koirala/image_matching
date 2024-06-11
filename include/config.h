// ** Holds configuration parameters like file paths, default values, and any
// other constant values

#pragma once

#include <string>

// length (dimension) of inputted query / database vectors
const int VECTOR_LEN = 512;

// Default full-sized input source, 1 query vector and 10,000 database vectors
const std::string BACKEND_VECTORS_FILE = "input/large.dat";

// Number of threads used in multithreaded sections
const int RECEIVER_NUM_CORES = 4;
const int SENDER_NUM_CORES = 4;

// Number of iterations of Newton's Method used by the secure-preprocessing receiver
// Results in a multiplicative depth of (3i + 1)
const int NEWTONS_ITERATIONS = 3;