// ** Holds configuration parameters like file paths, default values, and any
// other constant values

#pragma once

#include <string>

// similarity threshold value used to determine a match between vectors
const double MATCH_THRESHOLD = 0.85;

// Depth to be consumed by the comparison approximation function
// Relationship with multiplicative depth described at the below link
// https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/FUNCTION_EVALUATION.md
const size_t COMP_DEPTH = 10;

// Number of squares to be taken during alpha-norm approximation of max values
// Invokes a mult depth of alpha in the group-testing approach
const size_t ALPHA_DEPTH = 2;

// Number of threads used in multithreaded sections
const size_t RECEIVER_NUM_CORES = 32;
const size_t SENDER_NUM_CORES = 32;


// ---------- Variables below should not be changed ----------

// TODO: make serialization into separate executable
const bool READ_FROM_SERIAL = false;

// dimension (length) of inputted query / database vectors
const size_t VECTOR_DIM = 512;