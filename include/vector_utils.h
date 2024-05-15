// ** Contains the functionalities for loading and processing of data vectors.
#include "../include/openFHE_wrapper.h"
#include "openfhe.h"
#include <cstddef>
#include <iostream>
#include <string>
#include <vector>

namespace VectorUtils {
// Other utility functions
void concatenateVectors(std::vector<double> &dest, std::vector<double> source,
                        int n);


double plaintextCosineSim(std::vector<double> x, std::vector<double> y);
} // namespace VectorUtils