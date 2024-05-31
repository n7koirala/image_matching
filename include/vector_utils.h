// ** Contains the functionalities for loading and processing of data vectors.
#include <cstddef>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cmath>

using namespace std;

namespace VectorUtils {

void concatenateVectors(vector<double> &dest, vector<double> source,
                        int n);


double plaintextCosineSim(vector<double> x, vector<double> y);
} // namespace VectorUtils