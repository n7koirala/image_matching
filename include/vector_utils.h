// ** Contains the functionalities for loading and processing of data vectors.

#pragma once

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

double plaintextMagnitude(vector<double> x, int vectorDim);

vector<double> plaintextNormalize(vector<double> x, int vectorDim);

double plaintextInnerProduct(vector<double> x, vector<double> y, int vectorDim);
} // namespace VectorUtils