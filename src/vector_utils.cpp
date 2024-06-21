#include "../include/vector_utils.h"

/* Append the vector source onto the end of the vector dest, n times */
void VectorUtils::concatenateVectors(vector<double> &dest,
                                     vector<double> source, int n) {
  for (int i = 0; i < n; i++) {
    dest.insert(dest.end(), source.begin(), source.end());
  }
}


double VectorUtils::plaintextCosineSim(vector<double> x, vector<double> y) {
  double xMag = 0.0;
  double yMag = 0.0;
  double innerProduct = 0.0;

  if (x.size() != y.size()) {
    cerr << "Error: cannot compute cosine similarity between vectors of different dimension" << endl;
    return -1.0;
  }

  for (size_t i = 0; i < x.size(); i++) {
    xMag += (x[i] * x[i]);
    yMag += (y[i] * y[i]);
    innerProduct += (x[i] * y[i]);
  }

  return innerProduct / (sqrt(xMag) * sqrt(yMag));
}


double VectorUtils::plaintextMagnitude(vector<double> x, int vectorDim) {
  double m = 0.0;
  for (int i = 0; i < vectorDim; i++) {
    m += (x[i] * x[i]);
  }
  m = sqrt(m);
  return m;
}


vector<double> VectorUtils::plaintextNormalize(vector<double> x, int vectorDim) {
  double m = plaintextMagnitude(x, vectorDim);
  vector<double> x_norm = x;
  if (m != 0) {
    for (int i = 0; i < vectorDim; i++) {
      x_norm[i] = x[i] / m;
    }
  }
  return x_norm;
}


double VectorUtils::plaintextInnerProduct(vector<double> x, vector<double> y, int vectorDim) {
  double prod = 0.0;
  for (int i = 0; i < vectorDim; i++) {
    prod += x[i] * y[i];
  }
  return prod;
}