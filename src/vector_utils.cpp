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

  for (unsigned int i = 0; i < x.size(); i++) {
    xMag += (x[i] * x[i]);
    yMag += (y[i] * y[i]);
    innerProduct += (x[i] * y[i]);
  }

  return innerProduct / (sqrt(xMag) * sqrt(yMag));
}