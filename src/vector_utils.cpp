#include "../include/vector_utils.h"

/*
std::vector<std::vector<double>>
readVectorsFromFile(const std::string &fileName) {
  // Open input file
  std::ifstream fileStream;
  fileStream.open(fileName, std::ios::in);

  if (!fileStream.is_open()) {
    std::cerr << "Error opening file" << std::endl;
    return {{}};
  }

  // Read in vectors from file
  int inputDim, numVectors;
  fileStream >> inputDim >> numVectors;
  std::vector<std::vector<double>> plaintextVectors(
      numVectors, std::vector<double>(inputDim));
  for (int i = 0; i < numVectors; i++) {
    for (int j = 0; j < inputDim; j++) {
      fileStream >> plaintextVectors[i][j];
    }
  }
  fileStream.close();
  return plaintextVectors;
}
 */

/* Append the vector source onto the end of the vector dest, n times */
void VectorUtils::concatenateVectors(std::vector<double> &dest,
                                     std::vector<double> source, int n) {
  for (int i = 0; i < n; i++) {
    dest.insert(dest.end(), source.begin(), source.end());
  }
}


double VectorUtils::plaintextCosineSim(std::vector<double> x, std::vector<double> y) {
  double xMag = 0.0;
  double yMag = 0.0;
  double innerProduct = 0.0;

  if (x.size() != y.size()) {
    std::cerr << "Error: cannot compute cosine similarity between vectors of different size" << std::endl;
    return 0.0;
  }

  for (int i = 0; i < x.size(); i++) {
    xMag += (x[i] * x[i]);
    yMag += (y[i] * y[i]);
    innerProduct += (x[i] * y[i]);
  }

  return innerProduct / (sqrt(xMag) * sqrt(yMag));
}