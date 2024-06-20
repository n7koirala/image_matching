// ** cosine_similarity: Contains the definition and implementation of the
// cosine similarity computation logic using plaintext preprocessing.

#pragma once

#include "../include/config.h"
#include "../include/openFHE_wrapper.h"
#include "../include/vector_utils.h"
#include "openfhe.h"
#include <vector>
#include <omp.h>

using namespace lbcrypto;
using namespace std;

class Sender {
public:
  // constructor
  Sender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, int vectorParam);

  // public methods
  vector<Ciphertext<DCRTPoly>>
  computeSimilarity(Ciphertext<DCRTPoly> query,
                    vector<Ciphertext<DCRTPoly>> database);

  Ciphertext<DCRTPoly>
  mergeSingleCipher(Ciphertext<DCRTPoly> similarityCipher, int reductionDim);

  vector<Ciphertext<DCRTPoly>>
  mergeScores(vector<Ciphertext<DCRTPoly>> similarityCipher, int reductionDim);

  vector<Ciphertext<DCRTPoly>>
  approximateMax(vector<Ciphertext<DCRTPoly>> similarityCipher, int alpha, int partitionLen);

  Ciphertext<DCRTPoly> membershipQuery(vector<Ciphertext<DCRTPoly>> similarityCipher);

  tuple<vector<Ciphertext<DCRTPoly>>, vector<Ciphertext<DCRTPoly>>>
  formatScoreMatrices(vector<Ciphertext<DCRTPoly>> similarityScores);

  Ciphertext<DCRTPoly> alphaNormRows(vector<Ciphertext<DCRTPoly>> mergedCipher, int alpha, int rowLength);

  Ciphertext<DCRTPoly> alphaNormColumns(vector<Ciphertext<DCRTPoly>> mergedCipher, int alpha, int colLength);

  vector<Ciphertext<DCRTPoly>> indexScenario(vector<Ciphertext<DCRTPoly>> similarityCipher);

private:
  // some private members here
  CryptoContext<DCRTPoly> cc;
  PublicKey<DCRTPoly> pk;
  int numVectors;
};