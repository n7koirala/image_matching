// ** cosine_similarity: Contains the definition and implementation of the
// cosine similarity computation logic using plaintext preprocessing.

#pragma once

#include "../include/config.h"
#include "../include/openFHE_wrapper.h"
#include "../include/vector_utils.h"
#include "openfhe.h"
#include <vector>
#include <omp.h>
#include <time.h>

using namespace lbcrypto;
using namespace std;

class Sender {
public:
  // constructor
  Sender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, int vectorParam);

  // public methods
  void setDatabaseCipher(vector<Ciphertext<DCRTPoly>> databaseCipherParam);

  vector<Ciphertext<DCRTPoly>>
  computeSimilarity(Ciphertext<DCRTPoly> query);

  Ciphertext<DCRTPoly>
  mergeSingleCipher(Ciphertext<DCRTPoly> similarityCipher, int reductionDim);

  vector<Ciphertext<DCRTPoly>>
  mergeScores(vector<Ciphertext<DCRTPoly>> similarityCipher, int reductionDim);

  vector<Ciphertext<DCRTPoly>>
  mergeScoresOrdered(vector<Ciphertext<DCRTPoly>> similarityCipher, int reductionDim);

  Ciphertext<DCRTPoly> alphaNormRows(vector<Ciphertext<DCRTPoly>> mergedCipher, int alpha, int rowLength);

  Ciphertext<DCRTPoly> alphaNormColumns(vector<Ciphertext<DCRTPoly>> mergedCipher, int alpha, int colLength);

  Ciphertext<DCRTPoly> membershipQuery(Ciphertext<DCRTPoly> queryCipher);

  vector<Ciphertext<DCRTPoly>> indexQuery(Ciphertext<DCRTPoly> queryCipher);

private:
  // some private members here
  CryptoContext<DCRTPoly> cc;
  PublicKey<DCRTPoly> pk;
  int numVectors;
  vector<Ciphertext<DCRTPoly>> databaseCipher;
};