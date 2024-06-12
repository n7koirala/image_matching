// ** receiver: Defines the receiver (querier) base class
// Performs the vector normalization step in the plaintext domain

#pragma once

#include "../include/config.h"
#include "../include/openFHE_wrapper.h"
#include "../include/vector_utils.h"
#include "openfhe.h"
#include <vector>
#include <omp.h>

using namespace lbcrypto;
using namespace std;

class Receiver {
public:
  // constructor
  Receiver(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
              PrivateKey<DCRTPoly> skParam, int vectorParam);

  // utility functions for computing cosine similarity
  double plaintextMagnitude(vector<double> x);
  double plaintextInnerProduct(vector<double> x, vector<double> y);
  std::vector<double> plaintextNormalize(vector<double> x);
  double plaintextCosineSim(vector<double> x, vector<double> y);
  Ciphertext<DCRTPoly> encryptQuery(vector<double> query);
  vector<Ciphertext<DCRTPoly>> encryptDB(vector<vector<double>> database);
  vector<Plaintext> decryptSimilarity(vector<Ciphertext<DCRTPoly>> cosineCipher);
  vector<double> decryptMergedScores(vector<Ciphertext<DCRTPoly>> mergedCipher);

protected:
  // some protected members here -- inherited by subclass
  CryptoContext<DCRTPoly> cc;
  PublicKey<DCRTPoly> pk;
  PrivateKey<DCRTPoly> sk;
  int numVectors;
};