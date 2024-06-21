// ** cosine_similarity: Contains the definition and implementation of the
// cosine similarity computation logic using plaintext preprocessing.

#pragma once

#include "../include/config.h"
#include "../include/openFHE_wrapper.h"
#include "../include/vector_utils.h"
#include "openfhe.h"
#include <vector>

using namespace lbcrypto;
using namespace std;

class Enroller {
public:
  // constructor
  Enroller(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, int vectorParam);

  // public methods
  vector<Ciphertext<DCRTPoly>> encryptDB(vector<vector<double>> database);

private:
  // some private members here
  CryptoContext<DCRTPoly> cc;
  PublicKey<DCRTPoly> pk;
  int numVectors;
};