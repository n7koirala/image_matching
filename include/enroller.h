// ** cosine_similarity: Contains the definition and implementation of the
// cosine similarity computation logic using plaintext preprocessing.

#pragma once

#include "../include/config.h"
#include "../include/openFHE_wrapper.h"
#include "../include/vector_utils.h"
#include "openfhe.h"
#include <vector>
#include <filesystem>

using namespace lbcrypto;
using namespace std;

class Enroller {
public:
  // constructor
  Enroller(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam);

  // public methods
  vector<vector<Ciphertext<DCRTPoly>>> encryptDB(vector<vector<double>> database);

  void serializeDB(vector<vector<double>> database);


private:
  // private members
  CryptoContext<DCRTPoly> cc;
  PublicKey<DCRTPoly> pk;
  size_t numVectors;

  // private functions
  Ciphertext<DCRTPoly> encryptDBThread(size_t matrix, size_t index, vector<vector<double>> database);

  void serializeDBThread(size_t matrix, size_t index, vector<vector<double>> &database);
};