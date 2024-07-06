// ** sender: defines the sender (server) base class
// Stores encrypted database vectors and homomorphically computes membership/index queries 

#pragma once

#include "../include/config.h"
#include "../include/openFHE_wrapper.h"
#include "../include/vector_utils.h"
#include "openfhe.h"
#include <vector>
#include <omp.h>
#include <time.h>
#include <ctime>

using namespace lbcrypto;
using namespace std;
using namespace std::chrono;
using measure_typ = std::chrono::milliseconds;

class Sender {
public:
  // constructor
  Sender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, int vectorParam);

  // public methods
  void setDatabaseCipher(vector<Ciphertext<DCRTPoly>> databaseCipherParam);

  void serializeDatabaseCipher(string location);

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

  Ciphertext<DCRTPoly> matrixMembershipQuery(Ciphertext<DCRTPoly> queryCipher);

  vector<Ciphertext<DCRTPoly>> indexQuery(Ciphertext<DCRTPoly> queryCipher);

  tuple<Ciphertext<DCRTPoly>, Ciphertext<DCRTPoly>> matrixIndexQuery(Ciphertext<DCRTPoly> queryCipher);

private:
  // private members
  CryptoContext<DCRTPoly> cc;
  PublicKey<DCRTPoly> pk;
  int numVectors;
  vector<Ciphertext<DCRTPoly>> databaseCipher;
};