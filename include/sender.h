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
#include <fstream>

using namespace lbcrypto;
using namespace std;

class Sender {
public:
  // constructor
  Sender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam, ofstream& expStreamParam);

  // public methods
  void setDatabaseCipher(vector<vector<Ciphertext<DCRTPoly>>> databaseCipherParam);

  void serializeDatabaseCipher(string location);

  vector<Ciphertext<DCRTPoly>>
  computeSimilarity(vector<Ciphertext<DCRTPoly>> queryCipher);

  vector<Ciphertext<DCRTPoly>>
  indexScenarioNaive(vector<Ciphertext<DCRTPoly>> queryCipher);

  Ciphertext<DCRTPoly>
  membershipScenarioNaive(vector<Ciphertext<DCRTPoly>> queryCipher);

  Ciphertext<DCRTPoly>
  membershipScenario(vector<Ciphertext<DCRTPoly>> queryCipher, size_t rowLength);

  tuple<vector<Ciphertext<DCRTPoly>>, vector<Ciphertext<DCRTPoly>>>
  indexScenario(vector<Ciphertext<DCRTPoly>> queryCipher, size_t rowLength);

private:
  // private members
  CryptoContext<DCRTPoly> cc;
  PublicKey<DCRTPoly> pk;
  size_t numVectors;
  vector<vector<Ciphertext<DCRTPoly>>> databaseCipher;
  ofstream& expStream;

  // private functions
  Ciphertext<DCRTPoly> 
  computeSimilarityHelper(size_t matrixIndex, vector<Ciphertext<DCRTPoly>> queryCipher);

  Ciphertext<DCRTPoly>
  computeSimilaritySerial(size_t matrix, size_t index, Ciphertext<DCRTPoly> queryCipher);

  Ciphertext<DCRTPoly>
  generateQueryHelper(Ciphertext<DCRTPoly> queryCipher, size_t index);

  vector<Ciphertext<DCRTPoly>> 
  alphaNormRows(vector<Ciphertext<DCRTPoly>> scoreCipher, size_t alpha, size_t rowLength);

  vector<Ciphertext<DCRTPoly>> 
  alphaNormColumns(vector<Ciphertext<DCRTPoly>> scoreCipher, size_t alpha, size_t rowLength);
};