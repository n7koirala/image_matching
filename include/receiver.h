// ** receiver: Defines the receiver (querier) base class
// Performs the vector normalization step in the plaintext domain

#pragma once

#include "../include/config.h"
#include "../include/openFHE_wrapper.h"
#include "../include/vector_utils.h"
#include "openfhe.h"
#include <vector>
#include <omp.h>
#include <ctime>
#include <fstream>

using namespace lbcrypto;
using namespace std;

class Receiver {
public:
  // constructor
  Receiver(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
              PrivateKey<DCRTPoly> skParam, size_t vectorParam, ofstream& expStreamParam);

  // public methods
  vector<Ciphertext<DCRTPoly>> encryptQuery(vector<double> query);

  Ciphertext<DCRTPoly> encryptQueryAlt(vector<double> query);
  
  vector<double> decryptRawScores(vector<Ciphertext<DCRTPoly>> scoreCipher);

  bool decryptMembership(Ciphertext<DCRTPoly> membershipCipher);

  vector<size_t> decryptIndexNaive(vector<Ciphertext<DCRTPoly>> indexCipher);

  vector<size_t> decryptIndex(vector<Ciphertext<DCRTPoly>> rowCipher, vector<Ciphertext<DCRTPoly>> colCipher, size_t rowLength);

private:
  // private members
  CryptoContext<DCRTPoly> cc;
  PublicKey<DCRTPoly> pk;
  PrivateKey<DCRTPoly> sk;
  size_t numVectors;
  ofstream& expStream;

  // private functions
  Ciphertext<DCRTPoly> encryptQueryThread(double indexValue);
};