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

  // public methods
  Ciphertext<DCRTPoly> encryptQuery(vector<double> query);
  
  vector<Plaintext> decryptSimilarity(vector<Ciphertext<DCRTPoly>> cosineCipher);

  vector<double> decryptMergedScores(vector<Ciphertext<DCRTPoly>> mergedCipher);

  bool decryptMembershipQuery(Ciphertext<DCRTPoly> membershipCipher);

  vector<int> decryptIndexQuery(vector<Ciphertext<DCRTPoly>> indexCipher);

  vector<size_t> decryptMatrixIndexQuery(Ciphertext<DCRTPoly> rowCipher, Ciphertext<DCRTPoly> colCipher);

protected:
  // protected members
  CryptoContext<DCRTPoly> cc;
  PublicKey<DCRTPoly> pk;
  PrivateKey<DCRTPoly> sk;
  int numVectors;
};