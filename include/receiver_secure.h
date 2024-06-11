// ** receiver_secure: Defines a subclase of the receiver (querier) class
// Performs the vector normalization step in the encrypted domain

#pragma once

#include "../include/receiver.h"

using namespace lbcrypto;
using namespace std;

class SecurePreprocessingReceiver : public Receiver {
public:
  // constructor
  SecurePreprocessingReceiver(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
             PrivateKey<DCRTPoly> sk, int vectorParam);

  // utility functions for computing cosine similarity
  Ciphertext<DCRTPoly> encryptQuery(vector<double> query);
  vector<Ciphertext<DCRTPoly>> encryptDB(vector<vector<double>> database);

private:
  // private members
  Ciphertext<DCRTPoly> approxInverseMagnitude(Ciphertext<DCRTPoly> ctxt);
};