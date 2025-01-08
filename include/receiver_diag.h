// ** receiver: Defines the receiver (querier) base class
// encrypts / decrypts queries according to our novel diagonalization approach

#pragma once

#include "receiver.h"

class DiagonalReceiver : public Receiver {
public:
  // constructor
  DiagonalReceiver(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
              PrivateKey<DCRTPoly> skParam, size_t vectorParam);

  // public methods
  Ciphertext<DCRTPoly> encryptQuery(vector<double> query);

protected:
  
};