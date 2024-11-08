// ** receiver: Defines the receiver (querier) base class
// encrypts / decrypts queries according to literature baseline approach

#pragma once

#include "receiver.h"

class BaseReceiver : public Receiver {
public:
  // constructor
  BaseReceiver(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
              PrivateKey<DCRTPoly> skParam, size_t vectorParam);

  // public methods
  Ciphertext<DCRTPoly> encryptQuery(vector<double> query);

  

protected:

};