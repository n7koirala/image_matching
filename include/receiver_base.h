// ** receiver: Defines the receiver (querier) base class
// encrypts / decrypts queries according to literature baseline approach

#pragma once

#include "receiver_hers.h"

class BaseReceiver : public HersReceiver {
public:
  // constructor
  BaseReceiver(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
              PrivateKey<DCRTPoly> skParam, size_t vectorParam);

  // public methods
  vector<Ciphertext<DCRTPoly>> encryptQuery(vector<double> query) override;

protected:

};