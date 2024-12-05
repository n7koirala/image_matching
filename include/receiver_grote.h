// ** receiver: Defines the receiver (querier) base class
// encrypts / decrypts queries according to literature baseline approach

#pragma once

#include "receiver_base.h"

class GroteReceiver : public BaseReceiver {
public:
  // constructor
  GroteReceiver(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
              PrivateKey<DCRTPoly> skParam, size_t vectorParam);

  // public methods
  vector<size_t> decryptIndex(tuple<vector<Ciphertext<DCRTPoly>>, vector<Ciphertext<DCRTPoly>>> indexCipher);

};