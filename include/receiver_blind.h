// ** receiver: Defines the receiver (querier) base class
// encrypts / decrypts queries according to Blind-Match approach

#pragma once

#include "receiver.h"

class BlindReceiver : public Receiver {
public:
  // constructor
  BlindReceiver(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
              PrivateKey<DCRTPoly> skParam, size_t vectorParam);

  // public methods
  vector<Ciphertext<DCRTPoly>> encryptQuery(vector<double> &query, size_t chunkLength);

  vector<size_t> decryptIndex(vector<Ciphertext<DCRTPoly>> &indexCipher, size_t chunkLength);

protected:
  // protected methods
  Ciphertext<DCRTPoly> encryptQueryThread(vector<double> &query, size_t chunkLength, size_t index);
};