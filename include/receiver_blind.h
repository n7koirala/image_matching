// ** receiver_blind: Defines the receiver class according to Blind-Match approach

#pragma once

#include "receiver_hers.h"

class BlindReceiver : public HersReceiver {
public:
  // constructor
  BlindReceiver(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
              PrivateKey<DCRTPoly> skParam, size_t vectorParam);

  // public methods
  vector<Ciphertext<DCRTPoly>> 
  encryptQuery(vector<double> query) override;

  vector<size_t> 
  decryptIndex(vector<Ciphertext<DCRTPoly>> &indexCipher) override;

private:
  // private methods
  Ciphertext<DCRTPoly> 
  encryptQueryThread(vector<double> &query, size_t chunkLength, size_t index);
};