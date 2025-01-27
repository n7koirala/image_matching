// ** receiver: Defines the receiver class according to our novel diagonalization approach

#pragma once

#include "receiver_hers.h"

class DiagonalReceiver : public HersReceiver {
public:
  // constructor
  DiagonalReceiver(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
              PrivateKey<DCRTPoly> skParam, size_t vectorParam);

  // public methods
  vector<Ciphertext<DCRTPoly>> encryptQuery(vector<double> query) override;
  
};