// ** receiver: Defines the receiver (querier) base class
// Performs the vector normalization step in the plaintext domain

#pragma once

#include "receiver.h"

class HersReceiver : public Receiver {
public:
  // constructor
  HersReceiver(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
              PrivateKey<DCRTPoly> skParam, size_t vectorParam);

  // public methods
  vector<Ciphertext<DCRTPoly>> encryptQuery(vector<double> query) override;

  bool decryptMembership(Ciphertext<DCRTPoly> &membershipCipher) override;

  vector<size_t> decryptIndex(vector<Ciphertext<DCRTPoly>> &indexCipher) override;

protected:
  // protected functions
  Ciphertext<DCRTPoly> encryptQueryAlt(vector<double> query);

private:
  // private functions
  Ciphertext<DCRTPoly> encryptQueryThread(double indexValue);
  
};