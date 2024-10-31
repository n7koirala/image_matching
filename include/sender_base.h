#pragma once

#include "sender.h"

class BaseSender : public Sender {
public:
  // constructor
  BaseSender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam, ofstream& expStreamParam);

  // public methods
  vector<Ciphertext<DCRTPoly>>
  computeSimilarity(Ciphertext<DCRTPoly> queryCipher);

  Ciphertext<DCRTPoly>
  membershipScenario(Ciphertext<DCRTPoly> queryCipher);

  vector<Ciphertext<DCRTPoly>>
  indexScenario(Ciphertext<DCRTPoly> queryCipher);

protected:

};