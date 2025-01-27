#pragma once

#include "sender_base.h"

class GroteSender : public BaseSender {
public:
  // constructor
  GroteSender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam);

  // public methods
  Ciphertext<DCRTPoly>
  membershipScenario(vector<Ciphertext<DCRTPoly>> &queryCipher) override;

  vector<Ciphertext<DCRTPoly>>
  indexScenario(vector<Ciphertext<DCRTPoly>> &queryCipher) override;

};