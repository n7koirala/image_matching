#pragma once

#include "sender_base.h"

class GroteSender : public BaseSender {
public:
  // constructor
  GroteSender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam);

  // public methods
  Ciphertext<DCRTPoly>
  membershipScenario(Ciphertext<DCRTPoly> queryCipher);

  tuple<vector<Ciphertext<DCRTPoly>>, vector<Ciphertext<DCRTPoly>>>
  indexScenario(Ciphertext<DCRTPoly> queryCipher);

};