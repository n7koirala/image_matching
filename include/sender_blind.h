#pragma once

#include "sender_hers.h"

class BlindSender : public HersSender {
public:
  // constructor
  BlindSender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam);

  // public methods
  vector<Ciphertext<DCRTPoly>>
  computeSimilarity(vector<Ciphertext<DCRTPoly>> &queryCipher) override;

  Ciphertext<DCRTPoly>
  membershipScenario(vector<Ciphertext<DCRTPoly>> &queryCipher) override;

  vector<Ciphertext<DCRTPoly>>
  indexScenario(vector<Ciphertext<DCRTPoly>> &queryCipher) override;

protected:
  // protected methods
  Ciphertext<DCRTPoly>
  computeSimilarityMatrix(vector<Ciphertext<DCRTPoly>> &queryCipher, size_t chunkLength, size_t matrix);

  Ciphertext<DCRTPoly>
  computeSimilaritySerial(Ciphertext<DCRTPoly> &queryCipher, size_t matrix, size_t index);

};