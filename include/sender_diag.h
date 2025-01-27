#pragma once

#include "sender_hers.h"

class DiagonalSender : public HersSender {
public:
  // constructor
  DiagonalSender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam);

  // public methods
  vector<Ciphertext<DCRTPoly>>
  computeSimilarity(vector<Ciphertext<DCRTPoly>> &queryCipher) override;

  Ciphertext<DCRTPoly> 
  membershipScenario(vector<Ciphertext<DCRTPoly>> &queryCipher) override;

  vector<Ciphertext<DCRTPoly>> 
  indexScenario(vector<Ciphertext<DCRTPoly>> &queryCipher) override;

private:
  // private methods
  Ciphertext<DCRTPoly> 
  computeSimilarityMatrix(vector<Ciphertext<DCRTPoly>> &queryCipher, size_t matrix);

  Ciphertext<DCRTPoly> 
  computeSimilarityThread(Ciphertext<DCRTPoly> &queryCipher, size_t matrix, size_t index);

};