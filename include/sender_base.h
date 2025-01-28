#pragma once

#include "sender_hers.h"

class BaseSender : public HersSender {
public:
  // constructor
  BaseSender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam);

  // public methods
  vector<Ciphertext<DCRTPoly>>
  computeSimilarity(vector<Ciphertext<DCRTPoly>> &queryCipher) override;

  Ciphertext<DCRTPoly>
  membershipScenario(vector<Ciphertext<DCRTPoly>> &queryCipher) override;

  vector<Ciphertext<DCRTPoly>>
  indexScenario(vector<Ciphertext<DCRTPoly>> &queryCipher) override;

protected:

  void
  computeSimilarityThread(Ciphertext<DCRTPoly> &queryCipher, Ciphertext<DCRTPoly> &similarityCipher, size_t databaseIndex);

  void
  computeSimilarityAndMergeThread(Ciphertext<DCRTPoly> &queryCipher, Ciphertext<DCRTPoly> &mergedCipher, size_t startingIndex);

  vector<Ciphertext<DCRTPoly>>
  computeSimilarityAndMerge(Ciphertext<DCRTPoly> &queryCipher);

};