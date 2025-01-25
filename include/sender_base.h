#pragma once

#include "sender_hers.h"

class BaseSender : public HersSender {
public:
  // constructor
  BaseSender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam);

  // public methods
  vector<Ciphertext<DCRTPoly>>
  computeSimilarity(Ciphertext<DCRTPoly> queryCipher);

  vector<Ciphertext<DCRTPoly>>
  computeSimilarityAndMerge(Ciphertext<DCRTPoly> queryCipher);

  Ciphertext<DCRTPoly>
  membershipScenario(Ciphertext<DCRTPoly> queryCipher);

  vector<Ciphertext<DCRTPoly>>
  indexScenario(Ciphertext<DCRTPoly> queryCipher);

protected:

  void
  computeSimilarityThread(Ciphertext<DCRTPoly> &queryCipher, Ciphertext<DCRTPoly> &similarityCipher, size_t databaseIndex);

  void
  computeSimilarityAndMergeThread(Ciphertext<DCRTPoly> &queryCipher, Ciphertext<DCRTPoly> &mergedCipher, size_t startingIndex);

};