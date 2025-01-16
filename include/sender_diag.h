#pragma once

#include "sender.h"

class DiagonalSender : public Sender {
public:
  // constructor
  DiagonalSender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam);

  // public methods
  vector<Ciphertext<DCRTPoly>>
  computeSimilarity(Ciphertext<DCRTPoly> &queryCipher);

  Ciphertext<DCRTPoly> 
  membershipScenario(Ciphertext<DCRTPoly> &queryCipher);

  vector<Ciphertext<DCRTPoly>> 
  indexScenario(Ciphertext<DCRTPoly> &queryCipher);

protected:
  // protected methods
  Ciphertext<DCRTPoly> 
  computeSimilarityMatrix(vector<Ciphertext<DCRTPoly>> &queryCipher, size_t matrix);

  Ciphertext<DCRTPoly> 
  computeSimilarityThread(Ciphertext<DCRTPoly> &queryCipher, size_t matrix, size_t index);

};