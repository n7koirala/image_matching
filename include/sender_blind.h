#pragma once

#include "sender.h"

class BlindSender : public Sender {
public:
  // constructor
  BlindSender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam);

  // public methods
  vector<Ciphertext<DCRTPoly>>
  computeSimilarity(vector<Ciphertext<DCRTPoly>> &queryCipher, size_t chunkLength);

protected:
  // protected methods
  Ciphertext<DCRTPoly>
  computeSimilarityMatrix(vector<Ciphertext<DCRTPoly>> &queryCipher, size_t chunkLength, size_t matrix);

  Ciphertext<DCRTPoly>
  computeSimilaritySerial(Ciphertext<DCRTPoly> queryCipher, size_t matrix, size_t index);

};