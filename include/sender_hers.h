// ** sender_hers: defines the sender (server) class according to HERS approach
// Stores encrypted database vectors and homomorphically computes membership/index queries 

#pragma once

#include "sender.h"

class HersSender : public Sender {
public:
  // constructor
  HersSender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam);

  // public methods
  vector<Ciphertext<DCRTPoly>>
  computeSimilarity(vector<Ciphertext<DCRTPoly>> &queryCipher) override;

  Ciphertext<DCRTPoly>
  membershipScenario(vector<Ciphertext<DCRTPoly>> &queryCipher) override;

  vector<Ciphertext<DCRTPoly>>
  indexScenario(vector<Ciphertext<DCRTPoly>> &queryCipher) override;

  // Ciphertext<DCRTPoly>
  // membershipScenario(vector<Ciphertext<DCRTPoly>> queryCipher, size_t rowLength);

  // tuple<vector<Ciphertext<DCRTPoly>>, vector<Ciphertext<DCRTPoly>>>
  // indexScenario(vector<Ciphertext<DCRTPoly>> queryCipher, size_t rowLength);

protected:
  // private functions
  Ciphertext<DCRTPoly> 
  computeSimilarityHelper(size_t matrixIndex, vector<Ciphertext<DCRTPoly>> &queryCipher);

  Ciphertext<DCRTPoly>
  computeSimilaritySerial(size_t matrix, size_t index, Ciphertext<DCRTPoly> &queryCipher);

  Ciphertext<DCRTPoly>
  generateQueryHelper(Ciphertext<DCRTPoly> &queryCipher, size_t index);

  vector<Ciphertext<DCRTPoly>> 
  alphaNormRows(vector<Ciphertext<DCRTPoly>> &scoreCipher, size_t alpha, size_t rowLength);

  vector<Ciphertext<DCRTPoly>> 
  alphaNormColumns(vector<Ciphertext<DCRTPoly>> &scoreCipher, size_t alpha, size_t rowLength);
};