#include "../include/sender.h"
#include "openfhe.h"
#include <vector>

using namespace lbcrypto;

// implementation of functions declared in sender.h
Sender::Sender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               int dimParam, int vectorParam)
    : cc(ccParam), pk(pkParam), vectorDim(dimParam), numVectors(vectorParam) {}

vector<Ciphertext<DCRTPoly>>
Sender::computeSimilarity(Ciphertext<DCRTPoly> query,
                          vector<Ciphertext<DCRTPoly>> database) {
  vector<Ciphertext<DCRTPoly>> similarityCipher(database.size());
  for (int i = 0; i < database.size(); i++) {
    similarityCipher[i] = cc->EvalInnerProduct(query, database[i], vectorDim);
  }
  return similarityCipher;
}