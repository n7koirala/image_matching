// ** cosine_similarity: Contains the definition and implementation of the
// cosine similarity computation logic using plaintext preprocessing.

#include "../include/openFHE_wrapper.h"
#include "../include/vector_utils.h"
#include "openfhe.h"
#include <vector>

using namespace lbcrypto;
using namespace std;

class ReceiverHE {
public:
  // constructor
  ReceiverHE(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
             PrivateKey<DCRTPoly> sk, int dimParam, int vectorParam);

  // utility functions for computing cosine similarity
  Ciphertext<DCRTPoly> batchedInnerProduct(Ciphertext<DCRTPoly> c1,
                                           Ciphertext<DCRTPoly> c2,
                                           int dimension);
  Ciphertext<DCRTPoly> approxInverseMagnitude(Ciphertext<DCRTPoly> ctxt);
  Ciphertext<DCRTPoly> encryptQuery(vector<double> query);
  vector<Ciphertext<DCRTPoly>> encryptDB(vector<vector<double>> database);
  vector<Plaintext> decryptSimilarity(vector<Ciphertext<DCRTPoly>> cosineCipher);

private:
  // some private members here
  CryptoContext<DCRTPoly> cc;
  PublicKey<DCRTPoly> pk;
  PrivateKey<DCRTPoly> sk;
  int vectorDim;
  int numVectors;
};