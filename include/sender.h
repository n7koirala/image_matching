// ** cosine_similarity: Contains the definition and implementation of the
// cosine similarity computation logic using plaintext preprocessing.

#include "../include/vector_utils.h"
#include "../include/openFHE_wrapper.h"
#include "openfhe.h"
#include <vector>

using namespace lbcrypto;
using namespace std;

class Sender {
public:
  // constructor
  Sender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, int dimParam, int vectorParam);

  // public methods
  vector<Ciphertext<DCRTPoly>> computeSimilarity(Ciphertext<DCRTPoly> query, vector<Ciphertext<DCRTPoly>> database);

private:
  // some private members here
  CryptoContext<DCRTPoly> cc;
  PublicKey<DCRTPoly> pk;
  int vectorDim;
  int numVectors;
};