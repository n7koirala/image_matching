// ** receiver_plain: Defines and implements a receiver (querier)
// Performs the vector normalization step in the plaintext domain

#include "../include/openFHE_wrapper.h"
#include "../include/vector_utils.h"
#include "openfhe.h"
#include <vector>
#include <omp.h>

using namespace lbcrypto;
using namespace std;

class PlainReceiver {
public:
  // constructor
  PlainReceiver(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
              PrivateKey<DCRTPoly> skParam, int dimParam, int vectorParam);

  // utility functions for computing cosine similarity
  double plaintextMagnitude(vector<double> x);
  double plaintextInnerProduct(vector<double> x, vector<double> y);
  std::vector<double> plaintextNormalize(vector<double> x);
  double plaintextCosineSim(vector<double> x, vector<double> y);
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