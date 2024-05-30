// ** receiver_secure: Defines and implements a receiver (querier)
// Performs the vector normalization step in the encrypted domain

#include "../include/openFHE_wrapper.h"
#include "../include/vector_utils.h"
#include "openfhe.h"
#include <vector>
#include <omp.h>

using namespace lbcrypto;
using namespace std;

class SecureReceiver {
public:
  // constructor
  SecureReceiver(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
             PrivateKey<DCRTPoly> sk, int dimParam, int vectorParam);

  // utility functions for computing cosine similarity
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