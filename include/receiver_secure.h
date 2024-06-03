// ** receiver_secure: Defines and implements a receiver (querier)
// Performs the vector normalization step in the encrypted domain

#include "../include/receiver_plain.h"

using namespace lbcrypto;
using namespace std;

class SecureReceiver : public PlainReceiver {
public:
  // constructor
  SecureReceiver(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
             PrivateKey<DCRTPoly> sk, int dimParam, int vectorParam);

  // utility functions for computing cosine similarity
  Ciphertext<DCRTPoly> approxInverseMagnitude(Ciphertext<DCRTPoly> ctxt);
  Ciphertext<DCRTPoly> encryptQuery(vector<double> query);
  vector<Ciphertext<DCRTPoly>> encryptDB(vector<vector<double>> database);
};