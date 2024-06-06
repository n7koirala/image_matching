#include "../include/config.h"
#include "../include/receiver.h"
#include "../include/receiver_secure.h"
#include "../include/sender.h"
#include "../include/vector_utils.h"
#include "../include/openFHE_wrapper.h"
#include "openfhe.h"
#include <iostream>

using namespace lbcrypto;
using namespace std;

// ** Entry point of the application that orchestrates the flow. **

int main(int argc, char *argv[]) {

  cout << "Main execution entered..." << endl;

  uint32_t multDepth = 13;
  CCParams<CryptoContextCKKSRNS> parameters;
  parameters.SetSecurityLevel(HEStd_128_classic);
  parameters.SetMultiplicativeDepth(multDepth);
  parameters.SetScalingModSize(45);

  // Preset security level specifies ring dimension n = 32768
  // Batch size cannot be set above n/2 = 16384
  // Discuss whether batch size should be increased
  // parameters.SetBatchSize(32768);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(ADVANCEDSHE);

  auto keyPair = cc->KeyGen();
  auto pk = keyPair.publicKey;
  auto sk = keyPair.secretKey;
  cc->EvalMultKeyGen(sk);
  cc->EvalSumKeyGen(sk);

  // OpenFHEWrapper::printSchemeDetails(parameters, cc);
  cout << "CKKS scheme initialized..." << endl;

  // Get vectors from input
  ifstream fileStream;
  if (argc > 1) {
    fileStream.open(argv[1], ios::in);
  } else {
    fileStream.open(BACKEND_VECTORS_FILE, ios::in);
  }

  if (!fileStream.is_open()) {
    cerr << "Error opening file" << endl;
    return 1;
  }

  // Read in vectors from file
  int inputDim, numVectors;
  fileStream >> inputDim >> numVectors;

  // Read in query vector
  vector<double> queryVector(inputDim);
  for (int i = 0; i < inputDim; i++) {
    fileStream >> queryVector[i];
  }

  // Read in database vectors
  vector<vector<double>> plaintextVectors(numVectors, vector<double>(inputDim));
  for (int i = 0; i < numVectors; i++) {
    for (int j = 0; j < inputDim; j++) {
      fileStream >> plaintextVectors[i][j];
    }
  }
  fileStream.close();
  cout << "Vectors read in from file..." << endl;

  // Initialize receiver and sender objects -- only the receiver possesses the secret key
  SecurePreprocessingReceiver receiver(cc, pk, sk, inputDim, numVectors);
  Sender sender(cc, pk, inputDim, numVectors);

  // Normalize, batch, and encrypt the query vector
  Ciphertext<DCRTPoly> queryCipher = receiver.encryptQuery(queryVector);
  cout << "Query vector encrypted..." << endl;

  // Normalize, batch, and encrypt the database vectors
  vector<Ciphertext<DCRTPoly>> databaseCipher =
      receiver.encryptDB(plaintextVectors);
  cout << "Database vectors encrypted..." << endl;

  // Cosine similarity is equivalent to inner product of normalized vectors
  // In future, explore if key-switching is unnecessary / slower
  vector<Ciphertext<DCRTPoly>> cosineCipher =
      sender.computeSimilarity(queryCipher, databaseCipher);
  cout << "Similarity scores computed..." << endl;

  // Receiver is then able to decrypt all scores
  // This does not determine matches or protect provenance privacy, just contains all scores
  vector<Plaintext> resultPtxts = receiver.decryptSimilarity(cosineCipher);
  cout << "Similarity scores decrypted..." << endl;

  // Formatted Output
  int vectorsPerBatch = (int)(cc->GetEncodingParams()->GetBatchSize() / inputDim);
  for (int i = 0; i < numVectors; i++) {
    int batchNum = (int)(i / vectorsPerBatch);
    int batchIndex = (i % vectorsPerBatch) * inputDim;
    auto resultValues = resultPtxts[batchNum]->GetRealPackedValue();
    cout << "Cosine similarity of query vector with database[" << i << "]"
         << endl;
    cout << "Batch Num: " << batchNum << "\tBatch Index: " << batchIndex
         << endl;
    cout << "Homomorphic:\t" << resultValues[batchIndex] << endl;
    cout << "Expected:\t"
         << VectorUtils::plaintextCosineSim(queryVector, plaintextVectors[i]) << endl;
    cout << endl;
  }

  return 0;
}