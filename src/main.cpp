#include "../include/config.h"
#include "../include/receiver_secure.h"
#include "../include/receiver_plain.h"
#include "../include/sender.h"
#include "../include/vector_utils.h"
#include "openfhe.h"
#include <iostream>

using namespace lbcrypto;
using namespace std;

// ** Entry point of the application that orchestrates the flow. **

int main(int argc, char *argv[]) {

  CCParams<CryptoContextCKKSRNS> parameters;
  uint32_t multDepth = 13;

  parameters.SetSecurityLevel(HEStd_128_classic);
  parameters.SetMultiplicativeDepth(multDepth);
  parameters.SetScalingModSize(45);

  // Preset security level specifies ring dimension n = 32768
  // Batch size cannot be set above n/2 = 16384
  // Work with this for now, discuss at meeting
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
  cc->EvalRotateKeyGen(sk, {1, 2, 4, 8, 16, 32, 64, 128, 256, 512}); // don't think this is necessary anymore

  unsigned int batchSize = cc->GetEncodingParams()->GetBatchSize();

  // Output Scheme Information
  /*
  cout << "batchSize: " << batchSize << endl;
  cout << endl;

  cout << "CKKS default parameters: " << parameters << endl;
  cout << endl;

  cout << "scaling mod size: " << parameters.GetScalingModSize() << endl;
  cout << "ring dimension: " << cc->GetRingDimension() << endl;
  cout << "noise estimate: " << parameters.GetNoiseEstimate() << endl;
  cout << "multiplicative depth: " << parameters.GetMultiplicativeDepth() <<
  endl; cout << "Noise level: " << parameters.GetNoiseEstimate() << endl;
   */

  // Get vectors from input
  ifstream fileStream;
  if (argc > 0) {
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

  int vectorsPerBatch = (int)(batchSize / inputDim);
  int totalBatches = (int)(numVectors / vectorsPerBatch + 1);

  // Initialize receiver and sender objects
  // Only the receiver possesses the secret key
  SecureReceiver receiver(cc, pk, sk, inputDim, numVectors);
  // PlainReceiver receiver(cc, pk, sk, inputDim, numVectors);
  Sender sender(cc, pk, inputDim, numVectors);

  // Normalize, batch, and encrypt the query vector
  Ciphertext<DCRTPoly> queryCipher = receiver.encryptQuery(queryVector);

  // Normalize, batch, and encrypt the database vectors
  vector<Ciphertext<DCRTPoly>> databaseCipher =
      receiver.encryptDB(plaintextVectors);

  // Cosine similarity is equivalent to inner product of normalized vectors
  // In future, explore if key-switching is not necessary / slower
  vector<Ciphertext<DCRTPoly>> cosineCipher =
      sender.computeSimilarity(queryCipher, databaseCipher);

  // Receiver is then able to decrypt all scores
  // This does not determine matches or protect provenance privacy, just outputs all scores
  vector<Plaintext> resultPtxts = receiver.decryptSimilarity(cosineCipher);

  // Formatted Output
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