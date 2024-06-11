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

  cout << "[main.cpp]\tMain execution entered..." << endl;

  // plaintext preprocessing currently requires multDepth = 3
  // secure preprocessing currently requires multDepth = 15
  uint32_t multDepth = 3;
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

  int batchSize = cc->GetEncodingParams()->GetBatchSize();

  // OpenFHEWrapper::printSchemeDetails(parameters, cc);
  cout << "[main.cpp]\tCKKS scheme set up (depth = " << multDepth << ", batch size = " << batchSize << ")..." << endl;

  auto keyPair = cc->KeyGen();
  auto pk = keyPair.publicKey;
  auto sk = keyPair.secretKey;
  cc->EvalMultKeyGen(sk);
  cc->EvalSumKeyGen(sk);

  // these specific rotations needed for merge operation
  vector<int> rotationFactors = {-VECTOR_DIM};
  for(int i = (VECTOR_DIM - 1); i < batchSize; i *= 2) {
    rotationFactors.push_back(i);
  }
  cc->EvalRotateKeyGen(sk, rotationFactors);

  cout << "[main.cpp]\tCKKS keys generated..." << endl;

  // Get vectors from input
  ifstream fileStream;
  if (argc > 1) {
    fileStream.open(argv[1], ios::in);
  } else {
    fileStream.open(BACKEND_VECTORS_FILE, ios::in);
  }

  if (!fileStream.is_open()) {
    cerr << "[main.cpp]\tError opening file" << endl;
    return 1;
  }

  // Read in vectors from file
  int numVectors;
  fileStream >> numVectors;

  // Read in query vector
  vector<double> queryVector(VECTOR_DIM);
  for (int i = 0; i < VECTOR_DIM; i++) {
    fileStream >> queryVector[i];
  }

  // Read in database vectors
  vector<vector<double>> plaintextVectors(numVectors, vector<double>(VECTOR_DIM));
  for (int i = 0; i < numVectors; i++) {
    for (int j = 0; j < VECTOR_DIM; j++) {
      fileStream >> plaintextVectors[i][j];
    }
  }
  fileStream.close();
  cout << "[main.cpp]\tVectors read in from file..." << endl;

  // Initialize receiver and sender objects -- only the receiver possesses the secret key
  Receiver receiver(cc, pk, sk, numVectors);
  Sender sender(cc, pk, numVectors);

  // Normalize, batch, and encrypt the query vector
  Ciphertext<DCRTPoly> queryCipher = receiver.encryptQuery(queryVector);
  cout << "[main.cpp]\tQuery vector encrypted..." << endl;

  // Normalize, batch, and encrypt the database vectors
  vector<Ciphertext<DCRTPoly>> databaseCipher =
      receiver.encryptDB(plaintextVectors);
  cout << "[main.cpp]\tDatabase vectors encrypted..." << endl;

  // Cosine similarity is equivalent to inner product of normalized vectors
  // In future, explore if key-switching is unnecessary / slower
  vector<Ciphertext<DCRTPoly>> similarityCiphers =
      sender.computeSimilarity(queryCipher, databaseCipher);
  cout << "[main.cpp]\tSimilarity scores computed..." << endl;

  // Receiver is then able to decrypt all scores
  // This does not determine matches or protect provenance privacy, just contains all scores
  vector<Plaintext> resultPtxts = receiver.decryptSimilarity(similarityCiphers);
  cout << "[main.cpp]\tSimilarity scores decrypted..." << endl;

  // Testing merge operation
  cout << "[main.cpp]\tMerging scores..." << endl;

  Ciphertext<DCRTPoly> mergedCipher = sender.mergeScores(similarityCiphers);
  Plaintext mergedPtxt; 
  cc->Decrypt(sk, mergedCipher, &(mergedPtxt));
  auto mergedValues = mergedPtxt->GetRealPackedValue();

  // Formatted Output
  cout << endl;
  int vectorsPerBatch = (int)(batchSize / VECTOR_DIM);
  for (int i = 0; i < numVectors; i++) {
    int batchNum = (int)(i / vectorsPerBatch);
    int batchIndex = (i % vectorsPerBatch) * VECTOR_DIM;
    auto resultValues = resultPtxts[batchNum]->GetRealPackedValue();
    cout << "Cosine similarity of query vector with database[" << i << "]"
         << endl;
    cout << "Batch Num: " << batchNum << "\tBatch Index: " << batchIndex
         << endl;
    cout << "Expected:\t"
         << VectorUtils::plaintextCosineSim(queryVector, plaintextVectors[i]) << endl;
    cout << "Homomorphic:\t" << resultValues[batchIndex] << endl;
    cout << "Merged:\t\t" << mergedValues[i] << endl;
    cout << endl;
  }

  return 0;
}