#include "../include/config.h"
#include "../include/receiver.h"
#include "../include/receiver_secure.h"
#include "../include/sender.h"
#include "../include/vector_utils.h"
#include "../include/openFHE_wrapper.h"
#include "openfhe.h"
#include <iostream>

// header files needed for serialization -- discuss how to implement
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;
using namespace std;

// ** Entry point of the application that orchestrates the flow. **

int main(int argc, char *argv[]) {

  cout << "[main.cpp]\tMain execution entered..." << endl;

  // Open input file
  ifstream fileStream;
  if (argc > 1) {
    fileStream.open(argv[1], ios::in);
  } else {
    fileStream.open(BACKEND_VECTORS_FILE, ios::in);
  }

  if (!fileStream.is_open()) {
    cerr << "[main.cpp]\tError: input file not found" << endl;
    return 1;
  }

  // TODO: check / update these vals
  // plaintext preprocessing currently requires multDepth = 8 -> batchSize = 8192
  // secure preprocessing currently requires multDepth = 20 -> batchSize = 32768
  uint32_t multDepth = 20;// OpenFHEWrapper::computeMultDepth();
  CCParams<CryptoContextCKKSRNS> parameters;
  parameters.SetSecurityLevel(HEStd_128_classic);
  parameters.SetMultiplicativeDepth(multDepth);
  parameters.SetScalingModSize(45);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(ADVANCEDSHE);
  
  int batchSize = cc->GetEncodingParams()->GetBatchSize();

  // OpenFHEWrapper::printSchemeDetails(parameters, cc);
  cout << "[main.cpp]\tCKKS scheme set up (depth = " << multDepth << ", batch size = " << batchSize << ")" << endl;

  cout << "[main.cpp]\tGenerating key pair... " << flush;
  auto keyPair = cc->KeyGen();
  auto pk = keyPair.publicKey;
  auto sk = keyPair.secretKey;
  cout << "done" << endl;

  vector<int> binaryRotationFactors;
  for(int i = 1; i < batchSize; i *= 2) {
    binaryRotationFactors.push_back(i);
    binaryRotationFactors.push_back(-i);
  }

  cout << "[main.cpp]\tGenerating mult keys... " << flush;
  cc->EvalMultKeyGen(sk);
  cout << "done" << endl;

  cout << "[main.cpp]\tGenerating sum keys... " << flush;
  cc->EvalSumKeyGen(sk);
  cout << "done" << endl;

  cout << "[main.cpp]\tGenerating rotation keys... " << flush;
  cc->EvalRotateKeyGen(sk, binaryRotationFactors);
  cout << "done" << endl;

  // Read in vectors from file
  cout << "[main.cpp]\tReading in vectors from file... " << flush;
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
  cout << "done" << endl;

  // Initialize receiver and sender objects -- only the receiver possesses the secret key
  Receiver receiver(cc, pk, sk, numVectors);
  Sender sender(cc, pk, numVectors);

  // TESTING MERGE OPERATION
  vector<double> testValues(batchSize);
  for(int i = 0; i < batchSize; i++) {  testValues[i] = double(i);  }
  Plaintext testPtxt = cc->MakeCKKSPackedPlaintext(testValues);
  Ciphertext<DCRTPoly> testCipher;
  testCipher = cc->Encrypt(pk, testPtxt);
  testCipher = sender.mergeSingleCipher(testCipher, 16);

  return 0;
  cc->Decrypt(sk, testCipher, &testPtxt);
  testValues = testPtxt->GetRealPackedValue();
  cout << endl;
  for(int i = 0; i < batchSize; i++) {
    cout << "testValues[" << i << "]\t" << testValues[i] << endl;
  }

  return 0;
  // END

  // Normalize, batch, and encrypt the query vector
  Ciphertext<DCRTPoly> queryCipher = receiver.encryptQuery(queryVector);

  // Normalize, batch, and encrypt the database vectors
  vector<Ciphertext<DCRTPoly>> databaseCipher =
      receiver.encryptDB(plaintextVectors);

  // Cosine similarity is equivalent to inner product of normalized vectors
  // TODO: In future, explore if key-switching is unnecessary / slower
  // REMEMBER!!! : score merge operation has been removed from this function
  vector<Ciphertext<DCRTPoly>> similarityCipher =
      sender.computeSimilarity(queryCipher, databaseCipher);

  // Receiver is then able to decrypt all scores
  // This does not determine matches or protect provenance privacy, just contains all scores
  vector<Ciphertext<DCRTPoly>> mergedCipher; // = sender.mergeScores(similarityCipher, VECTOR_DIM);
  vector<double> mergedValues = receiver.decryptMergedScores(mergedCipher);

  // Output raw scores
  cout << endl;
  for (int i = 0; i < numVectors; i++) {
    cout << "Cosine similarity of query with database[" << i << "]" << endl;
    cout << "Expected:\t" << VectorUtils::plaintextCosineSim(queryVector, plaintextVectors[i]) << endl;
    cout << "Merged:  \t" << mergedValues[i] << endl;
    cout << endl;
  }

  // Run membership scenario upon similarity scores
  Ciphertext<DCRTPoly> membershipCipher =
      sender.membershipQuery(similarityCipher);
  double membershipResults = receiver.decryptMembershipQuery(membershipCipher);
  cout << endl << "Membership Query: there exists " << membershipResults << " match(es) between the query and the database" << endl;

  return 0;
}