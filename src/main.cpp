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
    fileStream.open(DEFAULT_VECTORS_FILE, ios::in);
  }

  if (!fileStream.is_open()) {
    cerr << "[main.cpp]\tError: input file not found" << endl;
    return 1;
  }

  uint32_t multDepth = 12; // OpenFHEWrapper::computeMultDepth();
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


  cout << "[main.cpp]\tGenerating mult keys... " << flush;
  cc->EvalMultKeyGen(sk);
  cout << "done" << endl;


  cout << "[main.cpp]\tGenerating sum keys... " << flush;
  cc->EvalSumKeyGen(sk);
  cout << "done" << endl;


  cout << "[main.cpp]\tGenerating rotation keys... " << flush;
  vector<int> binaryRotationFactors;
  for(int i = 1; i < batchSize; i *= 2) {
    binaryRotationFactors.push_back(i);
    binaryRotationFactors.push_back(-i);
  }
  cc->EvalRotateKeyGen(sk, binaryRotationFactors);
  cout << "done" << endl;


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


  // Normalize, batch, and encrypt the query vector
  Ciphertext<DCRTPoly> queryCipher = receiver.encryptQuery(queryVector);


  // Serialize the encrypted query vector for demonstration
  cout << "[main.cpp]\tSerializing encrypted query vector... " << flush;
  if (!Serial::SerializeToFile(SERIAL_FOLDER + "/query_cipher.txt", queryCipher, SerType::JSON)) {
      cerr << "Error: cannot serialize query cipher to" << SERIAL_FOLDER + "/query_cipher.txt" << endl;
      return 1;
  }
  cout << "done" << endl;


  // Normalize, batch, and encrypt the database vectors
  vector<Ciphertext<DCRTPoly>> databaseCipher =
      receiver.encryptDB(plaintextVectors);


  // Run membership scenario upon similarity scores
  /*
  Ciphertext<DCRTPoly> membershipCipher =
      sender.membershipQuery(queryCipher, databaseCipher);
  double membershipResults = receiver.decryptMembershipQuery(membershipCipher);
  cout << endl << "Results of membership query:"" << endl;
  cout << "\tThere exists " << membershipResults << " match(es) between the query vector and the database vectors" << endl;
   */

  // Run index scenario upon similarity scores
  vector<Ciphertext<DCRTPoly>> indexCipher = sender.indexQuery(queryCipher, databaseCipher);
  vector<int> matchingIndices = receiver.decryptIndexQuery(indexCipher);
  cout << endl << "Results of index query:" << endl;
  if(!matchingIndices.size()) {
    cout << "\tNo matches found between query vector and database vectors" << endl;
  }

  for(size_t i = 0; i < matchingIndices.size(); i++) {
    cout << "\tMatch found between the query vector and database vector [" << matchingIndices[i] << "]" << endl;
  }

  return 0;
}