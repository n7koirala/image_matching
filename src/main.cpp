#include "../include/config.h"
#include "../include/receiver.h"
#include "../include/enroller.h"
#include "../include/sender.h"
#include "../include/vector_utils.h"
#include "../include/openFHE_wrapper.h"
#include "openfhe.h"
#include <iostream>

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;
using namespace std;

// ** Entry point of the application that orchestrates the flow. **

int main(int argc, char *argv[]) {

  cout << "[main.cpp]\t\tMain execution entered..." << endl;

  // Open input file
  ifstream fileStream;
  if (argc > 1) {
    fileStream.open(argv[1], ios::in);
  } else {
    fileStream.open(DEFAULT_VECTORS_FILE, ios::in);
  }

  if (!fileStream.is_open()) {
    cerr << "[main.cpp]\t\tError: input file not found" << endl;
    return 1;
  }

  uint32_t multDepth = 4 + (4 * SIGN_COMPOSITIONS);
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
  cout << "[main.cpp]\t\tCKKS scheme set up (depth = " << multDepth << ", batch size = " << batchSize << ")" << endl;


  cout << "[main.cpp]\t\tGenerating key pair... " << flush;
  auto keyPair = cc->KeyGen();
  auto pk = keyPair.publicKey;
  auto sk = keyPair.secretKey;
  cout << "done" << endl;


  cout << "[main.cpp]\t\tGenerating mult keys... " << flush;
  cc->EvalMultKeyGen(sk);
  cout << "done" << endl;


  cout << "[main.cpp]\t\tGenerating sum keys... " << flush;
  cc->EvalSumKeyGen(sk);
  cout << "done" << endl;


  cout << "[main.cpp]\t\tGenerating rotation keys... " << flush;
  vector<int> binaryRotationFactors;
  for(int i = 1; i < batchSize; i *= 2) {
    binaryRotationFactors.push_back(i);
    binaryRotationFactors.push_back(-i);
  }
  cc->EvalRotateKeyGen(sk, binaryRotationFactors);
  cout << "done" << endl;

  cout << "[main.cpp]\t\tReading in vectors from file... " << flush;
  int numVectors;
  fileStream >> numVectors;

  // Read in query vector from file
  vector<double> queryVector(VECTOR_DIM);
  for (int i = 0; i < VECTOR_DIM; i++) {
    fileStream >> queryVector[i];
  }

  // Read in database vectors from file
  vector<vector<double>> plaintextVectors(numVectors, vector<double>(VECTOR_DIM));
  for (int i = 0; i < numVectors; i++) {
    for (int j = 0; j < VECTOR_DIM; j++) {
      fileStream >> plaintextVectors[i][j];
    }
  }
  fileStream.close();
  cout << "done" << endl;


  // Initialize receiver, enroller, and sender objects -- only the receiver possesses the secret key
  Receiver receiver(cc, pk, sk, numVectors);
  Enroller enroller(cc, pk, numVectors);
  Sender sender(cc, pk, numVectors);


  // Normalize, batch, and encrypt the query vector
  Ciphertext<DCRTPoly> queryCipher = receiver.encryptQuery(queryVector);


  // Serialize the encrypted query vector for demonstration
  cout << "[main.cpp]\t\tSerializing encrypted query vector... " << flush;
  if (!Serial::SerializeToFile("query_cipher.txt", queryCipher, SerType::JSON)) {
      cout << "failed" << endl;
  } else {
    cout << "done" << endl;
  }
  

  // Normalize, batch, and encrypt the database vectors
  sender.setDatabaseCipher(enroller.encryptDB(plaintextVectors));


  // Serialize an encrypted database vector for demonstration
  sender.serializeDatabaseCipher("database_cipher.txt");


  // Run membership scenario upon similarity scores
  cout << endl << "Simulating membership scenario" << endl << endl;
  Ciphertext<DCRTPoly> membershipCipher =
      sender.membershipQuery(queryCipher);
  bool membershipResults = receiver.decryptMembershipQuery(membershipCipher);
  cout << endl << "Results of membership query:" << endl;
  if(membershipResults) {
    cout << "\tThere exists a match between the query vector and the database vectors" << endl;
  } else {
    cout << "\tThere does not exist a match between the query vector and the database vectors" << endl;
  }
  

  // Run index scenario upon similarity scores
  cout << endl << "Simulating index scenario" << endl << endl;
  vector<Ciphertext<DCRTPoly>> indexCipher = sender.indexQuery(queryCipher);
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