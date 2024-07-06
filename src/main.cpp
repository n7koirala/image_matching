#include "../include/config.h"
#include "../include/receiver.h"
#include "../include/enroller.h"
#include "../include/sender.h"
#include "../include/vector_utils.h"
#include "../include/openFHE_wrapper.h"
#include "openfhe.h"
#include <iostream>
#include <ctime>

// Header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;
using namespace std;
using namespace std::chrono;
using measure_typ = std::chrono::milliseconds;

// Entry point of the application that orchestrates the flow

int main(int argc, char *argv[]) {

  cout << "[main.cpp]\t\tMain execution entered..." << endl;

  steady_clock::time_point start, end;
  long double dur;
  start = steady_clock::now();

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

  uint32_t multDepth = 8 + (4 * SIGN_COMPOSITIONS);
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
  

  // Normalize, batch, and encrypt the database vectors
  sender.setDatabaseCipher(enroller.encryptDB(plaintextVectors));

  end = steady_clock::now();
  dur = duration_cast<measure_typ>(end - start).count();
  cout << endl << "[main.cpp]\t\tSetup operations complete (" << dur / 1000.0 << "s)" << endl << endl;


  // Simulate membership scenario using CODASPY group testing algorithm
  start = steady_clock::now();
  Ciphertext<DCRTPoly> rowCipher = sender.matrixMembershipQuery(queryCipher);
  end = steady_clock::now();
  dur = duration_cast<measure_typ>(end - start).count();
  cout << endl << "[main.cpp]\t\tSender operations complete (" << dur / 1000.0 << "s)" << endl << endl;

  start = steady_clock::now();
  cout << "\tResults of membership query: " << receiver.decryptMembershipQuery(rowCipher) << endl;
  end = steady_clock::now();
  dur = duration_cast<measure_typ>(end - start).count();
  cout << endl << "[main.cpp]\t\tReceiver operations complete (" << dur / 1000.0 << "s)" << endl << endl;

  /*
  // Simulate index scenario using CODASPY group testing algorithm
  start = steady_clock::now();
  auto [rowCipher, colCipher] = sender.matrixIndexQuery(queryCipher);
  end = steady_clock::now();
  dur = duration_cast<measure_typ>(end - start).count();
  cout << endl << "[main.cpp]\t\tSender operations complete (" << dur / 1000.0 << "s)" << endl << endl;

  start = steady_clock::now();
  cout << "\tResults of index query: " << receiver.decryptMatrixIndexQuery(rowCipher, colCipher) << endl;
  end = steady_clock::now();
  dur = duration_cast<measure_typ>(end - start).count();
  cout << endl << "[main.cpp]\t\tReceiver operations complete (" << dur / 1000.0 << "s)" << endl << endl;


  // Simulate the membership scenario using naive approach
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
  

  // Simulate the index scenario usig the naive approach
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
   */

  return 0;
}