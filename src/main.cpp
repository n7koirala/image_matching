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

// experimenting with scheme switching -- discuss if this can be included?
// #include "binfhecontext.h"

using namespace lbcrypto;
using namespace std;
using namespace std::chrono;
using measure_typ = std::chrono::milliseconds;

// Entry point of the application that orchestrates the flow

int main(int argc, char *argv[]) {

  cout << "[main.cpp]\t\tMain execution entered..." << endl;

  steady_clock::time_point start, end;
  
  // Open global experiment-tracking file
  ofstream expStream;
  expStream.open("output/experiment.tsv", ios::app);
  if (!expStream.is_open()) {
    cerr << "[main.cpp]\t\tError: experiment file not found" << endl;
    return 1;
  }

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

  uint32_t multDepth = 1 + SIGN_DEPTH;
  CCParams<CryptoContextCKKSRNS> parameters;
  parameters.SetSecurityLevel(HEStd_128_classic);
  parameters.SetMultiplicativeDepth(multDepth);
  parameters.SetScalingModSize(45);
  parameters.SetScalingTechnique(FIXEDMANUAL);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(ADVANCEDSHE);
  
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();

  // OpenFHEWrapper::printSchemeDetails(parameters, cc);
  cout << "[main.cpp]\t\tCKKS scheme set up (depth = " << multDepth << ", batch size = " << batchSize << ")" << endl;

  start = steady_clock::now();
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
  for(int i = 1; i < int(batchSize); i *= 2) {
    binaryRotationFactors.push_back(i);
    binaryRotationFactors.push_back(-i);
  }
  cc->EvalRotateKeyGen(sk, binaryRotationFactors);
  end = steady_clock::now();
  cout << "done (Total keygen time:  " << duration_cast<measure_typ>(end - start).count() / 1000.0 << "s)" << endl;


  cout << "[main.cpp]\t\tReading in vectors from file... " << flush;
  size_t numVectors;
  fileStream >> numVectors;

  // Experiment logging
  expStream << numVectors << '\t' << flush;
  expStream << duration_cast<measure_typ>(end - start).count() / 1000.0 << '\t' << flush;

  // Read in query vector from file
  vector<double> queryVector(VECTOR_DIM);
  for (size_t i = 0; i < VECTOR_DIM; i++) {
    fileStream >> queryVector[i];
  }

  // Read in database vectors from file
  vector<vector<double>> plaintextVectors(numVectors, vector<double>(VECTOR_DIM));
  for (size_t i = 0; i < numVectors; i++) {
    for (size_t j = 0; j < VECTOR_DIM; j++) {
      fileStream >> plaintextVectors[i][j];
    }
  }
  fileStream.close();
  cout << "done (" << numVectors << " vectors)" << endl;


  // Initialize receiver, enroller, and sender objects -- only the receiver possesses the secret key
  Receiver receiver(cc, pk, sk, numVectors, expStream);
  Enroller enroller(cc, pk, numVectors);
  Sender sender(cc, pk, numVectors, expStream);


  // Normalize, batch, encrypt the database vectors
  cout << "[main.cpp]\t\tEncrypting database vectors... " << flush;
  start = steady_clock::now();
  enroller.serializeDB(plaintextVectors);
  end = steady_clock::now();
  cout << "done (" << duration_cast<measure_typ>(end - start).count() / 1000.0 << "s)" << endl;
  expStream << duration_cast<measure_typ>(end - start).count() / 1000.0 << '\t' << flush;
  

  // Normalize, batch, and encrypt the query vector
  cout << "[main.cpp]\t\tEncrypting query vector... " << flush;
  start = steady_clock::now();
  vector<Ciphertext<DCRTPoly>> queryCipher = receiver.encryptQuery(queryVector);
  end = steady_clock::now();
  cout << "done (" << duration_cast<measure_typ>(end - start).count() / 1000.0 << "s)" << endl;
  expStream << duration_cast<measure_typ>(end - start).count() / 1000.0 << '\t' << flush;


  // Perform naive membership scenario
  cout << "[main.cpp]\t\tRunning naive membership scenario... " << endl;
  start = steady_clock::now();
  Ciphertext<DCRTPoly> membershipCipher = sender.membershipScenarioNaive(queryCipher);
  end = steady_clock::now();
  cout << "done (" << duration_cast<measure_typ>(end - start).count() / 1000.0 << "s)" << endl;
  cout << "Results: " << receiver.decryptMembership(membershipCipher) << endl << endl;


  // Experiment logging
  expStream << endl;
  expStream.close();
  return 0;
}