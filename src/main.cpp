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

// Entry point of the application that orchestrates the flow

int main(int argc, char *argv[]) {

  cout << "[main.cpp]\t\tMain execution entered..." << endl;

  chrono::steady_clock::time_point start, end, queryStart, queryEnd;
  chrono::duration<double> duration;
  
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

  size_t numVectors;
  fileStream >> numVectors;


  // Declare CKKS scheme elements
  CryptoContext<DCRTPoly> cc;
  cc->ClearEvalMultKeys();
  cc->ClearEvalAutomorphismKeys();
  CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
  PublicKey<DCRTPoly> pk;
  PrivateKey<DCRTPoly> sk;
  size_t batchSize;

  if (READ_FROM_SERIAL) { // Deserialize scheme context and keys if already serialized
  
    if(!Serial::DeserializeFromFile("serial/cryptocontext.bin", cc, SerType::BINARY)) {
      cerr << "Error deserializing CryptoContext" << endl;
    }
    batchSize = cc->GetEncodingParams()->GetBatchSize();

    if (!Serial::DeserializeFromFile("serial/publickey.bin", pk, SerType::BINARY)) {
      cerr << "Error deserializing public key" << endl;
    }

    
    if (!Serial::DeserializeFromFile("serial/privatekey.bin", sk, SerType::BINARY)) {
      cerr << "Error deserializing private key" << endl;
    }

    ifstream multKeyDeserialFile("serial/multkey.bin", ios::in | ios::binary);
    if (multKeyDeserialFile.is_open()) {
      if (!cc->DeserializeEvalMultKey(multKeyDeserialFile, SerType::BINARY)) {
        cerr << "Error deserializing mult keys" << endl;
      }
      multKeyDeserialFile.close();
    } else {
      cerr << "Error deserializing mult keys" << endl;
    }

    ifstream sumKeyDeserialFile("serial/sumkey.bin", ios::in | ios::binary);
    if (sumKeyDeserialFile.is_open()) {
      if (!cc->DeserializeEvalSumKey(sumKeyDeserialFile, SerType::BINARY)) {
        cerr << "Error deserializing sum keys" << endl;
      }
      sumKeyDeserialFile.close();
    } else {
      cerr << "Error deserializing sum keys" << endl;
    }

    ifstream rotKeyDeserialFile("serial/rotkey.bin", ios::in | ios::binary);
    if (rotKeyDeserialFile.is_open()) {
      if (!cc->DeserializeEvalAutomorphismKey(rotKeyDeserialFile, SerType::BINARY)) {
        cerr << "Error deserializing rotation keys" << endl;
      }
      rotKeyDeserialFile.close();
    } else {
      cerr << "Error deserializing rotation keys" << endl;
    }

  } else { // Else generate and serialize scheme context and keys

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetMultiplicativeDepth(12);
    parameters.SetScalingModSize(45);
    parameters.SetScalingTechnique(FIXEDMANUAL);

    cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    batchSize = cc->GetEncodingParams()->GetBatchSize();

    start = chrono::steady_clock::now();
    cout << "[main.cpp]\t\tGenerating key pair... " << flush;
    auto keyPair = cc->KeyGen();
    pk = keyPair.publicKey;
    sk = keyPair.secretKey;
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
    end = chrono::steady_clock::now();
    duration = end - start;
    cout << "done (Total keygen time:  " << duration.count() << "s)" << endl;
  }

  // OpenFHEWrapper::printSchemeDetails(parameters, cc);
  cout << "[main.cpp]\t\tCKKS scheme set up (batch size = " << batchSize << ")" << endl;

  // Experiment logging
  expStream << numVectors << '\t' << flush;
  expStream << duration.count() << '\t' << flush;

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

  // Initialize receiver, enroller, and sender objects -- only the receiver possesses the secret key
  Receiver receiver(cc, pk, sk, numVectors, expStream);
  Enroller enroller(cc, pk, numVectors);
  Sender sender(cc, pk, numVectors, expStream);

  // Serialize the context, keys and database vectors if not already
  if (!READ_FROM_SERIAL) {
    cout << "[main.cpp]\t\tEncrypting database vectors... " << flush;
    start = chrono::steady_clock::now();
    enroller.serializeDB(plaintextVectors);
    end = chrono::steady_clock::now();
    duration = end - start;
    cout << "done (" << duration.count() << "s)" << endl;
    expStream << duration.count() << '\t' << flush;

    Serial::SerializeToFile("serial/cryptocontext.bin", cc, SerType::BINARY);
    Serial::SerializeToFile("serial/publickey.bin", pk, SerType::BINARY);
    Serial::SerializeToFile("serial/privatekey.bin", sk, SerType::BINARY);

    ofstream multKeyFile("serial/multkey.bin", ios::out | ios::binary);
    if (multKeyFile.is_open()) {
      if (!cc->SerializeEvalMultKey(multKeyFile, SerType::BINARY)) {
        cerr << "Error serializing mult keys" << endl;
      }
      multKeyFile.close();
    } else {
      cerr << "Error serializing mult keys" << endl;
    }

    ofstream rotKeyFile("serial/rotkey.bin", ios::out | ios::binary);
    if (rotKeyFile.is_open()) {
      if (!cc->SerializeEvalAutomorphismKey(rotKeyFile, SerType::BINARY)) {
        cerr << "Error serializing rotation keys" << endl;
      }
      rotKeyFile.close();
    }
    else {
      cerr << "Error serializing rotation keys" << endl;
    }

    ofstream sumKeyFile("serial/sumkey.bin", ios::out | ios::binary);
    if (sumKeyFile.is_open()) {
      if (!cc->SerializeEvalSumKey(sumKeyFile, SerType::BINARY)) {
        cerr << "Error serializing sum keys" << endl;
      }
      sumKeyFile.close();
    }
    else {
      cerr << "Error serializing sum keys" << endl;
    }
  }
  
  // PER-QUERY OPERATIONS BEGIN HERE
  queryStart = chrono::steady_clock::now();

  // Normalize, batch, and encrypt the query vector
  cout << "[main.cpp]\t\tEncrypting query vector... " << flush;
  start = chrono::steady_clock::now();
  vector<Ciphertext<DCRTPoly>> queryCipher = receiver.encryptQuery(queryVector);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;
  expStream << duration.count() << '\t' << flush;

  // Perform membership scenario
  cout << "[main.cpp]\t\tRunning membership scenario... " << endl;
  start = chrono::steady_clock::now();
  Ciphertext<DCRTPoly> membershipCipher = sender.membershipScenarioNaive(queryCipher);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;
  bool membershipResult = receiver.decryptMembership(membershipCipher);
  cout << "Results: " << membershipResult << endl << endl;

  // Perform index scenario
  cout << "[main.cpp]\t\tRunning index scenario... " << endl;
  start = chrono::steady_clock::now();
  vector<Ciphertext<DCRTPoly>> indexCipher = sender.indexScenarioNaive(queryCipher);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;
  vector<size_t> indexResults = receiver.decryptIndexNaive(indexCipher);
  cout << "Results: " << indexResults << endl << endl;

  queryEnd = chrono::steady_clock::now();
  duration = queryEnd - queryStart;
  // cout << duration.count() << endl;

  // Experiment logging
  expStream << endl;
  expStream.close();
  return 0;
}