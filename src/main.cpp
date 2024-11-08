#include "../include/config.h"
#include "../include/receiver.h"
#include "../include/receiver_base.h"
#include "../include/enroller.h"
#include "../include/enroller_base.h"
#include "../include/sender.h"
#include "../include/sender_base.h"
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

  cout << "\tRunning Setup Operations:" << endl;
  
  // Open global experiment-tracking file
  ofstream expStream;
  expStream.open("output/experiment.csv", ios::app);
  if (!expStream.is_open()) {
    cerr << "Error: experiment file not found" << endl;
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
    cerr << "Error: input file not found" << endl;
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
    parameters.SetMultiplicativeDepth(14);
    parameters.SetScalingModSize(45);
    parameters.SetScalingTechnique(FIXEDMANUAL);

    cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    batchSize = cc->GetEncodingParams()->GetBatchSize();

    cout << "Generating key pair... " << endl;
    auto keyPair = cc->KeyGen();
    pk = keyPair.publicKey;
    sk = keyPair.secretKey;

    cout << "Generating mult keys... " << endl;
    cc->EvalMultKeyGen(sk);

    cout << "Generating sum keys... " << endl;
    cc->EvalSumKeyGen(sk);

    cout << "Generating rotation keys... " << endl;
    vector<int> binaryRotationFactors;
    for(int i = 1; i < int(batchSize); i *= 2) {
      binaryRotationFactors.push_back(i);
      binaryRotationFactors.push_back(-i);
    }
    cc->EvalRotateKeyGen(sk, binaryRotationFactors);
  }

  // OpenFHEWrapper::printSchemeDetails(parameters, cc);
  cout << "CKKS scheme set up (batch size = " << batchSize << ")" << endl;

  // Experiment logging
  expStream << numVectors << "," << flush;

  // Read in query vector from file
  vector<double> queryVector(VECTOR_DIM);
  for (size_t i = 0; i < VECTOR_DIM; i++) {
    fileStream >> queryVector[i];
  }

  // Initialize receiver, enroller, and sender objects -- only the receiver possesses the secret key
  BaseReceiver receiver(cc, pk, sk, numVectors);
  BaseEnroller enroller(cc, pk, numVectors);
  BaseSender sender(cc, pk, numVectors);

  // Serialize the context, keys and database vectors if not already
  if (!READ_FROM_SERIAL) {
    
    cout << "Reading database vectors from file... " << endl;
    vector<vector<double>> plaintextVectors(numVectors, vector<double>(VECTOR_DIM));
    for (size_t i = 0; i < numVectors; i++) {
      for (size_t j = 0; j < VECTOR_DIM; j++) {
        fileStream >> plaintextVectors[i][j];
      }
    }

    cout << "Encrypting database vectors... " << endl;
    enroller.serializeDB(plaintextVectors);

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
  fileStream.close();
  
  // Individual-query experiments begin here
  cout << endl << "\tRunning Experiments:" << endl;
  chrono::steady_clock::time_point start, end;
  chrono::duration<double> duration;

  // Normalize, batch, and encrypt the query vector
  cout << "[Receiver]\tEncrypting query vector... " << flush;
  start = chrono::steady_clock::now();
  auto queryCipher = receiver.encryptQuery(queryVector); // auto needed here for dynamic polymorphism
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;
  expStream << duration.count() << "," << flush;

  // Perform membership scenario
  cout << "[Sender]\tComputing membership scenario... " << flush;
  start = chrono::steady_clock::now();
  Ciphertext<DCRTPoly> membershipCipher = sender.membershipScenario(queryCipher);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;
  expStream << duration.count() << "," << flush;

  cout << "[Receiver]\tDecrypting membership results... " << flush;
  start = chrono::steady_clock::now();
  bool membershipResult = receiver.decryptMembership(membershipCipher);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;
  expStream << duration.count() << "," << flush;

  // Perform index scenario
  cout << "[Sender]\tComputing index scenario... " << flush;
  start = chrono::steady_clock::now();
  vector<Ciphertext<DCRTPoly>> indexCipher = sender.indexScenario(queryCipher);
  end = chrono::steady_clock::now();
  duration = end - start;
  expStream << duration.count() << "," << flush;
  cout << "done (" << duration.count() << "s)" << endl;

  cout << "[Receiver]\tDecrypting index results... " << flush;
  start = chrono::steady_clock::now();
  vector<size_t> indexResults = receiver.decryptIndexNaive(indexCipher);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;
  expStream << duration.count() << "," << flush;

  // Verifying query results
  // The dataset-generation script creates datasets of size N with matches at indices 2 and N-1
  cout << endl << "\tVerifying Query Results:" << endl;
  cout << "Membership scenario: " << flush;
  if (membershipResult) {
    cout << "Correct" << endl;
    expStream << "true" << "," << flush;
  } else {
    cout << "Incorrect" << endl;
    expStream << "false" << "," << flush;
  }
  cout << "Index scenario: " << flush;
  if (indexResults.size() == 2 && indexResults[0] == 2 && indexResults[1] == numVectors-1) {
    cout << "Correct" << endl;
    expStream << "true" << "," << flush;
  } else {
    cout << "Incorrect" << endl;
    expStream << "false" << "," << flush;
  }

  // Experiment logging
  expStream << endl;
  expStream.close();
  cout << endl << "\tProgram successfully terminated" << endl;
  return 0;
}