// General functionality header files
#include "../include/config.h"
#include "../include/vector_utils.h"
#include "../include/openFHE_wrapper.h"
#include "openfhe.h"
#include <iostream>
#include <ctime>

// Receiver class header files
#include "../include/receiver_base.h"
#include "../include/receiver_blind.h"
#include "../include/receiver_diag.h"
#include "../include/receiver_grote.h"
#include "../include/receiver_hers.h"

// Enroller class header files
#include "../include/enroller_base.h"
#include "../include/enroller_blind.h"
#include "../include/enroller_diag.h"
#include "../include/enroller_hers.h"

// Sender class header files
#include "../include/sender_base.h"
#include "../include/sender_blind.h"
#include "../include/sender_diag.h"
#include "../include/sender_grote.h"
#include "../include/sender_hers.h"

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

  // Parse command line arg for experimental vector dataset
  ifstream fileStream;
  if (argc > 1) {
    fileStream.open(argv[1], ios::in);
  } else {
    cerr << "Error: input file not included" << endl;
    return 1;
  }
  if (!fileStream.is_open()) {
    cerr << "Error: unable to open input file" << endl;
    return 1;
  }
  size_t numVectors;
  fileStream >> numVectors;

  // Parse command line arg for experimental approach
  size_t expApproach;
  if (argc > 2) {
    expApproach = atoi(argv[2]);
  } else {
    cerr << "Error: approach argument not included" << endl;
    return 1;
  }
  if (expApproach < 1 || expApproach > 5) {
    cerr << "Error: approach must be from 1 to 5" << endl;
    return 1;
  }

  // Open global experiment-tracking file
  ofstream expStream;
  expStream.open(EXP_FILEPATH, ios::app);
  if (!expStream.is_open()) {
    cerr << "Error: experiment file not found" << endl;
    return 1;
  }

  // Compute required multiplicative depth based on approach used
  // Write approach used to stdout and experiment .csv file
  size_t multDepth = OpenFHEWrapper::computeRequiredDepth(expApproach);
  switch(expApproach) {
    
    case 1:
      cout << "Experimental approach: Literature baseline" << endl;
      expStream << "Baseline," << flush;
      break;

    case 2:
      cout << "Experimental approach: GROTE Paper" << endl;
      expStream << "GROTE," << flush;
      break;

    case 3:
      cout << "Experimental approach: Blind-Match paper" << endl;
      expStream << "Blind," << flush;
      break;

    case 4:
      cout << "Experimental approach: HERS paper" << endl;
      expStream << "HERS," << flush;
      break;
    
    case 5:
      cout << "Experimental approach: Novel diagonal transform" << endl;
      expStream << "Diagonal," << flush;
      break;
  }

  // Declare CKKS scheme elements
  CryptoContext<DCRTPoly> cc;
  cc->ClearEvalMultKeys();
  cc->ClearEvalAutomorphismKeys();
  CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
  PublicKey<DCRTPoly> pk;
  PrivateKey<DCRTPoly> sk;
  size_t batchSize;


  // Deserialize scheme context and keys if already serialized
  if (READ_FROM_SERIAL) {
  
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
    parameters.SetMultiplicativeDepth(multDepth);
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
    vector<int> rotationFactors(VECTOR_DIM-1);
    // generate keys from 1 to VECTOR_DIM
    iota(rotationFactors.begin(), rotationFactors.end(), 1);
    // generate positive binary rotation keys greater than VECTOR_DIM
    for(int i = VECTOR_DIM; i < int(batchSize); i *= 2) {
      rotationFactors.push_back(i);
    }
    // generate negative binary rotation keys 
    for(int i = 1; i < int(batchSize); i *= 2) {
      rotationFactors.push_back(-i);
    }
    cc->EvalRotateKeyGen(sk, rotationFactors);
  }

  // OpenFHEWrapper::printSchemeDetails(parameters, cc);
  cout << "CKKS scheme set up (depth = " << multDepth << ", batch size = " << batchSize << ")" << endl;

  // Log number of vectors to experiment file
  expStream << numVectors << "," << flush;

  // Read in query vector from file
  vector<double> queryVector(VECTOR_DIM);
  for (size_t i = 0; i < VECTOR_DIM; i++) {
    fileStream >> queryVector[i];
  }
  
  // Serialize the context, keys and database vectors if not already
  vector<vector<double>> plaintextVectors(numVectors, vector<double>(VECTOR_DIM));
  if (!READ_FROM_SERIAL) {
    
    cout << "Reading database vectors from file... " << endl;
    for (size_t i = 0; i < numVectors; i++) {
      for (size_t j = 0; j < VECTOR_DIM; j++) {
        fileStream >> plaintextVectors[i][j];
      }
    }

    cout << "Encrypting database vectors... " << endl;
    // Classes stored on heap to allow for cleaner polymorphism
    HersEnroller *enroller;

    if (expApproach == 1 || expApproach == 2) {
      enroller = new BaseEnroller(cc, pk, numVectors);
      static_cast<BaseEnroller*>(enroller)->serializeDB(plaintextVectors);
    } else if (expApproach == 3) {
      enroller = new BlindEnroller(cc, pk, numVectors);
      static_cast<BlindEnroller*>(enroller)->serializeDB(plaintextVectors, CHUNK_LEN);
    } else if (expApproach == 4) {
      enroller = new HersEnroller(cc, pk, numVectors);
      static_cast<HersEnroller*>(enroller)->serializeDB(plaintextVectors);
    } else if (expApproach == 5) {
      enroller = new DiagonalEnroller(cc, pk, numVectors);
      static_cast<DiagonalEnroller*>(enroller)->serializeDB(plaintextVectors);
    }
    delete enroller;

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

  Receiver *receiver = nullptr;
  Sender *sender = nullptr;
  bool membershipResult;
  vector<size_t> indexResults;

  // Allocate receiver and sender objects
  // receiver = new BaseReceiver(cc, pk, sk, numVectors);
  // sender = new BaseSender(cc, pk, numVectors);
  switch(expApproach) {
    
    case 1:
      receiver = new BaseReceiver(cc, pk, sk, numVectors);
      sender = new BaseSender(cc, pk, numVectors);
      break;

    case 2:
      receiver = new GroteReceiver(cc, pk, sk, numVectors);
      sender = new GroteSender(cc, pk, numVectors);
      break;

    case 3:
      receiver = new BlindReceiver(cc, pk, sk, numVectors);
      sender = new BlindSender(cc, pk, numVectors);
      break;

    case 4:
      receiver = new HersReceiver(cc, pk, sk, numVectors);
      sender = new HersSender(cc, pk, numVectors);
      break;
    
    case 5:
      receiver = new DiagonalReceiver(cc, pk, sk, numVectors);
      sender = new DiagonalSender(cc, pk, numVectors);
      break;
  }

  // Normalize, batch, and encrypt the query vector
  cout << "[Receiver]\tEncrypting query vector... " << flush;
  start = chrono::steady_clock::now();
  vector<Ciphertext<DCRTPoly>> queryCipher = receiver->encryptQuery(queryVector);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;
  expStream << duration.count() << "," << flush; // report query encryption time
  expStream << 1 << "," << flush; // report query communication overhead

  // Perform membership scenario
  cout << "[Sender]\tComputing membership scenario... " << flush;
  start = chrono::steady_clock::now();
  Ciphertext<DCRTPoly> membershipCipher = sender->membershipScenario(queryCipher);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;
  expStream << duration.count() << "," << flush; // report membership computation time
  expStream << 1 << "," << flush; // report membership communication overhead

  cout << "[Receiver]\tDecrypting membership results... " << flush;
  start = chrono::steady_clock::now();
  membershipResult = receiver->decryptMembership(membershipCipher);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;
  expStream << duration.count() << "," << flush;

  // Perform index scenario
  cout << "[Sender]\tComputing index scenario... " << flush;
  start = chrono::steady_clock::now();
  auto indexCipher = sender->indexScenario(queryCipher);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;
  expStream << duration.count() << "," << flush; // report index computation time
  expStream << indexCipher.size() << "," << flush; // report index communication overhead

  cout << "[Receiver]\tDecrypting index results... " << flush;
  start = chrono::steady_clock::now();
  indexResults = receiver->decryptIndex(indexCipher);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;
  expStream << duration.count() << "," << flush;

  // Displaying query results
  // The dataset-generation script creates datasets of size N with matches at indices 2 and N-1
  cout << endl << "\tDisplaying Query Results:" << endl;
  cout << "Membership scenario: " << flush;
  if (membershipResult) {
    cout << "true" << endl;
    expStream << "true" << "," << flush;
  } else {
    cout << "false" << endl;
    expStream << "false" << "," << flush;
  }
  cout << "Index scenario: " << flush;
  cout << indexResults << endl;
  expStream << indexResults << "," << flush;

  // Program cleanup
  expStream << endl;
  expStream.close();

  delete receiver;
  delete sender;

  cout << endl << "\tProgram successfully terminated" << endl;
  return 0;
}