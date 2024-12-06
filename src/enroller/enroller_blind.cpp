#include "../../include/enroller_blind.h"

// implementation of functions declared in enroller.h

// -------------------- CONSTRUCTOR --------------------

BlindEnroller::BlindEnroller(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               size_t vectorParam)
    : Enroller(ccParam, pkParam, vectorParam) {}

// -------------------- PUBLIC FUNCTIONS --------------------

void BlindEnroller::serializeDB(vector<vector<double>> &database, size_t chunkLength) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t chunksPerBatch = batchSize / chunkLength;
  size_t numMatrices = ceil(double(numVectors) / double(chunksPerBatch));

  // create necessary directory if does not exist
  string dirName = "serial/";
  if(!filesystem::exists(dirName)) {
    if(!filesystem::create_directory(dirName)) {
      cerr << "Error: Failed to create directory \"" + dirName + "\"" << endl;
      return;
    }
  }

  // create matrix-specific directories if they don't exist
  dirName = "serial/db_blind";
  if(!filesystem::exists(dirName)) {
    if(!filesystem::create_directory(dirName)) {
      cerr << "Error: Failed to create directory \"" + dirName + "\"" << endl;
    }
  }

  for (size_t i = 0; i < numMatrices; i++) {
    // create matrix-specific directories if they don't exist
    dirName = "serial/db_blind/matrix" + to_string(i);
    if(!filesystem::exists(dirName)) {
      if(!filesystem::create_directory(dirName)) {
        cerr << "Error: Failed to create directory \"" + dirName + "\"" << endl;
      }
    }
  }

  // normalize all plaintext database vectors
  // #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  // for (size_t i = 0; i < numVectors; i++) {
  //   database[i] = VectorUtils::plaintextNormalize(database[i], VECTOR_DIM);
  // }

  for(size_t i = 0; i < numMatrices; i++) {

    // TODO: reintroduce parallelism after checking correctness
    // #pragma omp parallel for num_threads(SENDER_NUM_CORES)
    for(size_t j = 0; j < VECTOR_DIM; j += chunkLength) {
      serializeDBThread(database, chunkLength, i, j);
    }

  }

  return;
}

// -------------------- PROTECTED FUNCTIONS --------------------

void BlindEnroller::serializeDBThread(vector<vector<double>> &database, size_t chunkLength, size_t matrix, size_t index) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t chunksPerBatch = batchSize / chunkLength;
  size_t remainingVectors = numVectors - (matrix * chunksPerBatch);

  vector<double> currentVector(batchSize);
  // copy chunks from database into single vector to be encrypted and serialized
  for(size_t i = 0; i < chunksPerBatch && i < remainingVectors; i++) {

    // TODO: clean up readability
    copy(database[i + matrix*chunksPerBatch].begin() + index, 
      database[i + matrix*chunksPerBatch].begin() + index + chunkLength,
      currentVector.begin() + i*chunkLength);
    
  }

  // TESTING CORRECTNESS
  for(size_t i = 0; i < 10; i++) {
    cout << currentVector[i] << " ";
  }
  cout << endl;
  // TESTING CORRECTNESS

  Ciphertext<DCRTPoly> currentCtxt = OpenFHEWrapper::encryptFromVector(cc, pk, currentVector);

  string filepath = "serial/db_blind/matrix" + to_string(matrix) + "/batch" + to_string(index) + ".bin";
  if (!Serial::SerializeToFile(filepath, currentCtxt, SerType::BINARY)) {
    cerr << "Error: serialization failed (cannot write to " + filepath + ")" << endl;
  }

  return;
}