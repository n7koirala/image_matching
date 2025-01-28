#include "../../include/enroller_base.h"

// implementation of functions declared in enroller.h

// -------------------- CONSTRUCTOR --------------------

BaseEnroller::BaseEnroller(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               size_t vectorParam)
    : HersEnroller(ccParam, pkParam, vectorParam) {}

// -------------------- PUBLIC FUNCTIONS --------------------

void BaseEnroller::serializeDB(vector<vector<double>> &database) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t vectorsPerBatch = batchSize / VECTOR_DIM;
  size_t numBatches = ceil(double(numVectors) / double(vectorsPerBatch));

  // create necessary directory if does not exist
  string dirpath = "serial/";
  if(!filesystem::exists(dirpath)) {
    if(!filesystem::create_directory(dirpath)) {
      cerr << "Error: Failed to create directory \"" + dirpath + "\"" << endl;
      return;
    }
  }

  // create matrix-specific directories if they don't exist
  string dirName = "serial/db_baseline/";
  if(!filesystem::exists(dirName)) {
    if(!filesystem::create_directory(dirName)) {
      cerr << "Error: Failed to create directory \"" + dirName + "\"" << endl;
    }
  }

  // normalize all plaintext database vectors
  #pragma omp parallel for num_threads(MAX_NUM_CORES)
  for (size_t i = 0; i < numVectors; i++) {
    database[i] = VectorUtils::plaintextNormalize(database[i], VECTOR_DIM);
  }

  // serialize all database vectors in sequential-batched format
  #pragma omp parallel for num_threads(MAX_NUM_CORES)
  for(size_t i = 0; i < numBatches; i++) {
    vector<double> currentVector(batchSize);
    for(size_t j = 0; j < min(vectorsPerBatch, numVectors - i*vectorsPerBatch); j++) {
      copy(database[j + i*vectorsPerBatch].begin(), database[j + i*vectorsPerBatch].end(), currentVector.begin()+j*VECTOR_DIM);
    }

    Ciphertext<DCRTPoly> currentCtxt = OpenFHEWrapper::encryptFromVector(cc, pk, currentVector);

    string filepath = "serial/db_baseline/batch" + to_string(i) + ".bin";
    if (!Serial::SerializeToFile(filepath, currentCtxt, SerType::BINARY)) {
      cerr << "Error: serialization failed (cannot write to " + filepath + ")" << endl;
    }
  }
}