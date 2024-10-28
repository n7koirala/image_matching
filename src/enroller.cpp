#include "../include/enroller.h"

// implementation of functions declared in enroller.h

// -------------------- CONSTRUCTOR --------------------

Enroller::Enroller(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               size_t vectorParam)
    : cc(ccParam), pk(pkParam), numVectors(vectorParam) {}

// -------------------- PUBLIC FUNCTIONS --------------------

vector<vector<Ciphertext<DCRTPoly>>>
Enroller::encryptDB(vector<vector<double>> database) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t numMatrices = ceil(double(numVectors) / double(batchSize));

  // normalize all plaintext database vectors
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for (size_t i = 0; i < numVectors; i++) {
    database[i] = VectorUtils::plaintextNormalize(database[i], VECTOR_DIM);
  }

  vector<vector<Ciphertext<DCRTPoly>>> databaseCipher( numMatrices, vector<Ciphertext<DCRTPoly>>(VECTOR_DIM) );

  // encrypt normalized vectors in index-batched format
  // TODO -- parallelize outer loop?
  for(size_t i = 0; i < numMatrices; i++) {

    #pragma omp parallel for num_threads(SENDER_NUM_CORES)
    for(size_t j = 0; j < VECTOR_DIM; j++) {
      databaseCipher[i][j] = encryptDBThread(i, j, database);
    }

  }

  return databaseCipher;
}


void Enroller::serializeDB(vector<vector<double>> database) {

  // create necessary directory if does not exist
  string dirpath = "serial/";
  if(!filesystem::exists(dirpath)) {
    if(!filesystem::create_directory(dirpath)) {
      cerr << "Error: Failed to create directory \"" + dirpath + "\"" << endl;
      return;
    }
  }
  
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t numMatrices = ceil(double(numVectors) / double(batchSize));

  // create matrix-specific directories if they don't exist
  string dirName;
  for(size_t i = 0; i < numMatrices; i++) {
    // create necessary directory if does not exist
    dirName = "serial/matrix" + to_string(i) + "/";
    if(!filesystem::exists(dirName)) {
      if(!filesystem::create_directory(dirName)) {
        cerr << "Error: Failed to create directory \"" + dirName + "\"" << endl;
      }
    }
  }

  // normalize all plaintext database vectors
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for (size_t i = 0; i < numVectors; i++) {
    database[i] = VectorUtils::plaintextNormalize(database[i], VECTOR_DIM);
  }

  // encrypt normalized vectors in index-batched format
  for(size_t i = 0; i < numMatrices; i++) {
    
    #pragma omp parallel for num_threads(SENDER_NUM_CORES)
    for(size_t j = 0; j < VECTOR_DIM; j++) {
      serializeDBThread(i, j, database);
    }

  }
}

// -------------------- PRIVATE FUNCTIONS --------------------

Ciphertext<DCRTPoly> Enroller::encryptDBThread(size_t matrix, size_t index, vector<vector<double>> database) {
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t startIndex = matrix * batchSize;

  vector<double> indexVector(batchSize);
  for(size_t k = startIndex; (k < startIndex + batchSize) && (k < size_t(numVectors)); k++) {
    indexVector[k % batchSize] = database[k][index];
  }

  return cc->Encrypt(pk, cc->MakeCKKSPackedPlaintext(indexVector));
}


void Enroller::serializeDBThread(size_t matrix, size_t index, vector<vector<double>> &database) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t startIndex = matrix * batchSize;

  vector<double> indexVector(batchSize);
  for(size_t k = startIndex; (k < startIndex + batchSize) && (k < size_t(numVectors)); k++) {
    indexVector[k % batchSize] = database[k][index];
  }
  
  Ciphertext<DCRTPoly> ctxt = cc->Encrypt(pk, cc->MakeCKKSPackedPlaintext(indexVector));

  string filepath = "serial/matrix" + to_string(matrix) + "/index" + to_string(index) + ".bin";
  if (!Serial::SerializeToFile(filepath, ctxt, SerType::BINARY)) {
    cerr << "Error: serialization failed (cannot write to " + filepath + ")" << endl;
  }
}