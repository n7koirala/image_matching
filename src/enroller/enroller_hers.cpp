#include "../../include/enroller_hers.h"

// implementation of functions declared in enroller.h

// -------------------- CONSTRUCTOR --------------------

HersEnroller::HersEnroller(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               size_t vectorParam)
    : cc(ccParam), pk(pkParam), numVectors(vectorParam) {}

// -------------------- PUBLIC FUNCTIONS --------------------

vector<vector<Ciphertext<DCRTPoly>>>
HersEnroller::encryptDB(vector<vector<double>> &database) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t numMatrices = ceil(double(numVectors) / double(batchSize));

  // normalize all plaintext database vectors
  #pragma omp parallel for num_threads(MAX_NUM_CORES)
  for (size_t i = 0; i < numVectors; i++) {
    database[i] = VectorUtils::plaintextNormalize(database[i], VECTOR_DIM);
  }

  vector<vector<Ciphertext<DCRTPoly>>> databaseCipher( numMatrices, vector<Ciphertext<DCRTPoly>>(VECTOR_DIM) );

  // encrypt normalized vectors in index-batched format
  for(size_t i = 0; i < numMatrices; i++) {

    #pragma omp parallel for num_threads(MAX_NUM_CORES)
    for(size_t j = 0; j < VECTOR_DIM; j++) {
      databaseCipher[i][j] = encryptDBThread(i, j, database);
    }

  }

  return databaseCipher;
}


void HersEnroller::serializeDB(vector<vector<double>> &database) {

  // create necessary directories if they do not exist
  string dirpath = "serial/";
  if(!filesystem::exists(dirpath)) {
    if(!filesystem::create_directory(dirpath)) {
      cerr << "Error: Failed to create directory \"" + dirpath + "\"" << endl;
      return;
    }
  }

  dirpath = "serial/db_hers/";
  if(!filesystem::exists(dirpath)) {
    if(!filesystem::create_directory(dirpath)) {
      cerr << "Error: Failed to create directory \"" + dirpath + "\"" << endl;
      return;
    }
  }
  
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t numMatrices = ceil(double(numVectors) / double(batchSize));

  // create matrix-specific directories if they don't exist
  for(size_t i = 0; i < numMatrices; i++) {
    // create necessary directory if does not exist
    dirpath = "serial/db_hers/matrix" + to_string(i) + "/";
    if(!filesystem::exists(dirpath)) {
      if(!filesystem::create_directory(dirpath)) {
        cerr << "Error: Failed to create directory \"" + dirpath + "\"" << endl;
      }
    }
  }

  // normalize all plaintext database vectors
  #pragma omp parallel for num_threads(MAX_NUM_CORES)
  for (size_t i = 0; i < numVectors; i++) {
    database[i] = VectorUtils::plaintextNormalize(database[i], VECTOR_DIM);
  }

  // encrypt normalized vectors in index-batched format
  for(size_t i = 0; i < numMatrices; i++) {
    
    #pragma omp parallel for num_threads(MAX_NUM_CORES)
    for(size_t j = 0; j < VECTOR_DIM; j++) {
      serializeDBThread(i, j, database);
    }

  }
}

// -------------------- PRIVATE FUNCTIONS --------------------

Ciphertext<DCRTPoly> HersEnroller::encryptDBThread(size_t matrix, size_t index, vector<vector<double>> &database) {
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t startIndex = matrix * batchSize;

  vector<double> indexVector(batchSize);
  for(size_t k = startIndex; (k < startIndex + batchSize) && (k < size_t(numVectors)); k++) {
    indexVector[k % batchSize] = database[k][index];
  }

  return cc->Encrypt(pk, cc->MakeCKKSPackedPlaintext(indexVector));
}


void HersEnroller::serializeDBThread(size_t matrix, size_t index, vector<vector<double>> &database) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t startIndex = matrix * batchSize;

  vector<double> indexVector(batchSize);
  for(size_t k = startIndex; (k < startIndex + batchSize) && (k < size_t(numVectors)); k++) {
    indexVector[k % batchSize] = database[k][index];
  }
  
  Ciphertext<DCRTPoly> ctxt = OpenFHEWrapper::encryptFromVector(cc, pk, indexVector);

  string filepath = "serial/db_hers/matrix" + to_string(matrix) + "/index" + to_string(index) + ".bin";
  if (!Serial::SerializeToFile(filepath, ctxt, SerType::BINARY)) {
    cerr << "Error: serialization failed (cannot write to " + filepath + ")" << endl;
  }
}