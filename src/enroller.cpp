#include "../include/enroller.h"

// implementation of functions declared in enroller.h
Enroller::Enroller(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               int vectorParam)
    : cc(ccParam), pk(pkParam), numVectors(vectorParam) {}


Ciphertext<DCRTPoly> Enroller::encryptDBThread(size_t matrix, size_t index, vector<vector<double>> database) {
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t startIndex = matrix * batchSize;

  vector<double> indexVector(batchSize);
  for(size_t k = startIndex; (k < startIndex + batchSize) && (k < size_t(numVectors)); k++) {
    indexVector[k % batchSize] = database[k][index];
  }

  return cc->Encrypt(pk, cc->MakeCKKSPackedPlaintext(indexVector));
}


vector<vector<Ciphertext<DCRTPoly>>>
Enroller::encryptDB(vector<vector<double>> database) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t numMatrices = ceil(double(numVectors) / double(batchSize));

  // normalize all plaintext database vectors
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for (int i = 0; i < numVectors; i++) {
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