#include "../../include/receiver_blind.h"

// implementation of functions declared in receiver_base.h

// -------------------- CONSTRUCTOR --------------------

BlindReceiver::BlindReceiver(CryptoContext<DCRTPoly> ccParam,
                         PublicKey<DCRTPoly> pkParam, PrivateKey<DCRTPoly> skParam, size_t vectorParam)
    : HersReceiver(ccParam, pkParam, skParam, vectorParam) {}

// -------------------- PUBLIC FUNCTIONS --------------------

vector<Ciphertext<DCRTPoly>> BlindReceiver::encryptQuery(vector<double> &query, size_t chunkLength) {

  size_t chunksPerVector = VECTOR_DIM / chunkLength; // number of chunks a 512-d vector is split into

  query = VectorUtils::plaintextNormalize(query, VECTOR_DIM);

  vector<Ciphertext<DCRTPoly>> queryVector(chunksPerVector);
  #pragma omp parallel for num_threads(MAX_NUM_CORES)
  for (size_t i = 0; i < chunksPerVector; i++) {
    queryVector[i] = encryptQueryThread(query, chunkLength, (i*chunkLength));
  }

  return queryVector;
}

vector<size_t> BlindReceiver::decryptIndex(vector<Ciphertext<DCRTPoly>> &indexCipher, size_t chunkLength) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t scoresPerBatch = batchSize / chunkLength;

  vector<size_t> outputValues;
  vector<double> indexValues;
  size_t batchStartingIndex, chunkStartingIndex, mergedChunkIndex;

  // Determine match indices according to pattern created by compression operation
  for(size_t i = 0; i < indexCipher.size(); i++) {
    indexValues = OpenFHEWrapper::decryptToVector(cc, sk, indexCipher[i]);

    for(size_t j = 0; j < batchSize; j++) {
      // If match is found during iterataion, append to returned list
      if(indexValues[j] >= 1.0) {
        batchStartingIndex = i * batchSize;
        chunkStartingIndex = j / chunkLength;
        mergedChunkIndex = (j % chunkLength) * scoresPerBatch;

        outputValues.push_back(batchStartingIndex + chunkStartingIndex + mergedChunkIndex);
      }
    }
  }
  
  return outputValues;
}

// -------------------- PROTECTED FUNCTIONS --------------------

Ciphertext<DCRTPoly> BlindReceiver::encryptQueryThread(vector<double> &query, size_t chunkLength, size_t index) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  vector<double> currentVector(batchSize);

  for (size_t i = 0; i < batchSize; i += chunkLength) {
    copy(query.begin() + index, 
      query.begin() + index + chunkLength,
      currentVector.begin() + i);
  }

  return OpenFHEWrapper::encryptFromVector(cc, pk, currentVector);

}