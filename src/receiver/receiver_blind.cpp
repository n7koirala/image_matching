#include "../../include/receiver_blind.h"

// implementation of functions declared in receiver_base.h

// -------------------- CONSTRUCTOR --------------------

BlindReceiver::BlindReceiver(CryptoContext<DCRTPoly> ccParam,
                         PublicKey<DCRTPoly> pkParam, PrivateKey<DCRTPoly> skParam, size_t vectorParam)
    : Receiver(ccParam, pkParam, skParam, vectorParam) {}

// -------------------- PUBLIC FUNCTIONS --------------------

vector<Ciphertext<DCRTPoly>> BlindReceiver::encryptQuery(vector<double> &query, size_t chunkLength) {

  size_t chunksPerVector = VECTOR_DIM / chunkLength; // number of chunks a 512-d vector is split into

  // TODO: include multithreading
  // #pragma omp parallel for num_threads(RECEIVER_NUM_CORES)
  vector<Ciphertext<DCRTPoly>> queryVector(chunksPerVector);
  for (size_t i = 0; i < chunksPerVector; i++) {
    queryVector[i] = encryptQueryThread(query, chunkLength, (i*chunkLength));
  }

  return queryVector;
}

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