#include "../include/receiver_base.h"

// implementation of functions declared in receiver_base.h

// -------------------- CONSTRUCTOR --------------------

BaseReceiver::BaseReceiver(CryptoContext<DCRTPoly> ccParam,
                         PublicKey<DCRTPoly> pkParam, PrivateKey<DCRTPoly> skParam, size_t vectorParam, ofstream& expStreamParam)
    : Receiver(ccParam, pkParam, skParam, vectorParam, expStreamParam) {}

// -------------------- PUBLIC FUNCTIONS --------------------

Ciphertext<DCRTPoly> BaseReceiver::encryptQuery(vector<double> query) {
  
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();

  query = VectorUtils::plaintextNormalize(query, VECTOR_DIM);
  vector<double> queryBatch(batchSize);
  for(size_t i = 0; i < batchSize; i += VECTOR_DIM) {
    copy(query.begin(), query.end(), queryBatch.begin() + i);
  }

  return OpenFHEWrapper::encryptFromVector(cc, pk, queryBatch);
}