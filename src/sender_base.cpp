#include "../include/sender_base.h"

// implementation of functions declared in base_sender.h

// -------------------- CONSTRUCTOR --------------------

BaseSender::BaseSender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               size_t vectorParam)
    : Sender(ccParam, pkParam, vectorParam) {}

// -------------------- PUBLIC FUNCTIONS --------------------

vector<Ciphertext<DCRTPoly>> BaseSender::computeSimilarity(Ciphertext<DCRTPoly> queryCipher) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t vectorsPerBatch = batchSize / VECTOR_DIM;
  size_t numBatches = ceil(double(numVectors) / double(vectorsPerBatch));
  vector<Ciphertext<DCRTPoly>> similarityCipher(numBatches);

  // embarrassingly parallel
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for (size_t i = 0; i < numBatches; i++) {
    computeSimilarityThread(queryCipher, similarityCipher[i], i);
  }
  
  return OpenFHEWrapper::mergeCiphers(cc, similarityCipher, VECTOR_DIM);
}


Ciphertext<DCRTPoly> BaseSender::membershipScenario(Ciphertext<DCRTPoly> queryCipher) {

  // compute similarity scores between query and database
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);

  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    scoreCipher[i] = OpenFHEWrapper::chebyshevCompare(cc, scoreCipher[i], MATCH_THRESHOLD, CHEBYSHEV_DEGREE);
  }
  
  // sum up all values into single result value at first slot of first cipher
  Ciphertext<DCRTPoly> membershipCipher = cc->EvalAddManyInPlace(scoreCipher);
  membershipCipher = cc->EvalSum(membershipCipher, cc->GetEncodingParams()->GetBatchSize());

  return membershipCipher;
}


vector<Ciphertext<DCRTPoly>> BaseSender::indexScenario(Ciphertext<DCRTPoly> queryCipher) {

  // compute similarity scores between query and database
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);
  
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    scoreCipher[i] = OpenFHEWrapper::chebyshevCompare(cc, scoreCipher[i], MATCH_THRESHOLD, CHEBYSHEV_DEGREE);
  }
  
  return scoreCipher;
}

// -------------------- PROTECTED FUNCTIONS --------------------
void BaseSender::computeSimilarityThread(Ciphertext<DCRTPoly> &queryCipher, Ciphertext<DCRTPoly> &similarityCipher, size_t databaseIndex) {

  Ciphertext<DCRTPoly> databaseCipher;
  string filepath = "serial/database/batch" + to_string(databaseIndex) + ".bin";
  if (!Serial::DeserializeFromFile(filepath, databaseCipher, SerType::BINARY)) {
      cerr << "Cannot read serialization from " << filepath << endl;
  }

  similarityCipher = cc->EvalInnerProduct(queryCipher, databaseCipher, VECTOR_DIM);
  cc->RelinearizeInPlace(similarityCipher);
  cc->RescaleInPlace(similarityCipher);

  return;
}