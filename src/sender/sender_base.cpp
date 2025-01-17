#include "../../include/sender_base.h"

// implementation of functions declared in sender_base.h

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

vector<Ciphertext<DCRTPoly>> BaseSender::computeSimilarityAndMerge(Ciphertext<DCRTPoly> queryCipher) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t vectorsPerBatch = batchSize / VECTOR_DIM;
  size_t numDatabaseCiphers = ceil(double(numVectors) / double(vectorsPerBatch));
  size_t outputSize = vectorsPerBatch * numDatabaseCiphers;
  size_t numMergedCiphers = ceil(double(outputSize) / double(batchSize));

  vector<Ciphertext<DCRTPoly>> mergedCipher(numMergedCiphers);

  // embarrassingly parallel
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for (size_t i = 0; i < numMergedCiphers; i++) {
    // populates mergedCipher with consecutively-packed similarity scores
    computeSimilarityAndMergeThread(queryCipher, mergedCipher[i], i);
  }

  return mergedCipher;
}


Ciphertext<DCRTPoly> BaseSender::membershipScenario(Ciphertext<DCRTPoly> queryCipher) {

  // compute similarity scores between query and database
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);
  // vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarityAndMerge(queryCipher);

  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    scoreCipher[i] = OpenFHEWrapper::chebyshevCompare(cc, scoreCipher[i], MATCH_THRESHOLD, COMP_DEPTH);
  }
  
  // sum up all values into single result value at first slot of first cipher
  Ciphertext<DCRTPoly> membershipCipher = cc->EvalAddManyInPlace(scoreCipher);
  membershipCipher = cc->EvalSum(membershipCipher, cc->GetEncodingParams()->GetBatchSize());

  return membershipCipher;
}


vector<Ciphertext<DCRTPoly>> BaseSender::indexScenario(Ciphertext<DCRTPoly> queryCipher) {

  // compute similarity scores between query and database
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);
  // vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarityAndMerge(queryCipher);
  
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    scoreCipher[i] = OpenFHEWrapper::chebyshevCompare(cc, scoreCipher[i], MATCH_THRESHOLD, COMP_DEPTH);
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

  // TODO: rewrite this using own sum function
  similarityCipher = cc->EvalInnerProduct(queryCipher, databaseCipher, VECTOR_DIM);
  cc->RelinearizeInPlace(similarityCipher);
  cc->RescaleInPlace(similarityCipher);

  return;
}

void BaseSender::computeSimilarityAndMergeThread(Ciphertext<DCRTPoly> &queryCipher, Ciphertext<DCRTPoly> &mergedCipher, size_t startingIndex) {
  
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t vectorsPerBatch = batchSize / VECTOR_DIM;
  size_t numDatabaseCiphers = ceil(double(numVectors) / double(vectorsPerBatch));
  
  Ciphertext<DCRTPoly> databaseCipher;
  string filepath;
  size_t currentIndex;

  // initialize mergedCipher to all zeros so we can add individually-merged ciphertexts to it
  mergedCipher = OpenFHEWrapper::encryptFromVector(cc, pk, {0});

  // for each database ciphertext in this thread's batch, do the following
  // deserialize db ciphertext
  // compute inner product of db cipher and query cipher
  // merge cosine similarity scores within that individual product cipher
  // rotate and add those merged similarity scores into the fully-packed singular output cipher
  for(size_t j = 0; j < VECTOR_DIM; j++) {

    currentIndex = (VECTOR_DIM * startingIndex) + j;
    if(currentIndex >= numDatabaseCiphers) {
      break;
    }

    filepath = "serial/database/batch" + to_string(currentIndex) + ".bin";
    if (!Serial::DeserializeFromFile(filepath, databaseCipher, SerType::BINARY)) {
        cerr << "Cannot read serialization from " << filepath << endl;
        break;
    }
    databaseCipher = cc->EvalInnerProduct(queryCipher, databaseCipher, VECTOR_DIM);
    cc->RelinearizeInPlace(databaseCipher);
    cc->RescaleInPlace(databaseCipher);
    databaseCipher = OpenFHEWrapper::mergeSingleCipher(cc, databaseCipher, VECTOR_DIM);

    cc->EvalAddInPlace(mergedCipher, OpenFHEWrapper::binaryRotate(cc, databaseCipher, -(vectorsPerBatch * j)));
  }

}