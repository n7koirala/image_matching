#include "../../include/sender_diag.h"

// implementation of functions declared in sender_diag.h

// -------------------- CONSTRUCTOR --------------------

DiagonalSender::DiagonalSender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               size_t vectorParam)
    : Sender(ccParam, pkParam, vectorParam) {}

// -------------------- PUBLIC FUNCTIONS --------------------
vector<Ciphertext<DCRTPoly>> DiagonalSender::computeSimilarity(Ciphertext<DCRTPoly> &queryCipher) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t cyclotomicOrder = 2 * cc->GetRingDimension(); // needed for fast hoisted rotations
  size_t numMatrices = ceil(double(numVectors) / double(batchSize));
  vector<Ciphertext<DCRTPoly>> similarityCipher(numMatrices);

  // generate all rotations of batched query vector
  vector<Ciphertext<DCRTPoly>> rotatedQueryCipher(VECTOR_DIM);
  rotatedQueryCipher[0] = queryCipher;
  shared_ptr<vector<DCRTPoly>> queryPrecomp = cc->EvalFastRotationPrecompute(queryCipher); // needed for fast hoisted rotations
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 1; i < VECTOR_DIM; i++) {
    rotatedQueryCipher[i] = cc->EvalFastRotation(queryCipher, i, cyclotomicOrder, queryPrecomp);
  }

  for(size_t m = 0; m < numMatrices; m++) {
    similarityCipher[m] = computeSimilarityMatrix(rotatedQueryCipher, m);
  }

  return similarityCipher;
}

Ciphertext<DCRTPoly> DiagonalSender::membershipScenario(Ciphertext<DCRTPoly> &queryCipher) {

  // compute similarity scores between query and database
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);
  
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    scoreCipher[i] = OpenFHEWrapper::chebyshevCompare(cc, scoreCipher[i], MATCH_THRESHOLD, COMP_DEPTH);
  }
  
  // sum up all values into single result value at first slot of first cipher
  Ciphertext<DCRTPoly> membershipCipher = cc->EvalAddManyInPlace(scoreCipher);
  membershipCipher = cc->EvalSum(membershipCipher, cc->GetEncodingParams()->GetBatchSize());

  return membershipCipher;
}

vector<Ciphertext<DCRTPoly>> DiagonalSender::indexScenario(Ciphertext<DCRTPoly> &queryCipher) {

  // compute similarity scores between query and database
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);
  
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    scoreCipher[i] = OpenFHEWrapper::chebyshevCompare(cc, scoreCipher[i], MATCH_THRESHOLD, COMP_DEPTH);
  }
  
  return scoreCipher;
}

// -------------------- PROTECTED FUNCTIONS --------------------
Ciphertext<DCRTPoly> DiagonalSender::computeSimilarityMatrix(vector<Ciphertext<DCRTPoly>> &queryCipher, size_t matrix) {

  vector<Ciphertext<DCRTPoly>> scoreCipher(VECTOR_DIM);

  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < VECTOR_DIM; i++) {
    scoreCipher[i] = computeSimilarityThread(queryCipher[i], matrix, i);
  }

  for(size_t i = 1; i < VECTOR_DIM; i++) {
    cc->EvalAddInPlace(scoreCipher[0], scoreCipher[i]);
  }

  cc->RelinearizeInPlace(scoreCipher[0]);
  cc->RescaleInPlace(scoreCipher[0]);

  return scoreCipher[0];
}

Ciphertext<DCRTPoly> DiagonalSender::computeSimilarityThread(Ciphertext<DCRTPoly> &queryCipher, size_t matrix, size_t index) {

  string filepath = "serial/db_diagonal/index" + to_string(matrix * VECTOR_DIM + index) + ".bin";
  Ciphertext<DCRTPoly> databaseCipher;
  if (Serial::DeserializeFromFile(filepath, databaseCipher, SerType::BINARY) == false) {
    cerr << "Error: cannot deserialize from \"" << filepath << "\"" << endl;
  }

  return cc->EvalMultNoRelin(queryCipher, databaseCipher);
}