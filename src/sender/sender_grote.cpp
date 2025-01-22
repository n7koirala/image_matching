#include "../../include/sender_grote.h"

// implementation of functions declared in sender_grote.h

// -------------------- CONSTRUCTOR --------------------

GroteSender::GroteSender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               size_t vectorParam)
    : BaseSender(ccParam, pkParam, vectorParam) {}

// -------------------- PUBLIC FUNCTIONS --------------------

Ciphertext<DCRTPoly> GroteSender::membershipScenario(Ciphertext<DCRTPoly> queryCipher) {

  cout << "GROTE membership scenario" << endl;

  // row length is the power of 2 closest to sqrt(batchSize)
  // dividing scores into square matrix as close as possible
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t rowLength = pow(2.0, ceil(log2(batchSize) / 2.0));

    // compute similarity scores between query and database
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);
  
  vector<Ciphertext<DCRTPoly>> colCipher = alphaNormColumns(scoreCipher, ALPHA_DEPTH, rowLength);

  #pragma omp parallel for num_threads(MAX_NUM_CORES)
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    scoreCipher[i] = OpenFHEWrapper::chebyshevCompare(cc, scoreCipher[i], MATCH_THRESHOLD, COMP_DEPTH);
  }
  
  // sum up all values into single result value at first slot of first cipher
  Ciphertext<DCRTPoly> membershipCipher = cc->EvalAddManyInPlace(scoreCipher);
  membershipCipher = cc->EvalSum(membershipCipher, cc->GetEncodingParams()->GetBatchSize());

  // return ciphertext containing boolean (0/1) result value
  return membershipCipher;
}

tuple<vector<Ciphertext<DCRTPoly>>, vector<Ciphertext<DCRTPoly>>> 
GroteSender::indexScenario(Ciphertext<DCRTPoly> queryCipher) {

  // row length is the power of 2 closest to sqrt(batchSize)
  // dividing scores into square matrix as close as possible
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t rowLength = pow(2.0, ceil(log2(batchSize) / 2.0));
  
  // compute similarity scores between query and database
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);

  // compute row and column maxes for group testing
  vector<Ciphertext<DCRTPoly>> rowCipher = alphaNormRows(scoreCipher, ALPHA_DEPTH, rowLength);

  vector<Ciphertext<DCRTPoly>> colCipher = alphaNormColumns(scoreCipher, ALPHA_DEPTH, rowLength);

  // since we are squaring score values ALPHA_DEPTH times, we must do the same for the comparison threshold
  double adjustedThreshold = MATCH_THRESHOLD;
  for(size_t a = 0; a < ALPHA_DEPTH; a++) {
    adjustedThreshold = adjustedThreshold * adjustedThreshold;
  }

  #pragma omp parallel for num_threads(MAX_NUM_CORES)
  for(size_t i = 0; i < rowCipher.size(); i++) {
    rowCipher[i] = OpenFHEWrapper::chebyshevCompare(cc, rowCipher[i], adjustedThreshold, COMP_DEPTH);
  }

  #pragma omp parallel for num_threads(MAX_NUM_CORES)
  for(size_t i = 0; i < colCipher.size(); i++) {
    colCipher[i] = OpenFHEWrapper::chebyshevCompare(cc, colCipher[i], adjustedThreshold, COMP_DEPTH);
  }

  // return boolean (0/1) values dictating which rows and columns contain matches
  return make_tuple(rowCipher, colCipher);
}