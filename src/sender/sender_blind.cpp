#include "../../include/sender_blind.h"

// implementation of functions declared in base_sender.h

// -------------------- CONSTRUCTOR --------------------

BlindSender::BlindSender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               size_t vectorParam)
    : HersSender(ccParam, pkParam, vectorParam) {}

// -------------------- PUBLIC FUNCTIONS --------------------

Ciphertext<DCRTPoly> BlindSender::membershipScenario(vector<Ciphertext<DCRTPoly>> &queryCipher) {

  // compute similarity scores between query and database
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);

  #pragma omp parallel for num_threads(MAX_NUM_CORES)
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    scoreCipher[i] = OpenFHEWrapper::chebyshevCompare(cc, scoreCipher[i], MATCH_THRESHOLD, COMP_DEPTH);
  }
  
  // sum up all values into single result value at first slot of first cipher
  Ciphertext<DCRTPoly> membershipCipher = cc->EvalAddManyInPlace(scoreCipher);
  membershipCipher = cc->EvalSum(membershipCipher, cc->GetEncodingParams()->GetBatchSize());

  return membershipCipher;
}

vector<Ciphertext<DCRTPoly>> BlindSender::indexScenario(vector<Ciphertext<DCRTPoly>> &queryCipher) {

  // compute similarity scores between query and database
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);

  #pragma omp parallel for num_threads(MAX_NUM_CORES)
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    scoreCipher[i] = OpenFHEWrapper::chebyshevCompare(cc, scoreCipher[i], MATCH_THRESHOLD, COMP_DEPTH);
  }

  return scoreCipher;
}

vector<Ciphertext<DCRTPoly>> BlindSender::computeSimilarity(vector<Ciphertext<DCRTPoly>> &queryCipher) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t chunksPerBatch = batchSize / CHUNK_LEN;
  size_t numMatrices = ceil(double(numVectors) / double(chunksPerBatch));

  vector<Ciphertext<DCRTPoly>> scoreCipher(numMatrices);

  for (size_t i = 0; i < numMatrices; i++) {
    scoreCipher[i] = computeSimilarityMatrix(queryCipher, CHUNK_LEN, i);
  }

  return OpenFHEWrapper::compressCiphers(cc, scoreCipher, CHUNK_LEN);
}

// -------------------- PROTECTED FUNCTIONS --------------------
Ciphertext<DCRTPoly> BlindSender::computeSimilarityMatrix(vector<Ciphertext<DCRTPoly>> &queryCipher, size_t chunkLength, size_t matrix) {

  size_t chunksPerVector = VECTOR_DIM / chunkLength;
  vector<Ciphertext<DCRTPoly>> matrixCipher(chunksPerVector);

  #pragma omp parallel for num_threads(MAX_NUM_CORES)
  for(size_t i = 0; i < chunksPerVector; i++) {
    matrixCipher[i] = computeSimilaritySerial(queryCipher[i], matrix, (i*chunkLength));
  }

  for(size_t i = 1; i < chunksPerVector; i++) {
    cc->EvalAddInPlace(matrixCipher[0], matrixCipher[i]);
  }

  cc->RelinearizeInPlace(matrixCipher[0]);
  cc->RescaleInPlace(matrixCipher[0]);

  Ciphertext<DCRTPoly> tempCipher;
  for (size_t r = 1; r < chunkLength; r *= 2) {
    tempCipher = OpenFHEWrapper::binaryRotate(cc, matrixCipher[0], r);
    cc->EvalAddInPlace(matrixCipher[0], tempCipher);
  }

  return matrixCipher[0];
}

Ciphertext<DCRTPoly> BlindSender::computeSimilaritySerial(Ciphertext<DCRTPoly> &queryCipher, size_t matrix, size_t index) {

  string filepath = "serial/db_blind/matrix" + to_string(matrix) + "/batch" + to_string(index) + ".bin";
  Ciphertext<DCRTPoly> databaseCipher;
  if (Serial::DeserializeFromFile(filepath, databaseCipher, SerType::BINARY) == false) {
    cerr << "Error: cannot deserialize from \"" << filepath << "\"" << endl;
  }

  return cc->EvalMultNoRelin(queryCipher, databaseCipher);
}