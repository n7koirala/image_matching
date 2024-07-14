#include "../include/sender.h"

// implementation of functions declared in sender.h
Sender::Sender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               int vectorParam)
    : cc(ccParam), pk(pkParam), numVectors(vectorParam) {}



void Sender::setDatabaseCipher(vector<vector<Ciphertext<DCRTPoly>>> databaseCipherParam) {
  databaseCipher = databaseCipherParam;
  return;
}


void Sender::serializeDatabaseCipher(string location) {
  cout << "[sender.cpp]\tSerializing encrypted database vector... " << flush;
  if (!Serial::SerializeToFile(location, databaseCipher[0], SerType::JSON)) {
      cout << "failed (cannot write to " << location << ")" << endl;
  } else {
    cout << "done" << endl;
  }
}



Ciphertext<DCRTPoly>
Sender::computeSimilarityHelper(size_t matrixIndex, vector<Ciphertext<DCRTPoly>> queryCipher) {

  vector<Ciphertext<DCRTPoly>> scoreCipher(VECTOR_DIM);
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < VECTOR_DIM; i++) {
    scoreCipher[i] = cc->EvalMultNoRelin(queryCipher[i], databaseCipher[matrixIndex][i]);
  }

  for(size_t i = 1; i < VECTOR_DIM; i++) {
    cc->EvalAddInPlace(scoreCipher[0], scoreCipher[i]);
  }

  cc->RelinearizeInPlace(scoreCipher[0]);
  cc->RescaleInPlace(scoreCipher[0]);

  return scoreCipher[0];
}

vector<Ciphertext<DCRTPoly>> Sender::computeSimilarity(vector<Ciphertext<DCRTPoly>> queryCipher) {
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t ciphersNeeded = ceil(double(numVectors) / double(batchSize));
  vector<Ciphertext<DCRTPoly>> similarityCipher(ciphersNeeded);

  for(size_t i = 0; i < ciphersNeeded; i++) {
    similarityCipher[i] = computeSimilarityHelper(i, queryCipher);
  }

  return similarityCipher;
}


Ciphertext<DCRTPoly> Sender::alphaNormRows(vector<Ciphertext<DCRTPoly>> mergedCipher, int alpha, int rowLength) {
  
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < mergedCipher.size(); i++) {
    mergedCipher[i] = OpenFHEWrapper::alphaNorm(cc, mergedCipher[i], alpha, rowLength);
  }

  vector<Ciphertext<DCRTPoly>> resultCipher; // = mergeScores(mergedCipher, rowLength);
  if(resultCipher.size() > 1) {
    cerr << "Error: alpha-norm shouldn't be computed on rows of length greater than the batch size" << endl;
  }

  return resultCipher[0];
}



Ciphertext<DCRTPoly> Sender::alphaNormColumns(vector<Ciphertext<DCRTPoly>> mergedCipher, int alpha, int colLength) {

  int batchSize = cc->GetEncodingParams()->GetBatchSize();
  int scoresPerBatch = batchSize / colLength;
  
  // raise all slots to the (2^a)th power
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < mergedCipher.size(); i++) {
    for(int a = 0; a < alpha; a++) {
      cc->EvalSquareInPlace(mergedCipher[i]);
    }
  }

  // add all ciphertexts in merged cipher together
  for(size_t i = 1; i < mergedCipher.size(); i++) {
    mergedCipher[0] = cc->EvalAdd(mergedCipher[0], mergedCipher[i]);
  }

  for(int i = 1; i < scoresPerBatch; i*=2) {
    mergedCipher[0] = cc->EvalAdd(mergedCipher[0], OpenFHEWrapper::binaryRotate(cc, mergedCipher[0], colLength*i));
  }

  vector<double> batchMask(batchSize, 0);
  for(int i = 0; i < colLength; i++) {
    batchMask[i] = 1.0;
  }
  Plaintext batchMaskPtxt = cc->MakeCKKSPackedPlaintext(batchMask);
  mergedCipher[0] = cc->EvalMult(mergedCipher[0], batchMaskPtxt);

  return mergedCipher[0];
}