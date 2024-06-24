#include "../include/sender.h"

// implementation of functions declared in sender.h
Sender::Sender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               int vectorParam)
    : cc(ccParam), pk(pkParam), numVectors(vectorParam) {}



void Sender::setDatabaseCipher(vector<Ciphertext<DCRTPoly>> databaseCipherParam) {
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



vector<Ciphertext<DCRTPoly>>
Sender::computeSimilarity(Ciphertext<DCRTPoly> query) {

  vector<Ciphertext<DCRTPoly>> similarityCipher(databaseCipher.size());

  // embarrassingly parallel
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for (size_t i = 0; i < databaseCipher.size(); i++) {
    similarityCipher[i] = cc->EvalInnerProduct(query, databaseCipher[i], VECTOR_DIM);
  }

  return similarityCipher;
}



// for n=reductionFactor, moves the n-th slots to the front of the cipher, sets all other slots to zero
// only works for reduction factors which are powers of 2
Ciphertext<DCRTPoly> Sender::mergeSingleCipher(Ciphertext<DCRTPoly> scoreCipher, int reductionFactor) {

  int batchSize = cc->GetEncodingParams()->GetBatchSize();
  int scoresPerBatch = batchSize / reductionFactor;

  // mergedCipher is the vector of ciphertexts to be returned
  Ciphertext<DCRTPoly> tempCipher;
  Ciphertext<DCRTPoly> currentBatchCipher;

  vector<double> reductionMask(batchSize);
  for(int i = 0; i < reductionFactor; i++) { reductionMask[i] = 1.0; }
  Plaintext reductionMaskPtxt = cc->MakeCKKSPackedPlaintext(reductionMask);

  // maskCount track the dimension of multiplicative masks needed
  int maskCount = 0;
  int rotationFactor = reductionFactor - 1;
  currentBatchCipher = scoreCipher;
  for(int i = 1; i < scoresPerBatch; i *= 2) {

    // if we have run out of padded zeros in the current batch cipher, update and apply multiplicative mask
    if(i == pow(reductionFactor, maskCount)) {
      fill(reductionMask.begin(), reductionMask.end(), 0.0);
      for(int j = 0; j < batchSize; j += pow(reductionFactor, maskCount+1)) {
        for(int k = 0; k < pow(reductionFactor, maskCount); k++) { 
          reductionMask[j + k] = 1.0;
        }
      }
      reductionMaskPtxt = cc->MakeCKKSPackedPlaintext(reductionMask);
      currentBatchCipher = cc->EvalMult(currentBatchCipher, reductionMaskPtxt);
      maskCount++;
    }

    tempCipher = OpenFHEWrapper::binaryRotate(cc, currentBatchCipher, rotationFactor * i);
    currentBatchCipher = cc->EvalAdd(currentBatchCipher, tempCipher);
  }

  vector<double> batchMask(batchSize);
  for(int i = 0; i < scoresPerBatch; i++) { batchMask[i] = 1.0; }
  Plaintext batchMaskPtxt = cc->MakeCKKSPackedPlaintext(batchMask);
  currentBatchCipher = cc->EvalMult(currentBatchCipher, batchMaskPtxt);

  return currentBatchCipher;
}


vector<Ciphertext<DCRTPoly>>
Sender::mergeScoresOrdered(vector<Ciphertext<DCRTPoly>> scoreCipher, int reductionDim) {

  int batchSize = cc->GetEncodingParams()->GetBatchSize();
  int scoresPerCipher = batchSize / reductionDim;
  int numScores = int(scoreCipher.size()) * scoresPerCipher;
  int neededCiphers = ceil(double(numScores) / double(batchSize));
  vector<Ciphertext<DCRTPoly>> mergedCipher(neededCiphers);

  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    scoreCipher[i] = mergeSingleCipher(scoreCipher[i], reductionDim);
  }

  int rotationFactor = 0;
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    rotationFactor = i * scoresPerCipher;
    scoreCipher[i] = OpenFHEWrapper::binaryRotate(cc, scoreCipher[i], -rotationFactor);
    if(rotationFactor % batchSize == 0) {
      mergedCipher[rotationFactor / batchSize] = scoreCipher[i];
    } else {
      mergedCipher[rotationFactor / batchSize] = cc->EvalAdd(mergedCipher[rotationFactor / batchSize], scoreCipher[i]);
    }
  }

  return mergedCipher;
}



vector<Ciphertext<DCRTPoly>>
Sender::mergeScores(vector<Ciphertext<DCRTPoly>> scoreCipher, int reductionDim) {

  int batchSize = cc->GetEncodingParams()->GetBatchSize();
  int neededCiphers = ceil(double(scoreCipher.size()) / double(reductionDim));
  vector<Ciphertext<DCRTPoly>> mergedCipher(neededCiphers);

  vector<double> scoreMask(batchSize);
  for(int i = 0; i < batchSize; i += reductionDim) {  scoreMask[i] = 1.0; }
  Plaintext scoreMaskPtxt = cc->MakeCKKSPackedPlaintext(scoreMask);

  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    scoreCipher[i] = cc->EvalMult(scoreCipher[i], scoreMaskPtxt);
  }

  for(size_t i = 0; i < scoreCipher.size(); i++) {
    scoreCipher[i] = OpenFHEWrapper::binaryRotate(cc, scoreCipher[i], -i);
    if(i % reductionDim == 0) {
      mergedCipher[i / reductionDim] = scoreCipher[i];
    } else {
      mergedCipher[i / reductionDim] = cc->EvalAdd(mergedCipher[i / reductionDim], scoreCipher[i]);
    }
  }

  return mergedCipher;
}



Ciphertext<DCRTPoly> Sender::alphaNormRows(vector<Ciphertext<DCRTPoly>> mergedCipher, int alpha, int rowLength) {
  
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < mergedCipher.size(); i++) {
    mergedCipher[i] = OpenFHEWrapper::alphaNorm(cc, mergedCipher[i], alpha, rowLength);
  }

  vector<Ciphertext<DCRTPoly>> resultCipher = mergeScores(mergedCipher, rowLength);
  if(resultCipher.size() > 1) {
    cerr << "Error: alpha-norm shouldn't be computed on rows of length greater than the batch size" << endl;
  }

  return resultCipher[0];
}



Ciphertext<DCRTPoly> Sender::alphaNormColumns(vector<Ciphertext<DCRTPoly>> mergedCipher, int alpha, int colLength) {

  int batchSize = cc->GetEncodingParams()->GetBatchSize();
  int scoresPerBatch = batchSize / colLength;
  
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < mergedCipher.size(); i++) {
    for(int a = 0; a < alpha; a++) {
      mergedCipher[i] = cc->EvalMult(mergedCipher[i], mergedCipher[i]);
    }
  }

  for(size_t i = 1; i < mergedCipher.size(); i++) {
    mergedCipher[0] = cc->EvalAdd(mergedCipher[0], mergedCipher[i]);
  }

  for(int i = 1; i < scoresPerBatch; i*=2) {
    mergedCipher[0] = cc->EvalAdd(mergedCipher[0], OpenFHEWrapper::binaryRotate(cc, mergedCipher[0], colLength*i));
  }

  vector<double> batchMask(batchSize);
  for(int i = 0; i < colLength; i++) {
    batchMask[i] = 1.0;
  }
  Plaintext batchMaskPtxt = cc->MakeCKKSPackedPlaintext(batchMask);
  mergedCipher[0] = cc->EvalMult(mergedCipher[0], batchMaskPtxt);

  return mergedCipher[0];
}



Ciphertext<DCRTPoly>
Sender::membershipQuery(Ciphertext<DCRTPoly> queryCipher) {

  int batchSize = cc->GetEncodingParams()->GetBatchSize();

  cout << "[sender.cpp]\tComputing similarity scores... " << flush;
  vector<Ciphertext<DCRTPoly>> similarityCipher = computeSimilarity(queryCipher);
  cout << "done" << endl;

  cout << "[sender.cpp]\tMerging similarity scores... " << flush;
  vector<Ciphertext<DCRTPoly>> mergedCipher = mergeScores(similarityCipher, VECTOR_DIM);
  cout << "done" << endl;

  cout << "[sender.cpp]\tApplying comparison function... " << flush;
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < mergedCipher.size(); i++) {
    mergedCipher[i] = cc->EvalAdd(mergedCipher[i], -MATCH_THRESHOLD);
    mergedCipher[i] = OpenFHEWrapper::sign(cc, mergedCipher[i]);
    mergedCipher[i] = OpenFHEWrapper::sumAllSlots(cc, mergedCipher[i]);
  }
  cout << "done" << endl;

  cout << "[sender.cpp]\tCombining result values... " << flush;
  // combine sums from all ciphertexts into first ciphertext, only return the first
  for(size_t i = 1; i < mergedCipher.size(); i++) {
    mergedCipher[0] = cc->EvalAdd(mergedCipher[0], mergedCipher[i]);
  }

  srand (time(0));
  vector<double> noiseValues(batchSize);
  noiseValues[0] = (rand() % 50) + 50.0; // random scalar from [50, 100]
  Plaintext noisePtxt = cc->MakeCKKSPackedPlaintext(noiseValues);
  mergedCipher[0] = cc->EvalMult(mergedCipher[0], noisePtxt);

  cout << "done" << endl;

  return mergedCipher[0];
}



vector<Ciphertext<DCRTPoly>> Sender::indexQuery(Ciphertext<DCRTPoly> queryCipher) {

  cout << "[sender.cpp]\tComputing similarity scores... " << flush;
  vector<Ciphertext<DCRTPoly>> similarityCipher = computeSimilarity(queryCipher);
  cout << "done" << endl;

  cout << "[sender.cpp]\tMerging similarity scores... " << flush;
  vector<Ciphertext<DCRTPoly>> mergedCipher = mergeScores(similarityCipher, VECTOR_DIM);
  cout << "done" << endl;

  cout << "[sender.cpp]\tApplying comparison function... " << flush;
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < mergedCipher.size(); i++) {
    mergedCipher[i] = cc->EvalAdd(mergedCipher[i], -MATCH_THRESHOLD);
    mergedCipher[i] = OpenFHEWrapper::sign(cc, mergedCipher[i]);
  }
  cout << "done" << endl;

  return mergedCipher;
}