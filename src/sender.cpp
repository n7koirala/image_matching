#include "../include/sender.h"

// implementation of functions declared in sender.h
Sender::Sender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               int vectorParam)
    : cc(ccParam), pk(pkParam), numVectors(vectorParam) {}

vector<Ciphertext<DCRTPoly>>
Sender::computeSimilarity(Ciphertext<DCRTPoly> query,
                          vector<Ciphertext<DCRTPoly>> database) {
  vector<Ciphertext<DCRTPoly>> similarityCipher(database.size());

  // embarrassingly parallel
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for (unsigned int i = 0; i < database.size(); i++) {
    similarityCipher[i] = cc->EvalInnerProduct(query, database[i], VECTOR_DIM);
  }
  cout << "[sender.cpp]\tSimilarity scores computed..." << endl;

  return mergeScores(similarityCipher);
}

// This implementation requires only two ciphertext multiplications per similarity ciphertext
// However, approach only works if VECTOR_DIM >= (batchSize / VECTOR_DIM)
// In our current case, VECTOR_DIM = 512 and (batchSize / VECTOR_DIM) = 16, therefore okay
// Essentially this needs to be modified if batchSize exceeds 262,144
vector<Ciphertext<DCRTPoly>> Sender::mergeScores(vector<Ciphertext<DCRTPoly>> similarityCipher) {

  int batchSize = cc->GetEncodingParams()->GetBatchSize();
  int scoresPerBatch = int(batchSize / VECTOR_DIM);
  int ciphersNeeded = 1 + int(numVectors / batchSize);
  int reductionFactor = batchSize / scoresPerBatch;

  // mergedCipher is the vector of ciphertexts to be returned
  Ciphertext<DCRTPoly> scoreMaskCipher;
  Ciphertext<DCRTPoly> batchMaskCipher;
  Ciphertext<DCRTPoly> tempCipher;
  Ciphertext<DCRTPoly> currentBatchCipher;
  vector<Ciphertext<DCRTPoly>> mergedCipher(ciphersNeeded);

  // mask used to isolate scores before merging, 1 at multiples of 512 indices, 0 elsewhere
  vector<double> scoreMask(batchSize);

  // mask used to isolate batches after merging, 1 in the first n/512 indices, 0 elsewhere
  vector<double> batchMask(batchSize);

  for(int i = 0; i < scoresPerBatch; i++) {
    scoreMask[i * VECTOR_DIM] = 1;
    batchMask[i] = 1;
  }

  Plaintext maskPtxt = cc->MakeCKKSPackedPlaintext(scoreMask);
  scoreMaskCipher = cc->Encrypt(pk, maskPtxt);
  maskPtxt = cc->MakeCKKSPackedPlaintext(batchMask);
  batchMaskCipher = cc->Encrypt(pk, maskPtxt);

  for(int i = 0; i < ciphersNeeded; i++) {
    for(int j = 0; j < reductionFactor; j++) {

      // check if we've merged all ciphertexts, therefore OOB
      if(j + i*reductionFactor >= int(similarityCipher.size())) {
        break;
      }

      // retain all similarity scores, set all garbage values to 0
      currentBatchCipher = cc->EvalMult(similarityCipher[j + i*reductionFactor], scoreMaskCipher);

      // perform rotations and additions to move similarity scores to front of ciphertext
      for(int rotationFactor = VECTOR_DIM - 1; rotationFactor < batchSize; rotationFactor *= 2) {
        tempCipher = cc->EvalRotate(currentBatchCipher, rotationFactor);
        currentBatchCipher = cc->EvalAdd(currentBatchCipher, tempCipher);
      }

      // retain all the merged scores at the front of the ciphertext, set the rest to 0
      currentBatchCipher = cc->EvalMult(currentBatchCipher, batchMaskCipher);
      
      // merge the scores from the current batch into the final outputted ciphertext
      if(j == 0) {
        mergedCipher[i] = currentBatchCipher;
      } else {
        currentBatchCipher = cc->EvalRotate(currentBatchCipher, j*-scoresPerBatch);
        mergedCipher[i] = cc->EvalAdd(mergedCipher[i], currentBatchCipher);
      }
    }
  }

  cout << "[sender.cpp]\tSimilarity scores merged..." << endl;
  return mergedCipher;
}