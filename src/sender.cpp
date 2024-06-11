#include "../include/sender.h"

// implementation of functions declared in sender.h
Sender::Sender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               int dimParam, int vectorParam)
    : cc(ccParam), pk(pkParam), vectorDim(dimParam), numVectors(vectorParam) {}

vector<Ciphertext<DCRTPoly>>
Sender::computeSimilarity(Ciphertext<DCRTPoly> query,
                          vector<Ciphertext<DCRTPoly>> database) {
  vector<Ciphertext<DCRTPoly>> similarityCipher(database.size());

  // embarrassingly parallel
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for (unsigned int i = 0; i < database.size(); i++) {
    similarityCipher[i] = cc->EvalInnerProduct(query, database[i], vectorDim);
  }
  return similarityCipher;
}

// This implementation requires only two ciphertext multiplications per similarity ciphertext
// However, approach only works if vectorDim >= (batchSize / vectorDim)
// In our use case, vectorDim = 512 and (batchSize / vectorDim) = 32, therefore okay
Ciphertext<DCRTPoly> Sender::mergeScores(vector<Ciphertext<DCRTPoly>> similarityCiphers) {

  int batchSize = cc->GetEncodingParams()->GetBatchSize();

  // merge operation requires four ciphertexts
  Ciphertext<DCRTPoly> mergedCipher;
  Ciphertext<DCRTPoly> tempCipher;
  Ciphertext<DCRTPoly> scoreMaskCipher;
  Ciphertext<DCRTPoly> batchMaskCipher;

  // mask used to isolate scores before merging, 1 at multiples of 512 indices, 0 elsewhere
  vector<double> scoreMask(batchSize);

  // mask used to isolate batches after merging, 1 in first n/512 indices, 0 elsewhere
  vector<double> batchMask(batchSize);

  for(int i = 0; i < int(batchSize / vectorDim); i++) {
    scoreMask[i * vectorDim] = 1;
    batchMask[i] = 1;
  }

  Plaintext maskPtxt = cc->MakeCKKSPackedPlaintext(scoreMask);
  scoreMaskCipher = cc->Encrypt(pk, maskPtxt);
  maskPtxt = cc->MakeCKKSPackedPlaintext(batchMask);
  batchMaskCipher = cc->Encrypt(pk, maskPtxt);

  // retain all similarity scores, set all garbage values to 0
  mergedCipher = cc->EvalMult(similarityCiphers[0], scoreMaskCipher);

  // perform rotations and additions to move similarity scores to front of ciphertext
  for(int rotationFactor = vectorDim - 1; rotationFactor < batchSize; rotationFactor *= 2) {
    tempCipher = cc->EvalRotate(mergedCipher, rotationFactor);
    mergedCipher = cc->EvalAdd(mergedCipher, tempCipher);
  }

  // retain all the merged scores at the start of the ciphertext, set the rest to 0
  mergedCipher = cc->EvalMult(mergedCipher, batchMaskCipher);

  return mergedCipher;
}