#include "../include/enroller.h"

// implementation of functions declared in sender.h
Enroller::Enroller(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               int vectorParam)
    : cc(ccParam), pk(pkParam), numVectors(vectorParam) {}

vector<Ciphertext<DCRTPoly>>
Enroller::encryptDB(vector<vector<double>> database) {
  cout << "[enroller.cpp]\tEncrypting database vectors... " << flush;

  int vectorsPerBatch =
      (int)(cc->GetEncodingParams()->GetBatchSize() / VECTOR_DIM);
  int totalBatches = ceil(double(numVectors) / double(vectorsPerBatch));

  // embarrassingly parallel
  #pragma omp parallel for num_threads(RECEIVER_NUM_CORES)
  for (int i = 0; i < numVectors; i++) {
    database[i] = VectorUtils::plaintextNormalize(database[i], VECTOR_DIM);
  }

  vector<vector<double>> batchedDatabase(totalBatches, vector<double>(0));
  for (int i = 0; i < numVectors; i++) {
    int batchNum = (int)(i / vectorsPerBatch);
    VectorUtils::concatenateVectors(batchedDatabase[batchNum], database[i], 1);
  }

  Plaintext databasePtxt;
  vector<Ciphertext<DCRTPoly>> databaseCipher(totalBatches);

  // embarrassingly parallel
  #pragma omp parallel for num_threads(RECEIVER_NUM_CORES)
  for(int i = 0; i < totalBatches; i++) {
    databasePtxt = cc->MakeCKKSPackedPlaintext(batchedDatabase[i]);
    databaseCipher[i] = cc->Encrypt(pk, databasePtxt);
  }

  cout << "done (" << numVectors << " vectors, " << totalBatches << " ciphertexts)" << endl;
  return databaseCipher;
}