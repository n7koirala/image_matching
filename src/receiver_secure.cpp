#include "../include/receiver_secure.h"

// implementation of functions declared in receiver_secure.h

SecurePreprocessingReceiver::SecurePreprocessingReceiver(CryptoContext<DCRTPoly> ccParam,
                       PublicKey<DCRTPoly> pkParam, PrivateKey<DCRTPoly> skParam, int vectorParam)
    : Receiver(ccParam, pkParam, skParam, vectorParam) {}

// Uses Newton's Method to approximate the inverse magnitude of a ciphertext
Ciphertext<DCRTPoly>
SecurePreprocessingReceiver::approxInverseMagnitude(Ciphertext<DCRTPoly> ctxt) {
  int batchSize = cc->GetEncodingParams()->GetBatchSize();

  auto bn = cc->EvalInnerProduct(ctxt, ctxt, VECTOR_DIM);

  // Uses a constant value for the initial approximation of Newton's method, sufficiently accurate for my random vector dataset
  // TODO: If a real-world dataset is used, this approximation should instead be set with a linear function, as in Panda 2021
  vector<double> initialGuess(batchSize, 0.001);
  Plaintext initialPtxt = cc->MakeCKKSPackedPlaintext(initialGuess);
  auto fn = cc->Encrypt(pk, initialPtxt);

  auto yn = fn;

  // Perform Newton's method to approximate inverse magnitude of ctxt
  // The multiplicative depth for i iterations is 3i+1
  for (int i = 0; i < NEWTONS_ITERATIONS; i++) {
    // b(n+1) = b(n) * f(n)^2
    bn = cc->EvalMult(bn, fn);
    bn = cc->EvalMult(bn, fn);

    // f(n+1) = (1/2) * (3 - b(n))
    fn = cc->EvalSub(3.0, bn);
    fn = cc->EvalMult(fn, 0.5);

    // y(n+1) = y(n) * f(n)
    yn = cc->EvalMult(yn, fn);
  }

  return yn;
}

Ciphertext<DCRTPoly> SecurePreprocessingReceiver::encryptQuery(vector<double> query) {
  int vectorsPerBatch =
      (int)(cc->GetEncodingParams()->GetBatchSize() / VECTOR_DIM);

  vector<double> batchedQuery(0);
  VectorUtils::concatenateVectors(batchedQuery, query, vectorsPerBatch);

  Plaintext queryPtxt = cc->MakeCKKSPackedPlaintext(batchedQuery);
  Ciphertext<DCRTPoly> queryCipher = cc->Encrypt(pk, queryPtxt);
  Ciphertext<DCRTPoly> inverseCipher = approxInverseMagnitude(queryCipher);
  queryCipher = cc->EvalMult(queryCipher, inverseCipher);
  return queryCipher;
}

vector<Ciphertext<DCRTPoly>>
SecurePreprocessingReceiver::encryptDB(vector<vector<double>> database) {
  int vectorsPerBatch =
      (int)(cc->GetEncodingParams()->GetBatchSize() / VECTOR_DIM);
  int totalBatches = (int)(numVectors / vectorsPerBatch + 1);

  vector<vector<double>> batchedDatabase(totalBatches, vector<double>(0));
  for (int i = 0; i < numVectors; i++) {
    int batchNum = (int)(i / vectorsPerBatch);
    VectorUtils::concatenateVectors(batchedDatabase[batchNum], database[i], 1);
  }

  Plaintext databasePtxt;
  vector<Ciphertext<DCRTPoly>> databaseCipher(totalBatches);
  Ciphertext<DCRTPoly> inverseCipher;

  // embarrassingly parallel
  #pragma omp parallel for num_threads(RECEIVER_NUM_CORES)
  for (int i = 0; i < totalBatches; i++) {
    databasePtxt = cc->MakeCKKSPackedPlaintext(batchedDatabase[i]);
    databaseCipher[i] = cc->Encrypt(pk, databasePtxt);
    inverseCipher = approxInverseMagnitude(databaseCipher[i]);
    databaseCipher[i] = cc->EvalMult(databaseCipher[i], inverseCipher);
  }
  return databaseCipher;
}