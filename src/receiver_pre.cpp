#include "../include/receiver_pre.h"

// implementation of functions declared in receiver_pre.h
ReceiverPre::ReceiverPre(CryptoContext<DCRTPoly> ccParam,
                         PublicKey<DCRTPoly> pkParam, int dimParam,
                         int vectorParam)
    : cc(ccParam), pk(pkParam), vectorDim(dimParam), numVectors(vectorParam) {}

double ReceiverPre::plaintextMagnitude(vector<double> x) {
  double m = 0.0;
  for (int i = 0; i < vectorDim; i++) {
    m += (x[i] * x[i]);
  }
  m = sqrt(m);
  return m;
}

double ReceiverPre::plaintextInnerProduct(vector<double> x, vector<double> y) {
  double prod = 0.0;
  for (int i = 0; i < vectorDim; i++) {
    prod += x[i] * y[i];
  }
  return prod;
}

vector<double> ReceiverPre::plaintextNormalize(vector<double> x) {
  double m = plaintextMagnitude(x);
  vector<double> x_norm = x;
  if (m != 0) {
    for (int i = 0; i < vectorDim; i++) {
      x_norm[i] = x[i] / m;
    }
  }
  return x_norm;
}

/* This computation involves division, cannot be done directly in encrypted
 * domain */
double ReceiverPre::plaintextCosineSim(vector<double> x, vector<double> y) {
  return plaintextInnerProduct(x, y) /
         (plaintextMagnitude(x) * plaintextMagnitude(y));
}

Ciphertext<DCRTPoly> ReceiverPre::encryptQuery(vector<double> query) {
  int vectorsPerBatch =
      (int)(cc->GetEncodingParams()->GetBatchSize() / vectorDim);

  query = plaintextNormalize(query);

  vector<double> batchedQuery(0);
  VectorUtils::concatenateVectors(batchedQuery, query, vectorsPerBatch);

  Plaintext queryPtxt = cc->MakeCKKSPackedPlaintext(batchedQuery);
  Ciphertext<DCRTPoly> queryCipher = cc->Encrypt(pk, queryPtxt);
  return queryCipher;
}

vector<Ciphertext<DCRTPoly>>
ReceiverPre::encryptDB(vector<vector<double>> database) {
  int vectorsPerBatch =
      (int)(cc->GetEncodingParams()->GetBatchSize() / vectorDim);
  int totalBatches = (int)(numVectors / vectorsPerBatch + 1);

  for (int i = 0; i < numVectors; i++) {
    database[i] = plaintextNormalize(database[i]);
  }

  vector<vector<double>> batchedDatabase(totalBatches, vector<double>(0));
  for (int i = 0; i < numVectors; i++) {
    int batchNum = (int)(i / vectorsPerBatch);
    VectorUtils::concatenateVectors(batchedDatabase[batchNum], database[i], 1);
  }

  Plaintext databasePtxt;
  vector<Ciphertext<DCRTPoly>> databaseCipher(totalBatches);
  for (int i = 0; i < totalBatches; i++) {
    databasePtxt = cc->MakeCKKSPackedPlaintext(batchedDatabase[i]);
    databaseCipher[i] = cc->Encrypt(pk, databasePtxt);
  }

  return databaseCipher;
}