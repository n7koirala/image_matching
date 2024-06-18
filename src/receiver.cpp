#include "../include/receiver.h"

// implementation of functions declared in receiver_plain.h
Receiver::Receiver(CryptoContext<DCRTPoly> ccParam,
                         PublicKey<DCRTPoly> pkParam, PrivateKey<DCRTPoly> skParam, int vectorParam)
    : cc(ccParam), pk(pkParam), sk(skParam), numVectors(vectorParam) {}



double Receiver::plaintextMagnitude(vector<double> x) {
  double m = 0.0;
  for (int i = 0; i < VECTOR_DIM; i++) {
    m += (x[i] * x[i]);
  }
  m = sqrt(m);
  return m;
}



double Receiver::plaintextInnerProduct(vector<double> x, vector<double> y) {
  double prod = 0.0;
  for (int i = 0; i < VECTOR_DIM; i++) {
    prod += x[i] * y[i];
  }
  return prod;
}



vector<double> Receiver::plaintextNormalize(vector<double> x) {
  double m = plaintextMagnitude(x);
  vector<double> x_norm = x;
  if (m != 0) {
    for (int i = 0; i < VECTOR_DIM; i++) {
      x_norm[i] = x[i] / m;
    }
  }
  return x_norm;
}



/* This computation involves division, cannot be done directly in encrypted
 * domain */
double Receiver::plaintextCosineSim(vector<double> x, vector<double> y) {
  return plaintextInnerProduct(x, y) /
         (plaintextMagnitude(x) * plaintextMagnitude(y));
}



Ciphertext<DCRTPoly> Receiver::encryptQuery(vector<double> query) {
  cout << "[receiver.cpp]\tEncrypting query vector... " << flush;
  int vectorsPerBatch =
      (int)(cc->GetEncodingParams()->GetBatchSize() / VECTOR_DIM);

  query = plaintextNormalize(query);

  vector<double> batchedQuery(0);
  VectorUtils::concatenateVectors(batchedQuery, query, vectorsPerBatch);

  Plaintext queryPtxt = cc->MakeCKKSPackedPlaintext(batchedQuery);
  Ciphertext<DCRTPoly> queryCipher = cc->Encrypt(pk, queryPtxt);

  cout << "done" << endl;
  return queryCipher;
}



vector<Ciphertext<DCRTPoly>>
Receiver::encryptDB(vector<vector<double>> database) {
  cout << "[receiver.cpp]\tEncrypting database vectors... " << flush;

  int vectorsPerBatch =
      (int)(cc->GetEncodingParams()->GetBatchSize() / VECTOR_DIM);
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

  // embarrassingly parallel
  #pragma omp parallel for num_threads(RECEIVER_NUM_CORES)
  for (int i = 0; i < totalBatches; i++) {
    databasePtxt = cc->MakeCKKSPackedPlaintext(batchedDatabase[i]);
    databaseCipher[i] = cc->Encrypt(pk, databasePtxt);
  }

  cout << "done" << endl;
  return databaseCipher;
}



vector<Plaintext> Receiver::decryptSimilarity(vector<Ciphertext<DCRTPoly>> cosineCipher) {
  int vectorsPerBatch =
      (int)(cc->GetEncodingParams()->GetBatchSize() / VECTOR_DIM);
  int totalBatches = (int)(numVectors / vectorsPerBatch + 1);
  vector<Plaintext> resultPtxts(totalBatches);
  for (int i = 0; i < totalBatches; i++) {
    cc->Decrypt(sk, cosineCipher[i], &(resultPtxts[i]));
  }
  return resultPtxts;
}



vector<double> Receiver::decryptMergedScores(vector<Ciphertext<DCRTPoly>> mergedCipher) {
  cout << "[receiver.cpp]\tDecrypting similarity scores... " << flush;
  vector<double> output;

  Plaintext mergedPtxt;
  vector<double> mergedValues;
  for(long unsigned int i = 0; i < mergedCipher.size(); i++) {
    cc->Decrypt(sk, mergedCipher[i], &(mergedPtxt));
    mergedValues = mergedPtxt->GetRealPackedValue();
    VectorUtils::concatenateVectors(output, mergedValues, 1);
  }

  cout << "done" << endl;
  return output;
}



double Receiver::decryptMembershipQuery(Ciphertext<DCRTPoly> membershipCipher) {
  cout << "[receiver.cpp]\tDecrypting membership query... " << flush;
  Plaintext membershipPtxt;
  cc->Decrypt(sk, membershipCipher, &membershipPtxt);
  vector<double> membershipValues = membershipPtxt->GetRealPackedValue();
  cout << "done" << endl;
  return membershipValues[0];
}