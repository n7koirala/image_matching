#include "../include/receiver.h"

// implementation of functions declared in receiver_plain.h
Receiver::Receiver(CryptoContext<DCRTPoly> ccParam,
                         PublicKey<DCRTPoly> pkParam, PrivateKey<DCRTPoly> skParam, int vectorParam)
    : cc(ccParam), pk(pkParam), sk(skParam), numVectors(vectorParam) {}



Ciphertext<DCRTPoly> Receiver::encryptQuery(vector<double> query) {
  cout << "[receiver.cpp]\tEncrypting query vector... " << flush;
  int vectorsPerBatch =
      (int)(cc->GetEncodingParams()->GetBatchSize() / VECTOR_DIM);

  query = VectorUtils::plaintextNormalize(query, VECTOR_DIM);

  vector<double> batchedQuery(0);
  VectorUtils::concatenateVectors(batchedQuery, query, vectorsPerBatch);

  Plaintext queryPtxt = cc->MakeCKKSPackedPlaintext(batchedQuery);
  Ciphertext<DCRTPoly> queryCipher = cc->Encrypt(pk, queryPtxt);

  cout << "done" << endl;
  return queryCipher;
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



bool Receiver::decryptMembershipQuery(Ciphertext<DCRTPoly> membershipCipher) {
  cout << "[receiver.cpp]\tDecrypting membership query... " << flush;

  Plaintext membershipPtxt;
  cc->Decrypt(sk, membershipCipher, &membershipPtxt);
  vector<double> membershipValues = membershipPtxt->GetRealPackedValue();
  bool matchExists = false;

  if(membershipValues[0] >= 1.0) {
    matchExists = true;
  }

  cout << "done" << endl;
  return matchExists;
}


vector<int> Receiver::decryptIndexQuery(vector<Ciphertext<DCRTPoly>> indexCipher) {
  cout << "[receiver.cpp]\tDecrypting index query... " << flush;

  int batchSize = cc->GetEncodingParams()->GetBatchSize();
  vector<int> outputValues;
  vector<double> indexValues;
  Plaintext indexPtxt;
  int currentIndex;

  for(size_t i = 0; i < indexCipher.size(); i++) {
    cc->Decrypt(sk, indexCipher[i], &indexPtxt);
    indexValues = indexPtxt->GetRealPackedValue();

    currentIndex = 0;
    for(int j = 0; j < batchSize; j++) {

      if(round(indexValues[currentIndex]) == 1) {
        outputValues.push_back(j);
      }

      currentIndex += VECTOR_DIM;
      if(currentIndex >= batchSize) {
        currentIndex = (currentIndex % batchSize) + 1;
      }
    }
  }
  
  cout << "done" << endl;
  return outputValues;
}


vector<size_t> Receiver::decryptMatrixIndexQuery(Ciphertext<DCRTPoly> rowCipher, Ciphertext<DCRTPoly> colCipher) {

  int batchSize = cc->GetEncodingParams()->GetBatchSize();
  int rowFactor = (batchSize / VECTOR_DIM) * ceil(double(numVectors) / double(batchSize));
  
  vector<size_t> rowMatches;
  vector<size_t> colMatches;
  vector<size_t> matchIndices;

  Plaintext ptxt;
  cc->Decrypt(sk, rowCipher, &ptxt);
  vector<double> rowValues = ptxt->GetRealPackedValue();
  cc->Decrypt(sk, colCipher, &ptxt);
  vector<double> colValues = ptxt->GetRealPackedValue();

  // we need a separate index-tracking variable for row max values, since they are not in index-sorted order within rowCipher
  int rowIndex = 0;

  // loop over row / col maxes to find which rows / cols contain matches
  for(int i = 0; i < batchSize; i++) {
    
    if(colValues[rowIndex] >= 0.5) {
      colMatches.push_back(i);
    }

    if(rowValues[i] >= 0.5) {
      rowMatches.push_back(i);
    }

    rowIndex += VECTOR_DIM;
    if(rowIndex >= batchSize) {
      rowIndex = (rowIndex % batchSize) + 1;
    }
  }

  cout << "\tRow Factor: " << rowFactor << endl;
  cout << "\tRow Matches: " << rowMatches << endl;
  cout << "\tCol Matches: " << colMatches << endl;

  // use row / col numbers to determine candidate match indices
  for(size_t i = 0; i < rowMatches.size(); i++) {
    for(size_t j = 0; j < colMatches.size(); j++) {
      matchIndices.push_back(rowMatches[i] * rowFactor + colMatches[j]);
    }
  }

  return matchIndices;
}