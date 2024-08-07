#include "../include/receiver.h"

// implementation of functions declared in receiver_plain.h

// -------------------- CONSTRUCTOR --------------------

Receiver::Receiver(CryptoContext<DCRTPoly> ccParam,
                         PublicKey<DCRTPoly> pkParam, PrivateKey<DCRTPoly> skParam, size_t vectorParam, ofstream& expStreamParam)
    : cc(ccParam), pk(pkParam), sk(skParam), numVectors(vectorParam), expStream(expStreamParam) {}

// -------------------- PUBLIC FUNCTIONS --------------------

vector<Ciphertext<DCRTPoly>> Receiver::encryptQuery(vector<double> query) {
  
  vector<Ciphertext<DCRTPoly>> queryCipher(VECTOR_DIM);
  query = VectorUtils::plaintextNormalize(query, VECTOR_DIM);

  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < VECTOR_DIM; i++) {
    queryCipher[i] = encryptQueryThread(query[i]);
  }

  return queryCipher;
}


// encrypts the query vector into a single cipher, requires sender to generate 512 needed ciphers
Ciphertext<DCRTPoly> Receiver::encryptQueryAlt(vector<double> query) {
  
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();

  query = VectorUtils::plaintextNormalize(query, VECTOR_DIM);
  vector<double> batchedQuery(batchSize);
  for(size_t i = 0; i < batchSize; i += VECTOR_DIM) {
    copy(query.begin(), query.end(), batchedQuery.begin() + i);
  }

  return OpenFHEWrapper::encryptFromVector(cc, pk, batchedQuery);
}


// Decrypts a vector of ciphertexts and packs their values into a single output vector
vector<double> Receiver::decryptRawScores(vector<Ciphertext<DCRTPoly>> scoreCipher) {
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  vector<double> scoreVector(numVectors);
  vector<double> currentVector(batchSize);
  Plaintext ptxt;

  size_t startIndex;
  size_t copyLength;
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    cc->Decrypt(sk, scoreCipher[i], &ptxt);
    currentVector = ptxt->GetRealPackedValue();
    startIndex = i * batchSize;
    copyLength = min(numVectors - startIndex, batchSize);
    copy(currentVector.begin(), currentVector.begin()+copyLength, scoreVector.begin()+startIndex);
  }
  return scoreVector;
}


bool Receiver::decryptMembership(Ciphertext<DCRTPoly> membershipCipher) {

  steady_clock::time_point start, end;
  cout << "\tDecrypting membership query... " << flush;
  start = steady_clock::now();

  Plaintext membershipPtxt;
  cc->Decrypt(sk, membershipCipher, &membershipPtxt);
  vector<double> membershipValues = membershipPtxt->GetRealPackedValue();
  bool matchExists = false;

  // TODO: remove / justify hardcoded value
  if(membershipValues[0] >= 0.5) {
    matchExists = true;
  }

  end = steady_clock::now();
  cout << "done (" << duration_cast<measure_typ>(end - start).count() / 1000.0 << "s)" << endl;
  expStream << duration_cast<measure_typ>(end - start).count() / 1000.0 << '\t' << flush;

  return matchExists;
}


vector<size_t> Receiver::decryptIndexNaive(vector<Ciphertext<DCRTPoly>> indexCipher) {

  steady_clock::time_point start, end;
  cout << "\tDecrypting naive index query... " << flush;
  start = steady_clock::now();

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  vector<size_t> outputValues;
  vector<double> indexValues;
  Plaintext indexPtxt;

  for(size_t i = 0; i < indexCipher.size(); i++) {
    cc->Decrypt(sk, indexCipher[i], &indexPtxt);
    indexValues = indexPtxt->GetRealPackedValue();

    for(size_t j = 0; j < batchSize; j++) {
      // TODO: remove / justify hardcoded value
      if(indexValues[j] >= 0.5) {
        outputValues.push_back(j + (i * batchSize));
      }
    }
  }

  end = steady_clock::now();
  cout << "done (" << duration_cast<measure_typ>(end - start).count() / 1000.0 << "s)" << endl;
  
  return outputValues;
}


vector<size_t> Receiver::decryptIndex(vector<Ciphertext<DCRTPoly>> rowCipher, vector<Ciphertext<DCRTPoly>> colCipher, size_t rowLength) {
  
  steady_clock::time_point start, end;
  cout << "\tDecrypting index query... " << flush;
  start = steady_clock::now();
  
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t colLength = batchSize / rowLength;

  // decrypt results
  vector<double> rowVals = OpenFHEWrapper::decryptVectorToVector(cc, sk, rowCipher);
  vector<double> colVals = OpenFHEWrapper::decryptVectorToVector(cc, sk, colCipher);

  vector<size_t> rowMatches;
  vector<size_t> colMatches;
  vector<size_t> matchIndices;

  for(size_t i = 0; i < rowVals.size(); i++) {
    if(rowVals[i] >= 0.5) {
      rowMatches.push_back(i);
    }
  }

  for(size_t i = 0; i < colVals.size(); i++) {
    if(colVals[i] >= 0.5) {
      colMatches.push_back(i);
    }
  }

  size_t rowMatrixNum;
  size_t colMatrixNum;
  for(size_t i = 0; i < rowMatches.size(); i++) {
    rowMatrixNum = rowMatches[i] / colLength;

    for(size_t j = 0; j < colMatches.size(); j++) {
      colMatrixNum = colMatches[j] / rowLength;
      
      if(rowMatrixNum == colMatrixNum) {
        matchIndices.push_back((rowMatches[i] * rowLength) + (colMatches[j] % rowLength));
      }

    }
  }

  end = steady_clock::now();
  cout << "done (" << duration_cast<measure_typ>(end - start).count() / 1000.0 << "s)" << endl;

  return matchIndices;
}

// -------------------- PRIVATE FUNCTIONS --------------------

Ciphertext<DCRTPoly> Receiver::encryptQueryThread(double indexValue) {
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  vector<double> indexVector(batchSize, indexValue);
  Plaintext ptxt = cc->MakeCKKSPackedPlaintext(indexVector);
  return cc->Encrypt(pk, ptxt);
}