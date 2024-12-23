#include "../../include/receiver.h"

// implementation of functions declared in receiver.h

// -------------------- CONSTRUCTOR --------------------

Receiver::Receiver(CryptoContext<DCRTPoly> ccParam,
                         PublicKey<DCRTPoly> pkParam, PrivateKey<DCRTPoly> skParam, size_t vectorParam)
    : cc(ccParam), pk(pkParam), sk(skParam), numVectors(vectorParam) {}

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

bool Receiver::decryptMembership(Ciphertext<DCRTPoly> membershipCipher) {

  Plaintext membershipPtxt;
  cc->Decrypt(sk, membershipCipher, &membershipPtxt);
  vector<double> membershipValues = membershipPtxt->GetRealPackedValue();

  if(membershipValues[0] >= 1.0) {
    return true;
  }

  return false;
}


vector<size_t> Receiver::decryptIndex(vector<Ciphertext<DCRTPoly>> indexCipher) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  vector<size_t> outputValues;
  vector<double> indexValues;
  Plaintext indexPtxt;

  for(size_t i = 0; i < indexCipher.size(); i++) {
    cc->Decrypt(sk, indexCipher[i], &indexPtxt);
    indexValues = indexPtxt->GetRealPackedValue();

    for(size_t j = 0; j < batchSize; j++) {
      if(indexValues[j] >= 1.0) {
        outputValues.push_back(j + (i * batchSize));
      }
    }
  }
  
  return outputValues;
}

// -------------------- PRIVATE FUNCTIONS --------------------

Ciphertext<DCRTPoly> Receiver::encryptQueryThread(double indexValue) {
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  vector<double> indexVector(batchSize, indexValue);
  Plaintext ptxt = cc->MakeCKKSPackedPlaintext(indexVector);
  return cc->Encrypt(pk, ptxt);
}