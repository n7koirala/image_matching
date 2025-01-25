#include "../../include/receiver_hers.h"

// implementation of functions declared in receiver_hers.h

// -------------------- CONSTRUCTOR --------------------

HersReceiver::HersReceiver(CryptoContext<DCRTPoly> ccParam,
                         PublicKey<DCRTPoly> pkParam, PrivateKey<DCRTPoly> skParam, size_t vectorParam)
    : cc(ccParam), pk(pkParam), sk(skParam), numVectors(vectorParam) {}

// -------------------- PUBLIC FUNCTIONS --------------------

vector<Ciphertext<DCRTPoly>> HersReceiver::encryptQuery(vector<double> query) {
  
  vector<Ciphertext<DCRTPoly>> queryCipher(VECTOR_DIM);
  query = VectorUtils::plaintextNormalize(query, VECTOR_DIM);

  #pragma omp parallel for num_threads(MAX_NUM_CORES)
  for(size_t i = 0; i < VECTOR_DIM; i++) {
    queryCipher[i] = encryptQueryThread(query[i]);
  }

  return queryCipher;
}


// encrypts the query vector into a single cipher, requires sender to generate 512 needed ciphers
Ciphertext<DCRTPoly> HersReceiver::encryptQueryAlt(vector<double> query) {
  
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();

  query = VectorUtils::plaintextNormalize(query, VECTOR_DIM);
  vector<double> batchedQuery(batchSize);
  for(size_t i = 0; i < batchSize; i += VECTOR_DIM) {
    copy(query.begin(), query.end(), batchedQuery.begin() + i);
  }

  return OpenFHEWrapper::encryptFromVector(cc, pk, batchedQuery);
}

bool HersReceiver::decryptMembership(Ciphertext<DCRTPoly> &membershipCipher) {

  vector<double> membershipValues = OpenFHEWrapper::decryptToVector(cc, sk, membershipCipher);

  if(membershipValues[0] >= 1.0) {
    return true;
  }

  return false;
}


vector<size_t> HersReceiver::decryptIndex(vector<Ciphertext<DCRTPoly>> &indexCipher) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  vector<size_t> outputValues;
  vector<double> indexValues;

  for(size_t i = 0; i < indexCipher.size(); i++) {
    indexValues = OpenFHEWrapper::decryptToVector(cc, sk, indexCipher[i]);

    for(size_t j = 0; j < batchSize; j++) {
      if(indexValues[j] >= 1.0) {
        outputValues.push_back(j + (i * batchSize));
      }
    }
  }
  
  return outputValues;
}

// -------------------- PRIVATE FUNCTIONS --------------------

Ciphertext<DCRTPoly> HersReceiver::encryptQueryThread(double indexValue) {
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  vector<double> indexVector(batchSize, indexValue);
  Plaintext ptxt = cc->MakeCKKSPackedPlaintext(indexVector);
  return cc->Encrypt(pk, ptxt);
}