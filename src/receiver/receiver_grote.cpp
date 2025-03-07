#include "../../include/receiver_grote.h"

// implementation of functions declared in receiver_grote.h

// -------------------- CONSTRUCTOR --------------------

GroteReceiver::GroteReceiver(CryptoContext<DCRTPoly> ccParam,
                         PublicKey<DCRTPoly> pkParam, PrivateKey<DCRTPoly> skParam, size_t vectorParam)
    : BaseReceiver(ccParam, pkParam, skParam, vectorParam) {}

// -------------------- PUBLIC FUNCTIONS --------------------
vector<size_t> GroteReceiver::decryptIndex(vector<Ciphertext<DCRTPoly>> &indexCipher) {
  // row length is the power of 2 closest to sqrt(batchSize)
  // dividing scores into square matrix as close as possible
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t rowLength = pow(2.0, ceil(log2(batchSize) / 2.0));
  size_t colLength = batchSize / rowLength;

  // copy row and column scores from combined vector
  size_t numRowCiphers = ceil(double(ceil(double(numVectors) / double(batchSize))) / double(rowLength));
  size_t numColCiphers = ceil(double(ceil(double(numVectors) / double(batchSize))) / double(colLength));
  if (numRowCiphers + numColCiphers != indexCipher.size()) {
    cerr << "Error: incorrect parsing of index query results" << endl;
  }
  vector<Ciphertext<DCRTPoly>> rowCipher(indexCipher.begin(), indexCipher.begin() + numRowCiphers);
  vector<Ciphertext<DCRTPoly>> colCipher(indexCipher.begin() + numRowCiphers, indexCipher.end());


  // decrypt results
  vector<double> rowVals = OpenFHEWrapper::decryptVectorToVector(cc, sk, rowCipher);
  vector<double> colVals = OpenFHEWrapper::decryptVectorToVector(cc, sk, colCipher);

  vector<size_t> rowMatches;
  vector<size_t> colMatches;
  vector<size_t> matchIndices;

  for(size_t i = 0; i < rowVals.size(); i++) {
    if(rowVals[i] >= 1.0) {
      rowMatches.push_back(i);
    }
  }

  for(size_t i = 0; i < colVals.size(); i++) {
    if(colVals[i] >= 1.0) {
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

  return matchIndices;
}