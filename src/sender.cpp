#include "../include/sender.h"

// implementation of functions declared in sender.h
Sender::Sender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               size_t vectorParam)
    : cc(ccParam), pk(pkParam), numVectors(vectorParam) {}



void Sender::setDatabaseCipher(vector<vector<Ciphertext<DCRTPoly>>> databaseCipherParam) {
  databaseCipher = databaseCipherParam;
  return;
}


void Sender::serializeDatabaseCipher(string location) {
  cout << "[sender.cpp]\tSerializing encrypted database vector... " << flush;
  if (!Serial::SerializeToFile(location, databaseCipher[0], SerType::JSON)) {
      cout << "failed (cannot write to " << location << ")" << endl;
  } else {
    cout << "done" << endl;
  }
}



Ciphertext<DCRTPoly>
Sender::computeSimilarityHelper(size_t matrixIndex, vector<Ciphertext<DCRTPoly>> queryCipher) {

  vector<Ciphertext<DCRTPoly>> scoreCipher(VECTOR_DIM);
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < VECTOR_DIM; i++) {
    scoreCipher[i] = cc->EvalMultNoRelin(queryCipher[i], databaseCipher[matrixIndex][i]);
  }

  for(size_t i = 1; i < VECTOR_DIM; i++) {
    cc->EvalAddInPlace(scoreCipher[0], scoreCipher[i]);
  }

  cc->RelinearizeInPlace(scoreCipher[0]);
  cc->RescaleInPlace(scoreCipher[0]);

  return scoreCipher[0];
}

vector<Ciphertext<DCRTPoly>> Sender::computeSimilarity(vector<Ciphertext<DCRTPoly>> queryCipher) {
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t ciphersNeeded = ceil(double(numVectors) / double(batchSize));
  vector<Ciphertext<DCRTPoly>> similarityCipher(ciphersNeeded);

  // TODO: does parallelizing this outer loop increase performance? guessing not much
  for(size_t i = 0; i < ciphersNeeded; i++) {
    similarityCipher[i] = computeSimilarityHelper(i, queryCipher);
  }

  return similarityCipher;
}


vector<Ciphertext<DCRTPoly>> Sender::indexScenarioNaive(vector<Ciphertext<DCRTPoly>> queryCipher) {
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);

  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    // TODO: can we perform the subtraction in place?
    scoreCipher[i] = OpenFHEWrapper::sign(cc, cc->EvalSub(scoreCipher[i], MATCH_THRESHOLD), SIGN_COMPOSITIONS);
  }
  return scoreCipher;
}


Ciphertext<DCRTPoly> Sender::membershipScenarioNaive(vector<Ciphertext<DCRTPoly>> queryCipher) {
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);

  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    scoreCipher[i] = OpenFHEWrapper::sign(cc, cc->EvalSub(scoreCipher[i], MATCH_THRESHOLD), SIGN_COMPOSITIONS);
  }
  
  Ciphertext<DCRTPoly> membershipCipher = cc->EvalAddManyInPlace(scoreCipher);
  return OpenFHEWrapper::sumAllSlots(cc, membershipCipher);
}


vector<Ciphertext<DCRTPoly>> Sender::alphaNormRows(vector<Ciphertext<DCRTPoly>> scoreCipher, size_t alpha, size_t rowLength) {
  vector<Ciphertext<DCRTPoly>> alphaCipher(scoreCipher);

  for(size_t i = 0; i < alphaCipher.size(); i++) {
    for(size_t a = 0; a < alpha; a++) {
      cc->EvalSquareInPlace(alphaCipher[i]);
      cc->RescaleInPlace(alphaCipher[i]);
    }
    alphaCipher[i] = cc->EvalInnerProduct(alphaCipher[i], scoreCipher[i], rowLength);
    cc->RescaleInPlace(alphaCipher[i]);
  }

  return OpenFHEWrapper::mergeCiphers(cc, alphaCipher, rowLength);
}


// in current implementation, colLength is taken to be (batchSize / rowLength)
vector<Ciphertext<DCRTPoly>> Sender::alphaNormColumns(vector<Ciphertext<DCRTPoly>> scoreCipher, size_t alpha, size_t rowLength) {
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t ciphersNeeded = ceil(double(scoreCipher.size() * rowLength) / double(batchSize));
  vector<Ciphertext<DCRTPoly>> colCipher(ciphersNeeded);
  vector<Ciphertext<DCRTPoly>> alphaCipher(scoreCipher);

  vector<double> rowMask(rowLength, 1.0);
  Plaintext rowMaskPtxt = cc->MakeCKKSPackedPlaintext(rowMask);

  size_t outputCipher;
  size_t outputSlot;

  for(size_t i = 0; i < alphaCipher.size(); i++) {

    // perform exponential step of alpha norm operation
    for(size_t a = 0; a < alpha; a++) {
      cc->EvalSquareInPlace(alphaCipher[i]);
      cc->RescaleInPlace(alphaCipher[i]);
    }
    alphaCipher[i] = cc->EvalMult(alphaCipher[i], scoreCipher[i]);
    cc->RescaleInPlace(alphaCipher[i]);

    // perform addition step of alpha norm operation, use mask to keep one set of alpha norm values
    for(size_t j = rowLength; j < batchSize; j *= 2) {
      cc->EvalAddInPlace(alphaCipher[i], OpenFHEWrapper::binaryRotate(cc, alphaCipher[i], -j));
    }
    alphaCipher[i] = cc->EvalMult(alphaCipher[i], rowMaskPtxt);
    cc->RescaleInPlace(alphaCipher[i]);

    // place alpha norm values into output ciphertexts in consecutive batched format
    outputCipher = (i * rowLength) / batchSize;
    outputSlot = (i * rowLength) % batchSize;
    if(outputSlot == 0) {
      colCipher[outputCipher] = alphaCipher[i];
    } else {
      alphaCipher[i] = OpenFHEWrapper::binaryRotate(cc, alphaCipher[i], -outputSlot);
      cc->EvalAddInPlace(colCipher[outputCipher], alphaCipher[i]);
    }
  }
  
  return colCipher;
}

Ciphertext<DCRTPoly> Sender::membershipScenario(vector<Ciphertext<DCRTPoly>> queryCipher, size_t rowLength) {

  // compute similarity scores between query and database
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);

  // compute column maxes for group testing
  // TODO: experiment whether computing rownorms or colnorms is faster
  scoreCipher = alphaNormColumns(scoreCipher, ALPHA, rowLength);

  // compare maxes against similarity match threshold
  double updatedThreshold = pow(MATCH_THRESHOLD, pow(2, ALPHA)+1);
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    cc->EvalSubInPlace(scoreCipher[i], updatedThreshold);

    // TODO: un-hardcode depth value
    scoreCipher[i] = OpenFHEWrapper::sign(cc, scoreCipher[i], 13);
  }
  
  // sum up all values into single result value at first slot of first cipher
  Ciphertext<DCRTPoly> membershipCipher = cc->EvalAddManyInPlace(scoreCipher);
  membershipCipher = cc->EvalSum(membershipCipher, cc->GetEncodingParams()->GetBatchSize());

  // return ciphertext containing boolean (0/1) result value
  return membershipCipher;
}


tuple<vector<Ciphertext<DCRTPoly>>, vector<Ciphertext<DCRTPoly>>> 
Sender::indexScenario(vector<Ciphertext<DCRTPoly>> queryCipher, size_t rowLength) {
  
  // compute similarity scores between query and database
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);

  // compute row and column maxes for group testing
  vector<Ciphertext<DCRTPoly>> rowCipher = alphaNormRows(scoreCipher, ALPHA, rowLength);
  vector<Ciphertext<DCRTPoly>> colCipher = alphaNormColumns(scoreCipher, ALPHA, rowLength);

  // compare row and column maxes against similarity match threshold 
  double updatedThreshold = pow(MATCH_THRESHOLD, pow(2, ALPHA)+1);
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < rowCipher.size(); i++) {
    cc->EvalSubInPlace(rowCipher[i], updatedThreshold);

    // TODO: un-hardcode depth value
    rowCipher[i] = OpenFHEWrapper::sign(cc, rowCipher[i], 13);
  }

  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < colCipher.size(); i++) {
    cc->EvalSubInPlace(colCipher[i], updatedThreshold);

    // TODO: un-hardcode depth value
    colCipher[i] = OpenFHEWrapper::sign(cc, colCipher[i], 13);
  }

  // return boolean (0/1) values dictating which rows and columns contain matches
  return make_tuple(rowCipher, colCipher);
}