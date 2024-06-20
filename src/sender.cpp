#include "../include/sender.h"

// implementation of functions declared in sender.h
Sender::Sender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               int vectorParam)
    : cc(ccParam), pk(pkParam), numVectors(vectorParam) {}



vector<Ciphertext<DCRTPoly>>
Sender::computeSimilarity(Ciphertext<DCRTPoly> query,
                          vector<Ciphertext<DCRTPoly>> database) {
  cout << "[sender.cpp]\tComputing similarity scores... " << flush;
  vector<Ciphertext<DCRTPoly>> similarityCipher(database.size());

  // embarrassingly parallel
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for (unsigned int i = 0; i < database.size(); i++) {
    similarityCipher[i] = cc->EvalInnerProduct(query, database[i], VECTOR_DIM);
  }

  cout << "done" << endl;
  return similarityCipher;
}



Ciphertext<DCRTPoly> Sender::mergeSingleCipher(Ciphertext<DCRTPoly> scoreCipher, int reductionFactor) {
  cout << "[sender.cpp]\tMerging similarity scores... " << flush;

  int batchSize = cc->GetEncodingParams()->GetBatchSize();
  int scoresPerBatch = batchSize / reductionFactor;

  // mergedCipher is the vector of ciphertexts to be returned
  Ciphertext<DCRTPoly> tempCipher;
  Ciphertext<DCRTPoly> currentBatchCipher;

  vector<double> reductionMask(batchSize);
  for(int i = 0; i < reductionFactor; i++) { reductionMask[i] = 1.0; }
  Plaintext reductionMaskPtxt = cc->MakeCKKSPackedPlaintext(reductionMask);

  int rotationFactor = reductionFactor - 1;
  int numRotations = int(log2(scoresPerBatch));
  int maskCount = 0;
  currentBatchCipher = scoreCipher;
  for(int i = 0; i < numRotations; i++) {

    // if we have run out of padded zeros in the current batch cipher, update and apply multiplicative mask
    if(pow(2,i) == pow(reductionFactor, maskCount)) {
      fill(reductionMask.begin(), reductionMask.end(), 0.0);
      for(int j = 0; j < batchSize; j += pow(reductionFactor, maskCount+1)) {
        for(int k = 0; k < pow(reductionFactor, maskCount); k++) { 
          reductionMask[j + k] = 1.0;
        }
      }
      reductionMaskPtxt = cc->MakeCKKSPackedPlaintext(reductionMask);
      currentBatchCipher = cc->EvalMult(currentBatchCipher, reductionMaskPtxt);
      cout << "mult" << endl;
      maskCount++;
    }

    tempCipher = OpenFHEWrapper::binaryRotate(cc, currentBatchCipher, rotationFactor * pow(2,i));
    currentBatchCipher = cc->EvalAdd(currentBatchCipher, tempCipher);
  }

  vector<double> batchMask(batchSize);
  for(int i = 0; i < scoresPerBatch; i++) { batchMask[i] = 1.0; }
  Plaintext batchMaskPtxt = cc->MakeCKKSPackedPlaintext(batchMask);
  currentBatchCipher = cc->EvalMult(currentBatchCipher, batchMaskPtxt);
  cout << "mult" << endl;

  cout << "done" << endl;
  return currentBatchCipher;
}


vector<Ciphertext<DCRTPoly>>
Sender::mergeScores(vector<Ciphertext<DCRTPoly>> similarityCipher, int reductionDim) {
  return similarityCipher;
}



vector<Ciphertext<DCRTPoly>> Sender::approximateMax(vector<Ciphertext<DCRTPoly>> similarityCipher, int alpha, int partitionLen) {
  cout << "[sender.cpp]\tApproximating maximum scores... " << flush;
  vector<Ciphertext<DCRTPoly>> maxCipher = similarityCipher;

  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < similarityCipher.size(); i++) {
    maxCipher[i] = OpenFHEWrapper::alphaNorm(cc, maxCipher[i], alpha, partitionLen);
  }

  cout << "done" << endl;
  return mergeScores(maxCipher, partitionLen);
}



Ciphertext<DCRTPoly>
Sender::membershipQuery(vector<Ciphertext<DCRTPoly>> similarityCipher) {

  // Sender performs alpha-norm / merge operation to reduce number of scores by factor of 512
  // TODO: experiment with other partition lengths, VECTOR_DIM works with merge operation
  vector<Ciphertext<DCRTPoly>> maxCipher =
      approximateMax(similarityCipher, ALPHA, VECTOR_DIM);

  double adjustedThreshold = pow(DELTA, ALPHA);

  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < maxCipher.size(); i++) {
    maxCipher[i] = cc->EvalAdd(maxCipher[i], -adjustedThreshold);
    // maxCipher[i] = OpenFHEWrapper::sign(cc, maxCipher[i]);
    // maxCipher[i] = OpenFHEWrapper::normalizeVector(cc, maxCipher[i], 1, 0.1, -0.1/512.0);
    maxCipher[i] = OpenFHEWrapper::sumAllSlots(cc, maxCipher[i]);
  }

  // combine sums from all ciphertexts into first ciphertext, only return the first
  for(size_t i = 1; i < maxCipher.size(); i++) {
    maxCipher[0] = cc->EvalAdd(maxCipher[0], maxCipher[i]);
  }

  return maxCipher[0];
}



// TODO: rewrite this into shuffle operation
tuple<vector<Ciphertext<DCRTPoly>>, vector<Ciphertext<DCRTPoly>>>
Sender::formatScoreMatrices(vector<Ciphertext<DCRTPoly>> similarityScores) {
  int batchSize = cc->GetEncodingParams()->GetBatchSize();

  // ideal matrix dimension n is the smallest power of 2 such that n^2 >= numVectors
  // log change of base: log_4(numVectors) = log_e(numVectors) / log_e(4)
  int optimalMatrixDim = int(pow(2, ceil(log(numVectors) / log(4))));

  // however for dimension > 512, merge operation requires more mults and alpha norm becomes inaccurate
  // if not all scores fit into single matrix, we format the scores as a list of matrices
  int matrixDim = min(VECTOR_DIM, optimalMatrixDim);
  int matrixCapacity = matrixDim * matrixDim;
  int matricesNeeded = ceil(double(numVectors) / double(matrixCapacity));
  int ciphersNeeded = ceil(double(matricesNeeded * matrixCapacity) / double(batchSize));

  cout << "Number of scores: " << numVectors << endl;
  cout << "Matrix dimension: " << matrixDim << endl;
  cout << "Matrix capacity: " << matrixCapacity << endl;
  cout << "Matrices needed: " << matricesNeeded << endl;
  cout << "Ciphertexts needed: " << ciphersNeeded << endl << endl;

  // encrypt multiplicative masks
  vector<double> scoreMask(batchSize);
  vector<double> rowMask(batchSize);
  for(int i = 0; i < batchSize / VECTOR_DIM; i++) {
    scoreMask[i * VECTOR_DIM] = 1.0;
    rowMask[i] = 1.0;
  }
  Plaintext maskPtxt = cc->MakeCKKSPackedPlaintext(scoreMask);
  Ciphertext<DCRTPoly> scoreMaskCipher = cc->Encrypt(pk, maskPtxt);
  maskPtxt = cc->MakeCKKSPackedPlaintext(rowMask);
  Ciphertext<DCRTPoly> rowMaskCipher = cc->Encrypt(pk, maskPtxt);

  // use mask to remove all garbage values from similarity cipher, leaving only scores
  cout << "[sender.cpp]\tIsolating similarity scores... " << flush;
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < similarityScores.size(); i++) {
    similarityScores[i] = cc->EvalMult(similarityScores[i], scoreMaskCipher);
  }
  cout << "done" << endl;

  // generate list of indices of scores to be reformatted into matrices
  vector<int> indices;
  for(int i = 0; i < numVectors; i++) {
    indices.push_back(i);
  }

  // generate matrices of score indices
  vector<vector<vector<int>>> rowIndices;
  vector<vector<vector<int>>> colIndices;

  // create encrypted row matrix using index matrix as guide
  vector<Ciphertext<DCRTPoly>> rowCipher(ciphersNeeded);
  Ciphertext<DCRTPoly> currentRowCipher;
  Ciphertext<DCRTPoly> neededScoreCipher;
  Plaintext blankPtxt = cc->MakeCKKSPackedPlaintext(vector<double>(batchSize));
  int scoreLocation = 0;
  int rowLocation = 0;
  int rotationFactor = 0;

  cout << "[sender.cpp]\tForming row ciphertexts... " << flush;
  for(int matrix = 0; matrix < matricesNeeded; matrix++) {

    for(int row = 0; row < matrixDim; row++) {
      // initialize a blank ciphertext for the current row
      currentRowCipher = cc->Encrypt(pk, blankPtxt);

      for(int index = 0; index < matrixDim; index++) {
        // get location of needed score within similarityCipher
        scoreLocation = rowIndices[matrix][row][index];
        cout << scoreLocation << endl;
        if(scoreLocation == -1) { 
          continue;
        }
        scoreLocation *= VECTOR_DIM;

        // get location within rowCipher to put the needed score
        rowLocation = (matrix * matrixCapacity) + (row * matrixDim) + index;

        // determine rotation needed to bring needed score to correct index in current row
        rotationFactor = (scoreLocation % batchSize) - index;

        neededScoreCipher = OpenFHEWrapper::binaryRotate(cc, similarityScores[scoreLocation / batchSize], rotationFactor);
        currentRowCipher = cc->EvalAdd(currentRowCipher, neededScoreCipher);
      }

      currentRowCipher = cc->EvalMult(currentRowCipher, rowMaskCipher);
      rotationFactor = -(matrix * matrixCapacity) - (row * matrixDim);
      currentRowCipher = OpenFHEWrapper::binaryRotate(cc, currentRowCipher, rotationFactor);

      if((matrix * matrixCapacity + row * matrixDim) % batchSize == 0) {
        rowCipher[rowLocation / batchSize] = currentRowCipher;
      } else {
        rowCipher[rowLocation / batchSize] = cc->EvalAdd(rowCipher[rowLocation / batchSize], currentRowCipher);
      }
    }
  }
  cout << "done" << endl;

  // create encrypted column matrix using index matrix as guide
  vector<Ciphertext<DCRTPoly>> colCipher(ciphersNeeded);
  Ciphertext<DCRTPoly> currentColCipher;
  int colLocation = 0;
  cout << "[sender.cpp]\tForming column ciphertexts... " << flush;
  for(int matrix = 0; matrix < matricesNeeded; matrix++) {

    for(int col = 0; col < matrixDim; col++) {
      // initialize a blank ciphertext for the current column
      currentColCipher = cc->Encrypt(pk, blankPtxt);

      for(int index = 0; index < matrixDim; index++) {
        // get location of needed score within similarityCipher
        scoreLocation = colIndices[matrix][col][index];
        if(scoreLocation == -1) { 
          continue;
        }
        scoreLocation *= VECTOR_DIM;

        // get location within colCipher to put the needed score
        colLocation = (matrix * matrixCapacity) + (col * matrixDim) + index;

        // determine rotation needed to bring needed score to correct index in current col
        rotationFactor = (scoreLocation % batchSize) - index;

        neededScoreCipher = OpenFHEWrapper::binaryRotate(cc, similarityScores[scoreLocation / batchSize], rotationFactor);
        currentColCipher = cc->EvalAdd(currentColCipher, neededScoreCipher);
      }

      currentColCipher = cc->EvalMult(currentColCipher, rowMaskCipher);
      rotationFactor = -(matrix * matrixCapacity) - (col * matrixDim);
      currentColCipher = OpenFHEWrapper::binaryRotate(cc, currentColCipher, rotationFactor);

      if((matrix * matrixCapacity + col * matrixDim) % batchSize == 0) {
        colCipher[colLocation / batchSize] = currentColCipher;
      } else {
        colCipher[colLocation / batchSize] = cc->EvalAdd(colCipher[colLocation / batchSize], currentColCipher);
      }
    }
  }
  cout << "done" << endl;

  return tuple<vector<Ciphertext<DCRTPoly>>, vector<Ciphertext<DCRTPoly>>>{rowCipher, colCipher};
}



Ciphertext<DCRTPoly> Sender::alphaNormRows(vector<Ciphertext<DCRTPoly>> mergedCipher, int alpha, int rowLength) {
  cout << "[sender.cpp]\tApproximating maximum row scores... " << flush;


  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < mergedCipher.size(); i++) {
    mergedCipher[i] = OpenFHEWrapper::alphaNorm(cc, mergedCipher[i], alpha, rowLength);
  }

  vector<Ciphertext<DCRTPoly>> resultCipher = mergeScores(mergedCipher, rowLength);
  if(resultCipher.size() > 1) {
    cerr << "Error: alpha-norm shouldn't be computed on rows of length greater than the batch size" << endl;
  }

  cout << "done" << endl;
  return resultCipher[0];
}



Ciphertext<DCRTPoly> Sender::alphaNormColumns(vector<Ciphertext<DCRTPoly>> mergedCipher, int alpha, int colLength) {
  cout << "[sender.cpp]\tApproximating maximum column scores... " << flush;
  int batchSize = cc->GetEncodingParams()->GetBatchSize();
  int scoresPerBatch = batchSize / colLength;
  
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < mergedCipher.size(); i++) {
    for(int a = 0; a < alpha; a++) {
      mergedCipher[i] = cc->EvalMult(mergedCipher[i], mergedCipher[i]);
    }
  }

  for(size_t i = 1; i < mergedCipher.size(); i++) {
    mergedCipher[0] = cc->EvalAdd(mergedCipher[0], mergedCipher[i]);
  }

  for(int i = 1; i < scoresPerBatch; i*=2) {
    mergedCipher[0] = cc->EvalAdd(mergedCipher[0], OpenFHEWrapper::binaryRotate(cc, mergedCipher[0], colLength*i));
  }

  vector<double> batchMask(batchSize);
  for(int i = 0; i < colLength; i++) {
    batchMask[i] = 1.0;
  }
  Plaintext batchMaskPtxt = cc->MakeCKKSPackedPlaintext(batchMask);
  mergedCipher[0] = cc->EvalMult(mergedCipher[0], batchMaskPtxt);

  cout << "done" << endl;
  return mergedCipher[0];
}



vector<Ciphertext<DCRTPoly>> Sender::indexScenario(vector<Ciphertext<DCRTPoly>> similarityCipher) {

  vector<Ciphertext<DCRTPoly>> mergedCipher = mergeScores(similarityCipher, VECTOR_DIM);

  // ideal matrix dimension n is the smallest power of 2 such that n^2 >= numVectors
  // log change of base: log_4(numVectors) = log_e(numVectors) / log_e(4)
  int optimalMatrixDim = int(pow(2, ceil(log(numVectors) / log(4))));

  // however for dimension > 512, merge operation requires more mults and alpha norm becomes inaccurate
  // if not all scores fit into single matrix, we format the scores as a list of matrices
  int matrixDim = min(VECTOR_DIM, optimalMatrixDim);

  Ciphertext<DCRTPoly> rowMaxCipher = alphaNormRows(mergedCipher, ALPHA, matrixDim);
  Ciphertext<DCRTPoly> colMaxCipher = alphaNormColumns(mergedCipher, ALPHA, matrixDim);

  rowMaxCipher = OpenFHEWrapper::sign(cc, rowMaxCipher);
  colMaxCipher = OpenFHEWrapper::sign(cc, colMaxCipher);

  // placeholder return for unfinished function
  return mergedCipher;
}