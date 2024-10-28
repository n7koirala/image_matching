#include "../include/sender.h"

// implementation of functions declared in sender.h

// -------------------- CONSTRUCTOR --------------------

Sender::Sender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               size_t vectorParam, ofstream& expStreamParam)
    : cc(ccParam), pk(pkParam), numVectors(vectorParam), expStream(expStreamParam) {}

// -------------------- PUBLIC FUNCTIONS --------------------

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


vector<Ciphertext<DCRTPoly>> Sender::computeSimilarity(vector<Ciphertext<DCRTPoly>> queryCipher) {
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t ciphersNeeded = ceil(double(numVectors) / double(batchSize));
  vector<Ciphertext<DCRTPoly>> similarityCipher(ciphersNeeded);

  // note: parallelizing this loop seems to decrease performance, guessing due to nesting threads inside the helper func
  for(size_t i = 0; i < ciphersNeeded; i++) {
    similarityCipher[i] = computeSimilarityHelper(i, queryCipher);
  }

  return similarityCipher;
}


vector<Ciphertext<DCRTPoly>> Sender::indexScenarioNaive(vector<Ciphertext<DCRTPoly>> queryCipher) {
  
  chrono::steady_clock::time_point start, end;
  chrono::duration<double> duration;

  // compute similarity scores between query and database
  cout << "\tComputing similarity scores... " << flush;
  start = chrono::steady_clock::now();
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);
  end = chrono::steady_clock::now();
  cout << "done (" << duration.count() << "s)" << endl;

  cout << "\tComparing with match threshold... " << flush;
  start = chrono::steady_clock::now();
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    scoreCipher[i] = OpenFHEWrapper::chebyshevCompare(cc, scoreCipher[i], MATCH_THRESHOLD, CHEBYSHEV_DEGREE);
  }
  end = chrono::steady_clock::now();
  cout << "done (" << duration.count() << "s)" << endl;
  
  return scoreCipher;
}


Ciphertext<DCRTPoly> Sender::membershipScenarioNaive(vector<Ciphertext<DCRTPoly>> queryCipher) {
  
  chrono::steady_clock::time_point start, end;
  chrono::duration<double> duration;

  // compute similarity scores between query and database
  cout << "\tComputing similarity scores... " << flush;
  start = chrono::steady_clock::now();
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;
  expStream << duration.count() << '\t' << flush;

  cout << "\tComparing with match threshold... " << flush;
  start = chrono::steady_clock::now();
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    scoreCipher[i] = OpenFHEWrapper::chebyshevCompare(cc, scoreCipher[i], MATCH_THRESHOLD, CHEBYSHEV_DEGREE);
  }
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;
  expStream << duration.count() << '\t' << flush;
  
  // sum up all values into single result value at first slot of first cipher
  cout << "\tCombining boolean match values... " << flush;
  start = chrono::steady_clock::now();
  Ciphertext<DCRTPoly> membershipCipher = cc->EvalAddManyInPlace(scoreCipher);
  membershipCipher = cc->EvalSum(membershipCipher, cc->GetEncodingParams()->GetBatchSize());
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;
  expStream << duration.count() << '\t' << flush;

  return membershipCipher;
}


Ciphertext<DCRTPoly> Sender::membershipScenario(vector<Ciphertext<DCRTPoly>> queryCipher, size_t rowLength) {

  chrono::steady_clock::time_point start, end;
  chrono::duration<double> duration;

  // compute similarity scores between query and database
  cout << "\tComputing similarity scores... " << flush;
  start = chrono::steady_clock::now();
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;

  cout << "\tComputing alpha norm columns... " << flush;
  start = chrono::steady_clock::now();
  vector<Ciphertext<DCRTPoly>> colCipher = alphaNormColumns(scoreCipher, ALPHA, rowLength);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;

  cout << "\tComparing with match threshold... " << flush;
  start = chrono::steady_clock::now();
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < scoreCipher.size(); i++) {
    scoreCipher[i] = OpenFHEWrapper::chebyshevCompare(cc, scoreCipher[i], MATCH_THRESHOLD, CHEBYSHEV_DEGREE);
  }
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;
  
  // sum up all values into single result value at first slot of first cipher
  cout << "\tCombining boolean match values... " << flush;
  start = chrono::steady_clock::now();
  Ciphertext<DCRTPoly> membershipCipher = cc->EvalAddManyInPlace(scoreCipher);
  membershipCipher = cc->EvalSum(membershipCipher, cc->GetEncodingParams()->GetBatchSize());
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;

  // return ciphertext containing boolean (0/1) result value
  return membershipCipher;
}


tuple<vector<Ciphertext<DCRTPoly>>, vector<Ciphertext<DCRTPoly>>> 
Sender::indexScenario(vector<Ciphertext<DCRTPoly>> queryCipher, size_t rowLength) {

  chrono::steady_clock::time_point start, end;
  chrono::duration<double> duration;
  
  // compute similarity scores between query and database
  cout << "\tComputing similarity scores... " << flush;
  start = chrono::steady_clock::now();
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;

  // compute row and column maxes for group testing
  cout << "\tComputing alpha norm rows... " << flush;
  start = chrono::steady_clock::now();
  vector<Ciphertext<DCRTPoly>> rowCipher = alphaNormRows(scoreCipher, ALPHA, rowLength);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;

  cout << "\tComputing alpha norm columns... " << flush;
  start = chrono::steady_clock::now();
  vector<Ciphertext<DCRTPoly>> colCipher = alphaNormColumns(scoreCipher, ALPHA, rowLength);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;

  cout << "\tComparing with match threshold... " << flush;
  start = chrono::steady_clock::now();
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < rowCipher.size(); i++) {
    rowCipher[i] = OpenFHEWrapper::chebyshevCompare(cc, scoreCipher[i], MATCH_THRESHOLD, CHEBYSHEV_DEGREE);
  }

  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < colCipher.size(); i++) {
    colCipher[i] = OpenFHEWrapper::chebyshevCompare(cc, scoreCipher[i], MATCH_THRESHOLD, CHEBYSHEV_DEGREE);
  }
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;

  // return boolean (0/1) values dictating which rows and columns contain matches
  return make_tuple(rowCipher, colCipher);
}

// -------------------- PRIVATE FUNCTIONS --------------------

Ciphertext<DCRTPoly>
Sender::computeSimilarityHelper(size_t matrixIndex, vector<Ciphertext<DCRTPoly>> queryCipher) {

  vector<Ciphertext<DCRTPoly>> scoreCipher(VECTOR_DIM);

  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < VECTOR_DIM; i++) {
    scoreCipher[i] = computeSimilaritySerial(matrixIndex, i, queryCipher[i]);
  }

  for(size_t i = 1; i < VECTOR_DIM; i++) {
    cc->EvalAddInPlace(scoreCipher[0], scoreCipher[i]);
  }

  cc->RelinearizeInPlace(scoreCipher[0]);
  cc->RescaleInPlace(scoreCipher[0]);

  return scoreCipher[0];
}


// single-thread helper function for computing similarity scores using serialized database vectors
Ciphertext<DCRTPoly>
Sender::computeSimilaritySerial(size_t matrix, size_t index, Ciphertext<DCRTPoly> queryCipher) {

  string filepath = "serial/matrix" + to_string(matrix) + "/index" + to_string(index) + ".bin";
  Ciphertext<DCRTPoly> databaseCipher;
  if (Serial::DeserializeFromFile(filepath, databaseCipher, SerType::BINARY) == false) {
    cerr << "Error: cannot deserialize from \"" << filepath << "\"" << endl;
  }

  return cc->EvalMultNoRelin(queryCipher, databaseCipher);
}


Ciphertext<DCRTPoly> Sender::generateQueryHelper(Ciphertext<DCRTPoly> queryCipher, size_t index){
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();

  // generate mask to isolate only the values at the specified index
  vector<double> mask(batchSize, 0.0);
  for(size_t i = index; i < batchSize; i += VECTOR_DIM) {
    mask[i] = 1.0;
  }
  Plaintext maskPtxt = cc->MakeCKKSPackedPlaintext(mask);
  queryCipher = cc->EvalMult(queryCipher, maskPtxt);
  cc->RescaleInPlace(queryCipher);

  // add and rotate to fill all slots with that specified value
  return cc->EvalSum(queryCipher, VECTOR_DIM);
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