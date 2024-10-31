#include "../include/sender_base.h"

// implementation of functions declared in base_sender.h

// -------------------- CONSTRUCTOR --------------------

BaseSender::BaseSender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               size_t vectorParam, ofstream& expStreamParam)
    : Sender(ccParam, pkParam, vectorParam, expStreamParam) {}

// -------------------- PUBLIC FUNCTIONS --------------------

vector<Ciphertext<DCRTPoly>> BaseSender::computeSimilarity(Ciphertext<DCRTPoly> queryCipher) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t vectorsPerBatch = batchSize / VECTOR_DIM;
  size_t numBatches = ceil(double(numVectors) / double(vectorsPerBatch));
  vector<Ciphertext<DCRTPoly>> similarityCipher(numBatches);

  // embarrassingly parallel
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for (size_t i = 0; i < numBatches; i++) {

    Ciphertext<DCRTPoly> databaseCipher;
    string filepath = "serial/database/batch" + to_string(i) + ".bin";
    if (!Serial::DeserializeFromFile(filepath, databaseCipher, SerType::BINARY)) {
        cerr << "Cannot read serialization from " << filepath << endl;
    }

    similarityCipher[i] = cc->EvalInnerProduct(queryCipher, databaseCipher, VECTOR_DIM);
    cc->RelinearizeInPlace(similarityCipher[i]);
    cc->RescaleInPlace(similarityCipher[i]);
  }
  
  return OpenFHEWrapper::mergeCiphers(cc, similarityCipher, VECTOR_DIM);
}


Ciphertext<DCRTPoly> BaseSender::membershipScenario(Ciphertext<DCRTPoly> queryCipher) {
  
  chrono::steady_clock::time_point start, end;
  chrono::duration<double> duration;

  // compute similarity scores between query and database
  cout << "[sender.cpp]\tComputing similarity... " << flush;
  start = chrono::steady_clock::now();
  vector<Ciphertext<DCRTPoly>> scoreCipher = computeSimilarity(queryCipher);
  end = chrono::steady_clock::now();
  duration = end - start;
  cout << "done (" << duration.count() << "s)" << endl;
  expStream << duration.count() << '\t' << flush;

  cout << "[sender.cpp]\tComparing with match threshold... " << flush;
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


vector<Ciphertext<DCRTPoly>> BaseSender::indexScenario(Ciphertext<DCRTPoly> queryCipher) {
  
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