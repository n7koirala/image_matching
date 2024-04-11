#include <iostream>
#include "../include/cosine_similarity.h"
#include "../include/config.h"
#include "openfhe.h"

using namespace lbcrypto;
using namespace std;

// ** Entry point of the application that orchestrates the flow. **

int main() {

    // For static methods
    CosineSimilarity cs;
    
    CCParams<CryptoContextCKKSRNS> parameters;
    uint32_t multDepth = 12; 

    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(45);

    // Preset security level specifies ring dimension n = 32768
    // Batch size cannot be set above n/2 = 16384
    // Work with this for now, discuss at meeting
    // parameters.SetBatchSize(32768);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keyPair = cc->KeyGen();
    auto pk = keyPair.publicKey;
    auto sk = keyPair.secretKey;
    cc->EvalMultKeyGen(sk);
    cc->EvalSumKeyGen(sk);

    unsigned int batchSize = cc->GetEncodingParams()->GetBatchSize();

    // Output Scheme Information
    /*
    cout << "batchSize: " << batchSize << endl;
    cout << endl;

    cout << "CKKS default parameters: " << parameters << endl;
    cout << endl;

    cout << "scaling mod size: " << parameters.GetScalingModSize() << endl;
    cout << "ring dimension: " << cc->GetRingDimension() << endl;
    cout << "noise estimate: " << parameters.GetNoiseEstimate() << endl;
    cout << "multiplicative depth: " << parameters.GetMultiplicativeDepth() << endl;
    cout << "Noise level: " << parameters.GetNoiseEstimate() << endl;
     */

    // Open input file
    ifstream fileStream;
    fileStream.open(BACKEND_VECTORS_FILE, ios::in);
    if(!fileStream.is_open()) {
        cout << "Error opening file" << endl;
        return 1;
    }

    // Read in vectors from file
    int inputDim, numVectors;
    fileStream >> inputDim >> numVectors;
    vector<vector<double>> plaintextVectors(numVectors , vector<double>(inputDim));
    for(int i = 0; i < numVectors; i++) {
        for(int j = 0; j < inputDim; j++) {
            fileStream >> plaintextVectors[i][j];
        }
    }
    fileStream.close();

    // Compute number of vectors we can fit into a single ciphertext batch, and how many batches needed
    int vectorsPerBatch = (int)(batchSize / inputDim);          // round down
    int totalBatches = (int)(numVectors / vectorsPerBatch + 1); // round up

    // Normalize in plaintext domain
    vector<vector<double>> normalizedVectors(numVectors , vector<double>(inputDim));
    for(int i = 0; i < numVectors; i++) {
        normalizedVectors[i] = cs.plaintextNormalize(inputDim, plaintextVectors[i]);
    }

    // The first vector from the file is used as the query vector
    // Concatenate with itself so that queryVector is the length of a fully batched plaintext
    vector<double> queryVector(0);
    cs.concatenateVectors(queryVector, normalizedVectors[0], vectorsPerBatch);

    // Remaining vectors from file are used as database vectors to be queried against
    // Concatenate them in several different batches, each the length of a fully batched plaintext
    vector<vector<double>> databaseVectors( totalBatches, vector<double> (0));
    for(int i = 0; i < numVectors; i++) {
        int batchNum = (int)(i / vectorsPerBatch);
        cs.concatenateVectors(databaseVectors[batchNum], normalizedVectors[i], 1);
    }

    // Encode batched query and batched DB vectors as plaintexts
    Plaintext queryPtxt = cc->MakeCKKSPackedPlaintext(queryVector);

    vector<Plaintext> databasePtxts(totalBatches);
    for(int i = 0; i < totalBatches; i++) {
        databasePtxts[i] = cc->MakeCKKSPackedPlaintext(databaseVectors[i]);
    }

    // Encrypt the batched query vector
    auto queryCipher = cc->Encrypt(pk, queryPtxt);

    // Iterate over encrypted batched DB vectors and calculate CS for each one
    vector<Plaintext> resultPtxts(totalBatches);
    for(int i = 0; i < totalBatches; i++) {
        auto databaseCipher = cc->Encrypt(pk, databasePtxts[i]);

        // Cosine similarity is equivalent to inner product of normalized vectors
        // In future, explore if key-switching is not necessary / slower
        auto cosineCipher = cc->EvalInnerProduct(queryCipher, databaseCipher, inputDim);

        cc->Decrypt(sk, cosineCipher, &(resultPtxts[i]));
    }

    // Formatted Output
    for(int i = 1; i < numVectors; i++) {
        int batchNum = (int)(i / vectorsPerBatch);
        int batchIndex = (i % vectorsPerBatch) * inputDim;
        auto resultValues = resultPtxts[batchNum]->GetRealPackedValue();
        cout << "Cosine similarity of vector[" << 0 << "] with vector[" << i << "]" << endl;
        cout << "Batch Num: " << batchNum << "\tBatch Index: " << batchIndex << endl;
        cout << "Homomorphic:\t" << resultValues[batchIndex] << endl;
        cout << "Expected:\t" << cs.plaintextCosineSim(inputDim, plaintextVectors[0], plaintextVectors[i]) << endl;
        cout << endl;
    }
    
    return 0;
}