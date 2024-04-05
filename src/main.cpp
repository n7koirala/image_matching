#include <iostream>
#include "../include/cosine_similarity.h"
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

    /* Output Scheme Information
    cout << "batchSize: " << batchSize << endl;
    cout << endl;

    cout << "CKKS default parameters: " << parameters << endl;
    cout << endl;

    cout << "scaling mod size: " << parameters.GetScalingModSize() << endl;
    cout << "ring dimension: " << cc->GetRingDimension() << endl;
    cout << "noise estimate: " << parameters.GetNoiseEstimate() << endl;
    cout << "multiplicative depth: " << parameters.GetMultiplicativeDepth() << endl;
    cout << "Noise level: " << parameters.GetNoiseEstimate() << endl; */

    // Open input file
    ifstream fileStream;
    fileStream.open("input_random", ios::in);
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

    int vectorsPerBatch = (int)(batchSize / inputDim);          // round down
    int totalBatches = (int)(numVectors / vectorsPerBatch + 1); // round up
    int batchNum;

    // Normalize in plaintext domain
    vector<vector<double>> normalizedVectors(numVectors , vector<double>(inputDim));
    for(int i = 0; i < numVectors; i++) {
        normalizedVectors[i] = cs.plaintextNormalize(inputDim, plaintextVectors[i]);
    }

    // Concatenate for batching purposes
    // Query vector is concatenated with self vectorsPerBatch times
    // All numVectors=10000 database vectors are concatenated, yet split across several vectors to not exceed batch size
    vector<double> queryVector(0);
    vector<vector<double>> databaseVectors( totalBatches, vector<double> (0));
    for(int i = 1; i < numVectors; i++) {
        batchNum = (int)(i / vectorsPerBatch);
        if(batchNum == 0) {
            queryVector.insert(queryVector.end(), normalizedVectors[0].begin(), normalizedVectors[0].end());
        }
        databaseVectors[batchNum].insert(databaseVectors[batchNum].end(), normalizedVectors[i].begin(), normalizedVectors[i].end());
    }

    // Encode as plaintexts
    Plaintext queryPtxt = cc->MakeCKKSPackedPlaintext(queryVector);
    vector<Plaintext> databasePtxts(totalBatches);
    for(int i = 0; i < totalBatches; i++) {
        databasePtxts[i] = cc->MakeCKKSPackedPlaintext(databaseVectors[i]);
    }

    vector<Plaintext> resultPtxts(totalBatches);

    // Encrypt the encoded vectors
    auto queryCipher = cc->Encrypt(pk, queryPtxt);
    for(int i = 0; i < totalBatches; i++) {
        auto databaseCipher = cc->Encrypt(pk, databasePtxts[i]);

        // Cosine similarity is equivalent to inner product of normalized vectors
        auto cosineCipher = cc->EvalInnerProduct(queryCipher, databaseCipher, inputDim);

        // Decryption
        cc->Decrypt(sk, cosineCipher, &(resultPtxts[i]));

        // Computed Output
        cout << "Expected: cos(query, database[" << i*vectorsPerBatch << "]) =     ";
        cout << cs.plaintextCosineSim(inputDim, plaintextVectors[0], plaintextVectors[i*vectorsPerBatch]) << endl;

        cout.precision(4);
        resultPtxts[i]->SetLength(1);
        cout << "Homomorphic: cos(query, database[" << i*vectorsPerBatch << "]) = ";
        cout << resultPtxts[i] << endl;
    }
    
    return 0;
}