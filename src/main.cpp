#include "iostream"
#include "../include/cosine_similarity.h"
#include "openfhe.h"

using namespace lbcrypto;
using namespace std;

// ** Entry point of the application that orchestrates the flow. **

int main() {

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
    cout << "Noise level: " << parameters.GetNoiseEstimate() << endl;
    */
    
    // Randomized inputs
    int inputDim = 8;
    vector<double> xQ(inputDim);
    vector<double> x1(inputDim);
    vector<double> x2(inputDim);
    for(int i = 0; i < inputDim; i++) {
        xQ[i] = (rand() % 199) - 99; // random integer in [-99, 99]
        x1[i] = (rand() % 199) - 99; // random integer in [-99, 99]
        x2[i] = (rand() % 199) - 99; // random integer in [-99, 99]
    }
    
    cout << "Expected CS(xQ, x1) = " << cs.plaintextCosineSim(inputDim, xQ, x1) << endl;
    cout << "Expected CS(xQ, x2) = " << cs.plaintextCosineSim(inputDim, xQ, x2) << endl;

    // Normalize in plaintext domain
    vector<double> xQNorm = cs.plaintextNormalize(inputDim, xQ);
    vector<double> x1Norm = cs.plaintextNormalize(inputDim, x1);
    vector<double> x2Norm = cs.plaintextNormalize(inputDim, x2);

    // Concatenate for batching purposes
    vector<double> xQBatched = xQNorm;
    xQBatched.insert(xQBatched.end(), xQNorm.begin(), xQNorm.end());
    vector<double> x1Batched = x1Norm;
    x1Batched.insert(x1Batched.end(), x2Norm.begin(), x2Norm.end());

    // Encode as plaintexts
    Plaintext ptxtQ = cc->MakeCKKSPackedPlaintext(xQNorm);
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1Norm);
    Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2Norm);

    Plaintext ptxtQB = cc->MakeCKKSPackedPlaintext(xQBatched);
    Plaintext ptxt1B = cc->MakeCKKSPackedPlaintext(x1Batched);    
    
    // Encrypt the encoded vectors
    auto cQ = cc->Encrypt(pk, ptxtQ);
    auto c1 = cc->Encrypt(pk, ptxt1);
    auto c2 = cc->Encrypt(pk, ptxt2);

    auto cQB = cc->Encrypt(pk, ptxtQB);
    auto c1B = cc->Encrypt(pk, ptxt1B);

    // Compute cosine similarity in encrypted domain
    auto cQ1 = cc->EvalInnerProduct(cQ, c1, inputDim);
    auto cQ2 = cc->EvalInnerProduct(cQ, c2, inputDim);

    auto cB = cc->EvalInnerProduct(cQB, c1B, inputDim);

    // Decryption
    Plaintext result;
    cout.precision(4);
    cout << endl << "Non-batched homomorphic computations: " << endl;

    cc->Decrypt(sk, cQ1, &result);
    result->SetLength(1);
    cout << "Homomorphic CS(xQ, x1) = " << result;

    cc->Decrypt(sk, cQ2, &result);
    result->SetLength(1);
    cout << "Homomorphic CS(xQ, x2) = " << result;

    cout << endl << "Two-vector batched homomorphic computations: " << endl;

    cc->Decrypt(sk, cB, &result);
    result->SetLength(9);
    cout << "Homomorphic CS(xQ, x1, x2) = " << result;
    
    return 0;
}