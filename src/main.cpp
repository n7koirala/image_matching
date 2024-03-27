#include "iostream"
#include "openfhe.h"

using namespace lbcrypto;
using namespace std;

// ** Entry point of the application that orchestrates the flow. **

int main() {
    
    std::cout << "Test.." << std::endl;

     CCParams<CryptoContextCKKSRNS> parameters;

    uint32_t multDepth = 12; 

    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(45);
    parameters.SetBatchSize(32768);


    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    auto pk = keyPair.publicKey;

    unsigned int batchSize = cc->GetEncodingParams()->GetBatchSize();
    std::cout << "batchSize: " << batchSize << std::endl;

    std::cout << "CKKS default parameters: " << parameters << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;

    std::cout << "scaling mod size: " << parameters.GetScalingModSize() << std::endl;
    std::cout << "ring dimension: " << cc->GetRingDimension() << std::endl;
    std::cout << "noise estimate: " << parameters.GetNoiseEstimate() << std::endl;
    std::cout << "multiplicative depth: " << parameters.GetMultiplicativeDepth() << std::endl;
    std::cout << "Noise level: " << parameters.GetNoiseEstimate() << std::endl;


    return 0;
}