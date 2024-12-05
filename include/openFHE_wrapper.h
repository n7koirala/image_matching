// ** Wrapper functions for the OpenFHE library

#pragma once

#include "config.h"
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

namespace OpenFHEWrapper {

size_t 
computeRequiredDepth(size_t approach);

void 
printSchemeDetails(CCParams<CryptoContextCKKSRNS> parameters, CryptoContext<DCRTPoly> cc);

void
printCipherDetails(Ciphertext<DCRTPoly> ctxt);

Ciphertext<DCRTPoly> 
encryptFromVector(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk, vector<double> vec);

vector<double> 
decryptToVector(CryptoContext<DCRTPoly> cc, PrivateKey<DCRTPoly> sk, Ciphertext<DCRTPoly> ctxt);

vector<double> 
decryptVectorToVector(CryptoContext<DCRTPoly> cc, PrivateKey<DCRTPoly> sk, vector<Ciphertext<DCRTPoly>> ctxt);

Ciphertext<DCRTPoly> 
binaryRotate(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, int factor);

Ciphertext<DCRTPoly> 
sign(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, size_t maxDepth);

Ciphertext<DCRTPoly> 
sumAllSlots(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt);

Ciphertext<DCRTPoly>
chebyshevCompare(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, double delta, size_t signDepth);

vector<Ciphertext<DCRTPoly>> 
mergeCiphers(CryptoContext<DCRTPoly> cc, vector<Ciphertext<DCRTPoly>> &ctxts, size_t dimension);

Ciphertext<DCRTPoly> 
mergeSingleCipher(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> &ctxt, size_t dimension);

Plaintext 
generateMergeMask(CryptoContext<DCRTPoly> cc, size_t dimension, size_t segmentLength);
}