// ** Wrapper functions for the OpenFHE library

#pragma once

#include "config.h"
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

namespace OpenFHEWrapper {

void printSchemeDetails(CCParams<CryptoContextCKKSRNS> parameters, CryptoContext<DCRTPoly> cc);

void deserializeKeys(CryptoContext<DCRTPoly> cc, PrivateKey<DCRTPoly> sk);

Ciphertext<DCRTPoly> encryptFromVector(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk, vector<double> vec);

vector<double> decryptToVector(CryptoContext<DCRTPoly> cc, PrivateKey<DCRTPoly> sk, Ciphertext<DCRTPoly> ctxt);

Ciphertext<DCRTPoly> binaryRotate(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, int factor);

Ciphertext<DCRTPoly> sign(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt);

Ciphertext<DCRTPoly> sumAllSlots(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt);

Ciphertext<DCRTPoly> approxInverseRoot(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, Ciphertext<DCRTPoly> initial);

Ciphertext<DCRTPoly> normalizeVector(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, int dimension, double initialSlope, double initialIntercept);

Ciphertext<DCRTPoly> chebyshevSign(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, double lower, double upper, int polyDegree);

Ciphertext<DCRTPoly> alphaNorm(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, size_t alpha, size_t partitionLen);

vector<Ciphertext<DCRTPoly>> mergeCiphers(CryptoContext<DCRTPoly> cc, vector<Ciphertext<DCRTPoly>> ctxts, size_t dimension);

Ciphertext<DCRTPoly> mergeSingleCipher(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, size_t dimension);

Plaintext generateMergeMask(CryptoContext<DCRTPoly> cc, size_t dimension, size_t segmentLength);
}