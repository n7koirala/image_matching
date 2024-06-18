// ** Wrapper functions for the OpenFHE library

#pragma once

#include "config.h"
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

namespace OpenFHEWrapper {
int computeMultDepth();

void printSchemeDetails(CCParams<CryptoContextCKKSRNS> parameters, CryptoContext<DCRTPoly> cc);

Ciphertext<DCRTPoly> binaryRotate(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, int factor);

Ciphertext<DCRTPoly> sign(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt);

Ciphertext<DCRTPoly> sumAllSlots(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt);

Ciphertext<DCRTPoly> approxInverseRoot(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, Ciphertext<DCRTPoly> initial);

Ciphertext<DCRTPoly> normalizeVector(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, int dimension, double initialSlope, double initialIntercept);

Ciphertext<DCRTPoly> alphaNorm(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, int alpha, int partitionLen);
}