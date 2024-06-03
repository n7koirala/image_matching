// ** Wrapper functions for the OpenFHE library

#pragma once

#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

namespace OpenFHEWrapper {
void printSchemeDetails(CCParams<CryptoContextCKKSRNS> parameters, CryptoContext<DCRTPoly> cc);

}