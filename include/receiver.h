// ** receiver: Defines the abstract class for receiver (querier) functionality

#pragma once

#include "../include/config.h"
#include "../include/openFHE_wrapper.h"
#include "../include/vector_utils.h"
#include "openfhe.h"
#include <vector>
#include <omp.h>
#include <ctime>
#include <fstream>

using namespace lbcrypto;
using namespace std;

class Receiver {
public:
  // constructor
  Receiver(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
              PrivateKey<DCRTPoly> skParam, size_t vectorParam);

  // destructor
  virtual ~Receiver() = default;

  // virtual methods -- to be overridden by derived receiver classes
  virtual vector<Ciphertext<DCRTPoly>> 
  encryptQuery(vector<double> query) = 0;

  virtual bool 
  decryptMembership(Ciphertext<DCRTPoly> &membershipCipher) = 0;

  virtual vector<size_t> 
  decryptIndex(vector<Ciphertext<DCRTPoly>> &indexCipher) = 0;

protected:
  // protected members (accessible by derived classes)
  CryptoContext<DCRTPoly> cc;
  PublicKey<DCRTPoly> pk;
  PrivateKey<DCRTPoly> sk;
  size_t numVectors;

};