#include "../include/openFHE_wrapper.h"

void OpenFHEWrapper::printSchemeDetails(CCParams<CryptoContextCKKSRNS> parameters, CryptoContext<DCRTPoly> cc) {
  cout << "batch size: " << cc->GetEncodingParams()->GetBatchSize() << endl;
  cout << endl;

  cout << "CKKS default parameters: " << parameters << endl;
  cout << endl;

  cout << "scaling mod size: " << parameters.GetScalingModSize() << endl;
  cout << "ring dimension: " << cc->GetRingDimension() << endl;
  cout << "noise estimate: " << parameters.GetNoiseEstimate() << endl;
  cout << "multiplicative depth: " << parameters.GetMultiplicativeDepth() <<
  endl; cout << "noise level: " << parameters.GetNoiseEstimate() << endl;
}



void OpenFHEWrapper::deserializeKeys(CryptoContext<DCRTPoly> cc, PrivateKey<DCRTPoly> sk) {
  // Attempting to serialize / deserialize keys, need help on this
  int batchSize = cc->GetEncodingParams()->GetBatchSize();

  // Attempt to deserialize mult keys
  ifstream multKeyIStream("/key_mult.txt", ios::in | ios::binary);
  if (!multKeyIStream.is_open() || !cc->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY)) {
    cerr << "Error: Cannot read serialization from " << "/key_mult.txt" << endl;
    
    cc->EvalMultKeyGen(sk);
    cout << "[main.cpp]\tMult key generated..." << endl;
    ofstream multKeyFile("/key_mult.txt", ios::out | ios::binary);
    if (multKeyFile.is_open()) {
      if (!cc->SerializeEvalMultKey(multKeyFile, SerType::BINARY)) {
        cerr << "Error: writing mult keys" << endl;
        exit(1);
      }
      cout << "[main.cpp]\tMult keys serialized..." << endl;
      multKeyFile.close();
    } else {
      cerr << "Error: serializing mult keys" << endl;
      exit(1);
    }
  } else {
    cout << "[main.cpp]\tSuccessfully deserialized mult keys" << endl;
  }

  // Attempt to deserialize sum keys
  ifstream sumKeyIStream("/key_sum.txt", ios::in | ios::binary);
  if (!sumKeyIStream.is_open() || !cc->DeserializeEvalSumKey(sumKeyIStream, SerType::BINARY)) {
    cerr << "Error: Cannot read serialization from " << "/key_sum.txt" << endl;
    
    cc->EvalSumKeyGen(sk);
    cout << "[main.cpp]\tSum key generated..." << endl;
    ofstream sumKeyFile("/key_sum.txt", ios::out | ios::binary);
    if (sumKeyFile.is_open()) {
      if (!cc->SerializeEvalSumKey(sumKeyFile, SerType::BINARY)) {
        cerr << "Error: writing sum keys" << endl;
        exit(1);
      }
      cout << "[main.cpp]\tSum keys serialized..." << endl;
      sumKeyFile.close();
    } else {
      cerr << "Error: serializing sum keys" << endl;
      exit(1);
    }
  } else {
    cout << "[main.cpp]\tSuccessfully deserialized sum keys" << endl;
  }

  // Attempt to deserialize rotation key
  ifstream rotKeyIStream("/key_rot.txt", ios::in | ios::binary);
  if (!rotKeyIStream.is_open() || !cc->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY)) {
    cerr << "Cannot read serialization from " << "/key_rot.txt" << endl;
    
    // If deserialization fails, generate and serialize new key

    // these specific rotations needed for merge operation
    vector<int> binaryRotationFactors;
    for(int i = 1; i < batchSize; i *= 2) {
      binaryRotationFactors.push_back(i);
      binaryRotationFactors.push_back(-i);
    }

    cc->EvalRotateKeyGen(sk, binaryRotationFactors);
    cout << "[main.cpp]\tRotation keys generated..." << endl;
    
    ofstream rotationKeyFile("/key_rot.txt", ios::out | ios::binary);
    if (rotationKeyFile.is_open()) {
      if (!cc->SerializeEvalAutomorphismKey(rotationKeyFile, SerType::BINARY)) {
        cerr << "Error: writing rotation keys" << endl;
        exit(1);
      }
      cout << "[main.cpp]\tRotation keys serialized..." << endl;
    }
    else {
      cerr << "Error: serializing rotation keys" << endl;
      exit(1);
    }
  } else {
    cout << "[main.cpp]\tSuccessfully deserialized rotation keys" << endl;
  }
}

// decrypts a given ciphertext and returns a vector of its contents
// for ease of testing purposes
Ciphertext<DCRTPoly> OpenFHEWrapper::encryptFromVector(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk, vector<double> vec) {
  Plaintext ptxt = cc->MakeCKKSPackedPlaintext(vec);
  return cc->Encrypt(pk, ptxt);
}


// decrypts a given ciphertext and returns a vector of its contents
// for ease of testing purposes
vector<double> OpenFHEWrapper::decryptToVector(CryptoContext<DCRTPoly> cc, PrivateKey<DCRTPoly> sk, Ciphertext<DCRTPoly> ctxt) {
  Plaintext ptxt;
  cc->Decrypt(sk, ctxt, &ptxt);
  return ptxt->GetRealPackedValue();
}


vector<double> OpenFHEWrapper::decryptVectorToVector(CryptoContext<DCRTPoly> cc, PrivateKey<DCRTPoly> sk, vector<Ciphertext<DCRTPoly>> ctxt) {
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  vector<double> temp(batchSize);
  vector<double> output(batchSize * ctxt.size());
  Plaintext ptxt;
  for(size_t i = 0; i < ctxt.size(); i++) {
    cc->Decrypt(sk, ctxt[i], &ptxt);
    temp = ptxt->GetRealPackedValue();
    copy(temp.begin(), temp.end(), output.begin() + i * batchSize);
  }
  return output;
}


// performs any rotation on a ciphertext using 2log_2(batchsize) rotation keys and (1/2)log_2(batchsize) rotations
Ciphertext<DCRTPoly> OpenFHEWrapper::binaryRotate(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, int factor) {
  int batchSize = cc->GetEncodingParams()->GetBatchSize();

  vector<int> neededRotations;
  int factorSign;
  int binaryCounter;
  int currentRotation;

  while(factor != 0) {
    factorSign = factor / abs(factor);

    binaryCounter = pow(2, round(log2(abs(factor))));
    currentRotation = (binaryCounter * factorSign) % batchSize;
    if(currentRotation != 0) {
      neededRotations.push_back(binaryCounter * factorSign);
    }

    factor -= binaryCounter * factorSign;
  }

  for(long unsigned int i = 0; i < neededRotations.size(); i++) {
    ctxt = cc->EvalRotate(ctxt, neededRotations[i]);
  }

  return ctxt;
}


// Sign-approximating polynomial f_4(x) determined from JH Cheon, 2019/1234
// https://ia.cr/2019/1234
Ciphertext<DCRTPoly> OpenFHEWrapper::sign(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> x) {
  
  // extends range of sign-approximating poly to (-2, 2)
  // x = cc->EvalMult(x, 0.75);

  vector<double> coefficients({ 0.0, 
                                315.0 / 128.0,  
                                0.0, 
                                -420.0 / 128.0, 
                                0.0, 
                                378.0 / 128.0,
                                0.0, 
                                -180.0 / 128.0,
                                0.0,
                                35.0 / 128.0});

  for(int i = 0; i < SIGN_COMPOSITIONS; i++) {
    x = cc->EvalPoly(x, coefficients);
  }

  return cc->EvalMult(0.5, cc->EvalAdd(x, 1.0));
}

// Sets every slot in the ciphertext equal to the sum of all slots
Ciphertext<DCRTPoly> OpenFHEWrapper::sumAllSlots(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt) {
  int batchSize = cc->GetEncodingParams()->GetBatchSize();
  Ciphertext<DCRTPoly> temp;
  for(int i = 1; i < batchSize; i *= 2) {
    temp = binaryRotate(cc, ctxt, i);
    ctxt = cc->EvalAdd(ctxt, temp);
  }
  return ctxt;
}

// Uses Newton's Method to approximate the inverse square root of the slots of a ciphertext
// Requires good initial approximation
Ciphertext<DCRTPoly>
OpenFHEWrapper::approxInverseRoot(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, Ciphertext<DCRTPoly> initial) {

  Ciphertext<DCRTPoly> bn = ctxt;
  Ciphertext<DCRTPoly> fn = initial;
  Ciphertext<DCRTPoly> yn = fn;

  // Perform Newton's method to approximate inverse magnitude of ctxt
  // The multiplicative depth for i iterations is 3i+1
  for (int i = 0; i < NEWTONS_ITERATIONS; i++) {
    // b(n+1) = b(n) * f(n)^2
    bn = cc->EvalMult(bn, fn);
    bn = cc->EvalMult(bn, fn);

    // f(n+1) = (1/2) * (3 - b(n))
    fn = cc->EvalSub(3.0, bn);
    fn = cc->EvalMult(fn, 0.5);

    // y(n+1) = y(n) * f(n)
    yn = cc->EvalMult(yn, fn);
  }

  return yn;
}



Ciphertext<DCRTPoly>
OpenFHEWrapper::normalizeVector(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, int dimension, double initialSlope, double initialIntercept) {

  Ciphertext<DCRTPoly> selfInnerProduct = cc->EvalInnerProduct(ctxt, ctxt, dimension);
  Ciphertext<DCRTPoly> initialGuess = cc->EvalAdd(cc->EvalMult(selfInnerProduct, initialSlope), initialIntercept);
  Ciphertext<DCRTPoly> normalizationFactor = approxInverseRoot(cc, selfInnerProduct, initialGuess);
  
  return cc->EvalMult(ctxt, normalizationFactor);
}


Ciphertext<DCRTPoly>
OpenFHEWrapper::chebyshevSign(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, double lower, double upper, int polyDegree) {
  Ciphertext<DCRTPoly> result = cc->EvalChebyshevFunction([](double x) -> double { return x / abs(x); }, ctxt, lower,
                                          upper, polyDegree);
  return result;
}


// packs every i-th slot of each cipher into a consecutive sequence at the front of the outputted cipher(s)
// can handle cases where the number of slots is larger than the batch size of a single ciphertext
// requires dimension param to be a power of two
vector<Ciphertext<DCRTPoly>> OpenFHEWrapper::mergeCiphers(CryptoContext<DCRTPoly> cc, vector<Ciphertext<DCRTPoly>> ctxts, size_t dimension) {
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t elementsPerCipher = batchSize / dimension;
  size_t outputSize = elementsPerCipher * ctxts.size();
  size_t neededCiphers = ceil(double(outputSize) / double(batchSize));
  size_t outputCipher;
  size_t outputSlot;
  
  vector<Ciphertext<DCRTPoly>> mergedCipher(neededCiphers);

  for(size_t i = 0; i < ctxts.size(); i++) {
    outputCipher = (elementsPerCipher * i) / batchSize;
    outputSlot = (elementsPerCipher * i) % batchSize;

    if(outputSlot == 0) {
      mergedCipher[outputCipher] = OpenFHEWrapper::mergeSingleCipher(cc, ctxts[i], dimension);
    } else {
      cc->EvalAddInPlace(mergedCipher[outputCipher], OpenFHEWrapper::binaryRotate(cc, OpenFHEWrapper::mergeSingleCipher(cc, ctxts[i], dimension), -outputSlot));
    }
  }

  return mergedCipher;
}


// packs every i-th slot of the cipher into a consecutive sequence at the front of the outputted cipher
// requires dimension param to be a power of two
Ciphertext<DCRTPoly> OpenFHEWrapper::mergeSingleCipher(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, size_t dimension) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t outputSize = batchSize / dimension;
  size_t paddingSize = 1;
  size_t rotationFactor = dimension - 1;

  // perform log2 rotations and additions
  for(size_t i = 1; i < outputSize; i *= 2) {
    
    // apply multiplicative mask if rotations + additions have consumed all the padded zeros
    if(i >= paddingSize) {
      ctxt = cc->EvalMult(ctxt, OpenFHEWrapper::generateMergeMask(cc, dimension, i));
      // cc->RescaleInPlace(ctxt); // Rescaling here introduces nonnegligible errors -- discuss why in next meeting
      paddingSize = i * dimension;
    }
    
    cc->EvalAddInPlace(ctxt, OpenFHEWrapper::binaryRotate(cc, ctxt, rotationFactor * i));
  }

  ctxt = cc->EvalMult(ctxt, generateMergeMask(cc, dimension, outputSize));
  // cc->RescaleInPlace(ctxt);

  return ctxt;
}


// generates a plaintext multiplicative mask to isolate needed slots during repeated rotations + additions
// helper function for single-cipher merge operation
Plaintext OpenFHEWrapper::generateMergeMask(CryptoContext<DCRTPoly> cc, size_t dimension, size_t segmentLength) {
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  vector<double> mask(batchSize, 0.0);

  if(segmentLength > batchSize / dimension) {
    cerr << "Mask generation index error" << endl;
    return cc->MakeCKKSPackedPlaintext(mask);
  }

  size_t i = 0;
  while(i < batchSize) {
    fill(mask.begin()+i, mask.begin()+i+segmentLength, 1.0);
    i += dimension * segmentLength;
  }
  return cc->MakeCKKSPackedPlaintext(mask);
}