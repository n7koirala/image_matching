#include "../include/openFHE_wrapper.h"

size_t OpenFHEWrapper::computeRequiredDepth(size_t approach) {

  // size_t depth = 0;

  switch(approach) {

    case 1: // novel stacked MVM
      break;

    case 2: // literature baseline
      break;

    case 3: // GROTE group testing
      break;

  }

  return 0;
}

// output relevant metadata of a given CKKS scheme
void OpenFHEWrapper::printSchemeDetails(CCParams<CryptoContextCKKSRNS> parameters, CryptoContext<DCRTPoly> cc) {
  cout << "batch size: " << cc->GetEncodingParams()->GetBatchSize() << endl;
  cout << endl;

  cout << "CKKS default parameters: " << parameters << endl;
  cout << endl;

  cout << "scaling mod size: " << parameters.GetScalingModSize() << endl;
  cout << "ring dimension: " << cc->GetRingDimension() << endl;
  cout << "noise estimate: " << parameters.GetNoiseEstimate() << endl;
  cout << "multiplicative depth: " << parameters.GetMultiplicativeDepth() << endl; 
  cout << "noise level: " << parameters.GetNoiseEstimate() << endl;
}


// output relevant internal details of a given ciphertext
void OpenFHEWrapper::printCipherDetails(Ciphertext<DCRTPoly> ctxt) {
  cout << "---------- Ciphertext Details ----------" << endl;
  cout << "\tBatch Size: " << ctxt->GetSlots() << endl;
  cout << "\tScaling Degree: " << ctxt->GetNoiseScaleDeg() << "\t(delta = " << ctxt->GetScalingFactor() << ")" << endl;
  cout << "\tLevel: " << ctxt->GetLevel() << endl;
  cout << "\tEncoding Parameters: " << ctxt->GetEncodingParameters() << endl;
  cout << endl;
}


// decrypts a given ciphertext and returns a vector of its contents
Ciphertext<DCRTPoly> OpenFHEWrapper::encryptFromVector(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk, vector<double> vec) {
  Plaintext ptxt = cc->MakeCKKSPackedPlaintext(vec);
  return cc->Encrypt(pk, ptxt);
}


// decrypts a given ciphertext and returns a vector of its contents
vector<double> OpenFHEWrapper::decryptToVector(CryptoContext<DCRTPoly> cc, PrivateKey<DCRTPoly> sk, Ciphertext<DCRTPoly> ctxt) {
  Plaintext ptxt;
  cc->Decrypt(sk, ctxt, &ptxt);
  return ptxt->GetRealPackedValue();
}

// decrypts a given vector of ciphertexts and returns a vector of their contents
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


// implements the sign function sgn(x) = { 1 if x>0, 0.5 if x=0, 0 if x<0 }
// sign-approximating polynomial f_4(x) and composition method determined from JH Cheon, 2019/1234 (https://ia.cr/2019/1234)
// performs i compositions, where 4i+1 <= maxDepth, ideally choose maxDepth to equal some 4i+1
Ciphertext<DCRTPoly> OpenFHEWrapper::sign(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> x, size_t maxDepth) {

  size_t comps = (maxDepth - 1) / 4;

  // coefficients for sign-aproximating polynomial f_4(x)
  const vector<double> COEFS({
    0.0, 
    315.0 / 128.0,  
    0.0, 
    -420.0 / 128.0, 
    0.0, 
    378.0 / 128.0,
    0.0, 
    -180.0 / 128.0,
    0.0,
    35.0 / 128.0
  });

  for(size_t i = 0; i < comps; i++) {
    // Note EvalPoly performs rescaling operation even with FIXEDMANUAL set, which is convenient
    x = cc->EvalPoly(x, COEFS);
  }

  // shift range from [-1, 1] to [0, 1], allowing for additive VAFs
  cc->EvalAddInPlace(x, 1.0);
  cc->EvalMultInPlace(x, 0.5);
  cc->RescaleInPlace(x);

  return x;
}


// TODO: replace built-in EvalSum function with this, remove generation of SumKey
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

// Approximates the piecewise comparison function x = { 2 if x >= delta ; 0 if x < delta }
Ciphertext<DCRTPoly>
OpenFHEWrapper::chebyshevCompare(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, double delta, size_t signDepth) {

  if (signDepth < 7 || signDepth > 15) {
    cerr << "Error: chebshevCompare requires a depth parameter between 7 and 15" << endl;
    return ctxt;
  }

  // Relationship between depth and polynomial degree described at the below link
  // https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/FUNCTION_EVALUATION.md
  const vector<int> DEPTH_TO_DEGREE({
    -1, -1, -1, -1, 5, 13, 27, 59, 119, 247, 495, 1007, 2031
  });

  // Coefficients for sign-approximating polynomial f_3 given in Cheon, 2019
  const vector<double> SIGN_COEFS({
    0.0, 
    35.0 / 16.0,  
    0.0, 
    -35.0 / 16.0, 
    0.0, 
    21.0 / 16.0,
    0.0, 
    -5.0 / 16.0
  });

  // compute Chebyshev approximation of sign function first for steeper slope near x=0
  // set to use a multiplicative depth of (signDepth - 3) 
  size_t polyDegree = DEPTH_TO_DEGREE[signDepth - 3];
  ctxt = cc->EvalChebyshevFunction([&delta](double x) -> double { return (x >= delta) ? 1 : -1; }, ctxt, -1, 1, polyDegree);

  // compute Cheon's polynomial approximation for smoother zeroing near x=-1 and x=1
  // requires multiplicative depth of 3
  // TODO: consider using a polynomial of depth 2 from same paper
  ctxt = cc->EvalPoly(ctxt, SIGN_COEFS);

  // shift range from [-1,1] to [0,2] fulfilling requirements for additive VAF
  cc->EvalAddInPlace(ctxt, 1.0);

  return ctxt;
}


// packs every i-th slot of each cipher into a consecutive sequence at the front of the outputted cipher(s)
// can handle cases where the number of slots is larger than the batch size of a single ciphertext
// requires dimension param to be a power of two
vector<Ciphertext<DCRTPoly>> OpenFHEWrapper::mergeCiphers(CryptoContext<DCRTPoly> cc, vector<Ciphertext<DCRTPoly>> &ctxts, size_t dimension) {
  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t elementsPerCipher = batchSize / dimension;
  size_t outputSize = elementsPerCipher * ctxts.size();
  size_t neededCiphers = ceil(double(outputSize) / double(batchSize));
  size_t outputCipher;
  size_t outputSlot;
  
  #pragma omp parallel for num_threads(SENDER_NUM_CORES)
  for(size_t i = 0; i < ctxts.size(); i++) {
    ctxts[i] = OpenFHEWrapper::mergeSingleCipher(cc, ctxts[i], dimension);
  }

  vector<Ciphertext<DCRTPoly>> mergedCipher(neededCiphers);

  for(size_t i = 0; i < ctxts.size(); i++) {
    outputCipher = (elementsPerCipher * i) / batchSize;
    outputSlot = (elementsPerCipher * i) % batchSize;

    if(outputSlot == 0) {
      mergedCipher[outputCipher] = ctxts[i];
    } else {
      cc->EvalAddInPlace(mergedCipher[outputCipher], OpenFHEWrapper::binaryRotate(cc, ctxts[i], -outputSlot));
    }
  }

  return mergedCipher;
}


// packs every i-th slot of the cipher into a consecutive sequence at the front of the outputted cipher
// requires dimension param to be a power of two
Ciphertext<DCRTPoly> OpenFHEWrapper::mergeSingleCipher(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> &ctxt, size_t dimension) {

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  size_t outputSize = batchSize / dimension;
  size_t paddingSize = 1;
  size_t rotationFactor = dimension - 1;

  // perform log2 rotations and additions
  for(size_t i = 1; i < outputSize; i *= 2) {
    
    // apply multiplicative mask if rotations + additions have consumed all the padded zeros
    if(i >= paddingSize) {
      ctxt = cc->EvalMult(ctxt, OpenFHEWrapper::generateMergeMask(cc, dimension, i));
      cc->RelinearizeInPlace(ctxt);
      cc->RescaleInPlace(ctxt);
      paddingSize = i * dimension;
    }
    
    cc->EvalAddInPlace(ctxt, OpenFHEWrapper::binaryRotate(cc, ctxt, rotationFactor * i));
  }

  ctxt = cc->EvalMult(ctxt, generateMergeMask(cc, dimension, outputSize));
  cc->RelinearizeInPlace(ctxt);
  cc->RescaleInPlace(ctxt);

  return ctxt;
}

// helper function for single-cipher merge operation
// generates a plaintext multiplicative mask to isolate needed slots during repeated rotations + additions
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