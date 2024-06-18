#include "../include/openFHE_wrapper.h"

// computes required multiplicative depth based on parameters from config.h
int OpenFHEWrapper::computeMultDepth() {
  // for initial similarity computation
  int depth = 1;

  // for the merge operation upon the similarity scores
  depth += 2;

  // for computing max approximations
  depth += ALPHA;

  // for merge operation upon the max approximations
  depth += 2;

  // for approximating inverse magnitude
  // depth += 3*NEWTONS_ITERATIONS;

  // each composition of the sign(x) polynomial requires a depth of 4
  depth += 4*SIGN_COMPOSITIONS;

  // TODO: determine untracked depth
  depth += 2;

  return depth;
}



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



// performs any rotation on a ciphertext using 2log2(batchsize) rotation keys and (1/2)log2(batchsize) rotations
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



// Approximating polynomial f4 determined from JH Cheon, 2019/1234
// TODO: properly cite
Ciphertext<DCRTPoly> OpenFHEWrapper::sign(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> x) {
  
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



Ciphertext<DCRTPoly> OpenFHEWrapper::alphaNorm(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, int alpha, int partitionLen) {
  Ciphertext<DCRTPoly> result = ctxt;

  for(int i = 0; i < alpha; i++) {
    result = cc->EvalMult(result, result);
  }
  result = cc->EvalInnerProduct(result, ctxt, partitionLen);

  return result;
}