#include "../include/cosine_similarity.h"
#include <vector> 
#include "openfhe.h"

using namespace lbcrypto;

// implementation of functions declared in cosine_similarity.h

double CosineSimilarity::plaintextMagnitude(int dim, vector<double> x) {
    double m = 0.0;
    for(int i = 0; i < dim; i++) {
        m += (x[i] * x[i]);
    }
    m = sqrt(m);
    return m;
}

double CosineSimilarity::plaintextInnerProduct(int dim, vector<double> x, vector<double> y) {
    double prod = 0.0;
    for(int i = 0; i < dim; i++) {
        prod += x[i] * y[i];
    }
    return prod;
}

vector<double> CosineSimilarity::plaintextNormalize(int dim, vector<double> x) {
    double m = plaintextMagnitude(dim, x);
    vector<double> x_norm = x;
    if(m != 0) {
        for(int i = 0; i < dim; i++) {
            x_norm[i] = x[i] / m;
        }
    }
    return x_norm;
}

/* This computation involves division, cannot be done directly in encrypted domain */
double CosineSimilarity::plaintextCosineSim(int dim, vector<double> x, vector<double> y) {
    return plaintextInnerProduct(dim, x, y) / (plaintextMagnitude(dim, x) * plaintextMagnitude(dim, y));
}

/* Append the vector source onto the end of the vector dest, n times */
void CosineSimilarity::concatenateVectors(vector<double>& dest, vector<double> source, int n) {
    for(int i = 0; i < n; i++) {
        dest.insert(dest.end(), source.begin(), source.end());
    }
}

/* Uses Newton's Method to approximate the inverse magnitude of a ciphertext */
Ciphertext<DCRTPoly> CosineSimilarity::approxInverseMagnitude(int dim, CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, KeyPair<DCRTPoly> keyPair) {
    int NUM_ITERATIONS = 3; // multiplicative depth for i iterations is 3i+1

    auto bn = cc->EvalInnerProduct(ctxt, ctxt, dim);

    vector<double> initialGuess(dim, 0.001);
    Plaintext initialPtxt = cc->MakeCKKSPackedPlaintext(initialGuess);
    auto fn = cc->Encrypt(keyPair.publicKey, initialPtxt);

    auto yn = fn;

    for(int i = 0; i < NUM_ITERATIONS; i++) {
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