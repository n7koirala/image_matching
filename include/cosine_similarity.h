// ** cosine_similarity: Contains the definition and implementation of the cosine similarity computation logic.

#include "../include/openFHE_wrapper.h"
#include <vector>
#include "openfhe.h"

using namespace lbcrypto;
using namespace std;

class CosineSimilarity {
public:
    // utitlity functions for computing cosine similarity
    double plaintextMagnitude(int dim, vector<double> x);
    double plaintextInnerProduct(int dim, vector<double> x, vector<double> y);
    std::vector<double> plaintextNormalize(int dim, vector<double> x);
    double plaintextCosineSim(int dim, vector<double> x, vector<double> y);
    void concatenateVectors(vector<double>& dest, vector<double> source, int n);
private:
    // some private members here
};