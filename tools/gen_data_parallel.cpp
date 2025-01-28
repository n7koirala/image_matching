#include <cstdlib>
#include <time.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;

int main(int argc, char *argv[]) {

    srand( (unsigned)time(NULL) );

    const size_t D = 512;
    const size_t N = atoi(argv[1]);
    vector<vector<int>> output(N);

    // generate random values
    #pragma omp parallel for num_threads(16)
    for (size_t i = 0; i < N; i++) {
        vector<int> current(D);
        for (size_t j = 0; j < D; j++) {
            current[j] = (rand() % 199 - 99);
        }
        output[i] = current;
    }

    for (size_t n = pow(2, 10); n <= N; n *= 2) {
        vector<int> match(D);
        for (size_t j = 0; j < D; j++) {
            match[j] = (rand() % 3 + 1);
        }
        output[n-1] = match;
    }

    // output to cout
    cout << N << endl;
    vector<int> query(D, 1);
    for (size_t j = 0; j < D; j++) {
        cout << query[j] << " ";
    }
    cout << endl;

    for (size_t i = 0; i < N; i++) {
        for (size_t j = 0; j < D; j++) {
            cout << output[i][j] << " ";
        }
        cout << endl;
    }
}