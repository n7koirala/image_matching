# Image Matching README

## Introduction

Welcome to the **Image Matching** project! This repository contains a comprehensive implementation of two image matching algorithms. The **Membership Scenario** determines whether a query image possesses any matches among a database of images. The **Index Scenario** determines which specific database images, if any, match with a query image.

The primary goal of this project is to provide a robust framework for the comparison and matching of facial representation vectors using advanced cryptographic techniques, specifically homomorphic encryption.

For theoretical details of this implementation, refer to this document: [Image Matching Documentation](https://www.overleaf.com/read/cbqxkzbbxjvd#ea7444).

## Features

- **Homomorphic Encryption**: Leverages the OpenFHE library to perform secure computations on encrypted data.
- **Biometric Standards**: Complies with standards set by the National Institute of Standards and Technology (NIST).
- **Parallel Processing**: Supports parallel processing to enhance performance.

## Requirements

- **C++ Compiler**: Ensure you have a modern C++ compiler that supports C++17 or later.
- **CMake**: Build system generator (version 3.10 or later).
- **OpenFHE Library**: For homomorphic encryption operations.
- **Standard Libraries**: Standard libraries for image processing and mathematical computations.

## Installation

### Step-by-Step Guide

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/n7koirala/image_matching.git
    cd image_matching
    ```

2. **Install Dependencies**:
    Ensure you have all necessary dependencies installed:
    - OpenFHE
    - CMake
    - Standard C++ libraries

3. **Build the Project**:
    ```bash
    mkdir build
    cd build
    cmake ..
    make
    ```

## Usage

To run the image matching application, navigate to the `build` folder and use the following command in your terminal:

```bash
./image_matching ../test/[image_file.dat]
```

<!For instance, try:
```bash
./image_matching ../test/2^10.dat
```>


This will execute the main application, showcasing both image matching algorithms, more specifically their encryption, matching, and decryption steps.


## Configuration

### Parameters

The application can be configured using various parameters defined in the source code. Key parameters include:

- **Similarity Match Threshold**: Set the cosine similarity value above which vectors are considered to be matching.
- **Sign Depth**: Set the maximum multiplicative depth of the sign-approximating polynomial.
- **Multiplicative Depth**: Set the depth of multiplicative operations.
- **Scaling Mod Size**: Configure the size for scaling modulus.
- **Batch Size**: Determine the batch size for encoding parameters.

### Example Configuration

```cpp
// include/config.h
const double MATCH_THRESHOLD = 0.85;
const int SIGN_DEPTH = 13;
```

```cpp
// src/main.cpp
uint32_t multDepth = SIGN_DEPTH + 1;
CCParams<CryptoContextCKKSRNS> parameters;
parameters.SetSecurityLevel(HEStd_128_classic);
parameters.SetMultiplicativeDepth(multDepth);
parameters.SetScalingModSize(45);
```

## Contributing

We welcome contributions from the community to enhance the functionality and performance of the image matching project. Here’s how you can contribute:

1. **Fork the Repository**: Click on the fork button at the top right of the repository page.
2. **Create a Branch**: Create a new branch for your feature or bugfix.
    ```bash
    git checkout -b feature-name
    ```
3. **Make Changes**: Implement your changes in the new branch.
4. **Submit a Pull Request**: Push your changes to your forked repository and submit a pull request to the main repository.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

```text
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

This README provides a comprehensive guide to understanding, installing, and contributing to the image matching project. For more detailed information, please refer to the source code and comments within the repository.
