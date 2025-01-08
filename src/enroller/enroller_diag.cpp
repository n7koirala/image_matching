#include "../../include/enroller_diag.h"

// implementation of functions declared in enroller.h

// -------------------- CONSTRUCTOR --------------------

DiagonalEnroller::DiagonalEnroller(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
         size_t vectorParam)
  : Enroller(ccParam, pkParam, vectorParam) {}

// -------------------- PUBLIC FUNCTIONS --------------------
void DiagonalEnroller::serializeDB(vector<vector<double>> database) {

  // create necessary directory if does not exist
  string dirName = "serial/";
  if(!filesystem::exists(dirName)) {
    if(!filesystem::create_directory(dirName)) {
      cerr << "Error: Failed to create directory \"" + dirName + "\"" << endl;
      return;
    }
  }

  // create matrix-specific directories if they don't exist
  dirName = "serial/db_diagonal";
  if(!filesystem::exists(dirName)) {
    if(!filesystem::create_directory(dirName)) {
      cerr << "Error: Failed to create directory \"" + dirName + "\"" << endl;
    }
  }

  vector<vector<vector<double>>> squareMatrices = splitIntoSquareMatrices(database, VECTOR_DIM);
  
  vector<vector<vector<double>>> allDiagonalMatrices;
  for (auto &squareMatrix: squareMatrices) {
    vector<vector<double>> diagonals = preprocessToDiagonalForm(squareMatrix);
    allDiagonalMatrices.push_back(diagonals);
  }

  vector<vector<double>> concatenatedRows = concatenateRows(allDiagonalMatrices);

  /*
  cout << "\nConcatenated Rows:" << endl;
  for (const auto& row : concatenatedRows) {
    for (double value : row) {
      cout << value << " ";
    }
    cout << endl;
    cout << endl;
  }
   */

  // encrypt each row 
  #pragma omp parallel for num_threads(RECEIVER_NUM_CORES)
  for (size_t i = 0; i < concatenatedRows.size(); i++) {
    serializeDBThread(concatenatedRows[i], i);
  }
}

// -------------------- PROTECTED FUNCTIONS --------------------

vector<vector<vector<double>>> DiagonalEnroller::splitIntoSquareMatrices(vector<vector<double>> &matrix, int k) {
  int rows = matrix.size();
  int cols = matrix[0].size();
  vector<vector<vector<double> > > result;

  // Split the matrix into k x k square matrices
  for (int i = 0; i < rows; i += k) {
	  vector<vector<double> > squareMatrix;

    for (int j = 0; j < k; ++j) {
      vector<double> row;
      for (int col = 0; col < cols; ++col) {
        row.push_back(matrix[i + j][col]);
      }
      squareMatrix.push_back(row);
    }

    result.push_back(squareMatrix);
  }

  return result;
}

// function to print the matrix
void DiagonalEnroller::printMatrix(vector<vector<double>> matrix) {
  for (const auto& row : matrix) {
    for (double value : row) {
      cout << value << " ";
    }
    cout << endl;
  }
}

// pre-process the matrix into diagonal form
vector<vector<double>> DiagonalEnroller::preprocessToDiagonalForm(vector<vector<double>> &matrix) {
  int K = matrix.size();    // number of rows
  int N = matrix[0].size();    // number of columns

  vector<vector<double>> diagonals(N, vector<double>(K));

  // fill each diagonal vector
  for (int i = 0; i < N; ++i) {
    for (int j = 0; j < K; ++j) {
      // calculate the column index for diagonal i in row j
      int colIndex = (j + i) % N;
      diagonals[i][j] = matrix[j][colIndex];
    }
  }

  return diagonals;
}

// Function to concatenate rows from multiple matrices
vector<vector<double>> DiagonalEnroller::concatenateRows(const vector<vector<vector<double>>> &matrices) {
  vector<vector<double>> concatenatedRows;

  if (matrices.empty()) return concatenatedRows;

  // Assume all matrices have the same number of rows
  int numRows = matrices[0].size();

  // For each row in the matrices
  for (int rowIndex = 0; rowIndex < numRows; ++rowIndex) {
	vector<double> concatenatedRow;

    // Concatenate the rowIndex-th row of each matrix
    for (const auto& matrix : matrices) {
      const auto& row = matrix[rowIndex];
      concatenatedRow.insert(concatenatedRow.end(), row.begin(), row.end());
    }

    concatenatedRows.push_back(concatenatedRow);
  }

  return concatenatedRows;
}

void DiagonalEnroller::serializeDBThread(vector<double> &currentRow, size_t index) {

  Ciphertext<DCRTPoly> currentCtxt = OpenFHEWrapper::encryptFromVector(cc, pk, currentRow);
  string filepath = "serial/db_diagonal/index" + to_string(index) + ".bin";
  if (!Serial::SerializeToFile(filepath, currentCtxt, SerType::BINARY)) {
    cerr << "Error: serialization failed (cannot write to " + filepath + ")" << endl;
  }

}