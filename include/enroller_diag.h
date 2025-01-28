// ** base_enroller: class for encrypting and/or serializing all database vectors
// done according to our novel diagonal approach

#pragma once

#include "enroller_hers.h"

class DiagonalEnroller : public HersEnroller {
public:
  // constructor
  DiagonalEnroller(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam);

  // public methods
  void serializeDB(vector<vector<double>> &database);

protected:
  // protected methods
  vector<vector<vector<double>>> splitIntoSquareMatrices(vector<vector<double>> &matrix, int k);

  void printMatrix(vector<vector<double>> matrix);

  vector<vector<double>> preprocessToDiagonalForm(vector<vector<double>> &matrix);

  vector<vector<double>> concatenateRows(const vector<vector<vector<double>>> &matrices);

  void serializeDBThread(vector<double> &currentRows, size_t index);

};