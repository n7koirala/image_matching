// ** base_enroller: class for encrypting and/or serializing all database vectors
// done according to the blind-match approach

#pragma once

#include "enroller.h"

class BlindEnroller : public Enroller {
public:
  // constructor
  BlindEnroller(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam);

  // public methods
  void serializeDB(vector<vector<double>> &database, size_t chunkLength);

protected:
	void serializeDBThread(vector<vector<double>> &database, size_t chunkLength, size_t matrix, size_t index);

};