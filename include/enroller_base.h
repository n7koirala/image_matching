// ** base_enroller: class for encrypting and/or serializing all database vectors
// done according to the lit baseline approach

#pragma once

#include "enroller.h"

class BaseEnroller : public Enroller {
public:
  // constructor
  BaseEnroller(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam);

  // public methods
  void serializeDB(vector<vector<double>> database);

};