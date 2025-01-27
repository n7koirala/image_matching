#include "../../include/sender.h"

// implementation of functions declared in sender.h

// -------------------- CONSTRUCTOR --------------------

Sender::Sender(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
               size_t vectorParam)
    : cc(ccParam), pk(pkParam), numVectors(vectorParam) {}