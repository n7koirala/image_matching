#include "../../include/receiver.h"

// implementation of functions declared in receiver.h

// -------------------- CONSTRUCTOR --------------------

Receiver::Receiver(CryptoContext<DCRTPoly> ccParam,
                         PublicKey<DCRTPoly> pkParam, PrivateKey<DCRTPoly> skParam, size_t vectorParam)
    : cc(ccParam), pk(pkParam), sk(skParam), numVectors(vectorParam) {}