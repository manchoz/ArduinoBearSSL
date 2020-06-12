#include <ArduinoBearSSL.h>

const uint16_t mySuites[] = {
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
};

constexpr size_t myNumSuites { sizeof(mySuites) / sizeof(mySuites[0]) };

const br_hash_class* myHashes[] = {
    &br_sha256_vtable
};

constexpr size_t myNumHashes { sizeof(myHashes) / sizeof(myHashes[0]) };
