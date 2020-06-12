#pragma once

#include "bearssl/bearssl_ssl.h"

/*
* The "full" profile supports all implemented cipher suites.
*
* Rationale for suite order, from most important to least
* important rule:
*
* -- Don't use 3DES if AES or ChaCha20 is available.
* -- Try to have Forward Secrecy (ECDHE suite) if possible.
* -- When not using Forward Secrecy, ECDH key exchange is
*    better than RSA key exchange (slightly more expensive on the
*    client, but much cheaper on the server, and it implies smaller
*    messages).
* -- ChaCha20+Poly1305 is better than AES/GCM (faster, smaller code).
* -- GCM is better than CCM and CBC. CCM is better than CBC.
* -- CCM is preferable over CCM_8 (with CCM_8, forgeries may succeed
*    with probability 2^(-64)).
* -- AES-128 is preferred over AES-256 (AES-128 is already
*    strong enough, and AES-256 is 40% more expensive).
*/

constexpr uint16_t SUITEs[] = {
    BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
    BR_TLS_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_RSA_WITH_AES_128_CCM,
    BR_TLS_RSA_WITH_AES_256_CCM,
    BR_TLS_RSA_WITH_AES_128_CCM_8,
    BR_TLS_RSA_WITH_AES_256_CCM_8,
    BR_TLS_RSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_RSA_WITH_AES_256_CBC_SHA256,
    BR_TLS_RSA_WITH_AES_128_CBC_SHA,
    BR_TLS_RSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_RSA_WITH_3DES_EDE_CBC_SHA
};

constexpr size_t SUITEs_NUM { sizeof(SUITEs) / sizeof(SUITEs[0]) };

/*
	 * All hash functions are activated.
	 * Note: the X.509 validation engine will nonetheless refuse to
	 * validate signatures that use MD5 as hash function.
	 */
const br_hash_class* HASHes[] = {
    &br_md5_vtable,
    &br_sha1_vtable,
    &br_sha224_vtable,
    &br_sha256_vtable,
    &br_sha384_vtable,
    &br_sha512_vtable
};

constexpr size_t HASHes_NUM { sizeof(HASHes) / sizeof(HASHes[0]) };
