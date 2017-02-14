/**
 * @file tls.h
 * @brief TLS (Transport Layer Security)
 *
 * @section License
 *
 * Copyright (C) 2010-2017 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSSL Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 1.7.6
 **/

#ifndef _TLS_H
#define _TLS_H

//Dependencies
#include "os_port.h"
#include "crypto.h"
#include "tls_config.h"
#include "hmac.h"
#include "rsa.h"
#include "dsa.h"
#include "ecdsa.h"
#include "dh.h"
#include "ecdh.h"
#include "cipher_mode_gcm.h"

//TLS version numbers
#define SSL_VERSION_3_0 0x0300
#define TLS_VERSION_1_0 0x0301
#define TLS_VERSION_1_1 0x0302
#define TLS_VERSION_1_2 0x0303

//Enable SSL/TLS support
#ifndef TLS_SUPPORT
   #define TLS_SUPPORT ENABLED
#elif (TLS_SUPPORT != ENABLED && TLS_SUPPORT != DISABLED)
   #error TLS_SUPPORT parameter is not valid
#endif

//Client mode of operation
#ifndef TLS_CLIENT_SUPPORT
   #define TLS_CLIENT_SUPPORT ENABLED
#elif (TLS_CLIENT_SUPPORT != ENABLED && TLS_CLIENT_SUPPORT != DISABLED)
   #error TLS_CLIENT_SUPPORT parameter is not valid
#endif

//Server mode of operation
#ifndef TLS_SERVER_SUPPORT
   #define TLS_SERVER_SUPPORT ENABLED
#elif (TLS_SERVER_SUPPORT != ENABLED && TLS_SERVER_SUPPORT != DISABLED)
   #error TLS_SERVER_SUPPORT parameter is not valid
#endif

//Minimum version that can be negotiated
#ifndef TLS_MIN_VERSION
   #define TLS_MIN_VERSION TLS_VERSION_1_0
#elif (TLS_MIN_VERSION < SSL_VERSION_3_0)
   #error TLS_MIN_VERSION parameter is not valid
#endif

//Maximum version that can be negotiated
#ifndef TLS_MAX_VERSION
   #define TLS_MAX_VERSION TLS_VERSION_1_2
#elif (TLS_MAX_VERSION > TLS_VERSION_1_2 || TLS_MAX_VERSION < TLS_MIN_VERSION)
   #error TLS_MAX_VERSION parameter is not valid
#endif

//Session resumption mechanism
#ifndef TLS_SESSION_RESUME_SUPPORT
   #define TLS_SESSION_RESUME_SUPPORT ENABLED
#elif (TLS_SESSION_RESUME_SUPPORT != ENABLED && TLS_SESSION_RESUME_SUPPORT != DISABLED)
   #error TLS_SESSION_RESUME_SUPPORT parameter is not valid
#endif

//Lifetime of session cache entries
#ifndef TLS_SESSION_CACHE_LIFETIME
   #define TLS_SESSION_CACHE_LIFETIME 3600000
#elif (TLS_SESSION_CACHE_LIFETIME < 1000)
   #error TLS_SESSION_CACHE_LIFETIME parameter is not valid
#endif

//ECC callback functions
#ifndef TLS_ECC_CALLBACK_SUPPORT
   #define TLS_ECC_CALLBACK_SUPPORT DISABLED
#elif (TLS_ECC_CALLBACK_SUPPORT != ENABLED && TLS_ECC_CALLBACK_SUPPORT != DISABLED)
   #error TLS_ECC_CALLBACK_SUPPORT parameter is not valid
#endif

//SNI (Server Name Indication) extension
#ifndef TLS_SNI_SUPPORT
   #define TLS_SNI_SUPPORT ENABLED
#elif (TLS_SNI_SUPPORT != ENABLED && TLS_SNI_SUPPORT != DISABLED)
   #error TLS_SNI_SUPPORT parameter is not valid
#endif

//ALPN (Application-Layer Protocol Negotiation) extension
#ifndef TLS_ALPN_SUPPORT
   #define TLS_ALPN_SUPPORT DISABLED
#elif (TLS_ALPN_SUPPORT != ENABLED && TLS_ALPN_SUPPORT != DISABLED)
   #error TLS_ALPN_SUPPORT parameter is not valid
#endif

//Maximum number of certificates the end entity can load
#ifndef TLS_MAX_CERTIFICATES
   #define TLS_MAX_CERTIFICATES 3
#elif (TLS_MAX_CERTIFICATES < 1)
   #error TLS_MAX_CERTIFICATES parameter is not valid
#endif

//RSA key exchange support
#ifndef TLS_RSA_SUPPORT
   #define TLS_RSA_SUPPORT ENABLED
#elif (TLS_RSA_SUPPORT != ENABLED && TLS_RSA_SUPPORT != DISABLED)
   #error TLS_RSA_SUPPORT parameter is not valid
#endif

//DHE_RSA key exchange support
#ifndef TLS_DHE_RSA_SUPPORT
   #define TLS_DHE_RSA_SUPPORT ENABLED
#elif (TLS_DHE_RSA_SUPPORT != ENABLED && TLS_DHE_RSA_SUPPORT != DISABLED)
   #error TLS_DHE_RSA_SUPPORT parameter is not valid
#endif

//DHE_DSS key exchange support
#ifndef TLS_DHE_DSS_SUPPORT
   #define TLS_DHE_DSS_SUPPORT DISABLED
#elif (TLS_DHE_DSS_SUPPORT != ENABLED && TLS_DHE_DSS_SUPPORT != DISABLED)
   #error TLS_DHE_DSS_SUPPORT parameter is not valid
#endif

//DH_anon key exchange support
#ifndef TLS_DH_ANON_SUPPORT
   #define TLS_DH_ANON_SUPPORT DISABLED
#elif (TLS_DH_ANON_SUPPORT != ENABLED && TLS_DH_ANON_SUPPORT != DISABLED)
   #error TLS_DH_ANON_SUPPORT parameter is not valid
#endif

//ECDHE_RSA key exchange support
#ifndef TLS_ECDHE_RSA_SUPPORT
   #define TLS_ECDHE_RSA_SUPPORT ENABLED
#elif (TLS_ECDHE_RSA_SUPPORT != ENABLED && TLS_ECDHE_RSA_SUPPORT != DISABLED)
   #error TLS_ECDHE_RSA_SUPPORT parameter is not valid
#endif

//ECDHE_ECDSA key exchange support
#ifndef TLS_ECDHE_ECDSA_SUPPORT
   #define TLS_ECDHE_ECDSA_SUPPORT ENABLED
#elif (TLS_ECDHE_ECDSA_SUPPORT != ENABLED && TLS_ECDHE_ECDSA_SUPPORT != DISABLED)
   #error TLS_ECDHE_ECDSA_SUPPORT parameter is not valid
#endif

//ECDH_anon key exchange support
#ifndef TLS_ECDH_ANON_SUPPORT
   #define TLS_ECDH_ANON_SUPPORT DISABLED
#elif (TLS_ECDH_ANON_SUPPORT != ENABLED && TLS_ECDH_ANON_SUPPORT != DISABLED)
   #error TLS_ECDH_ANON_SUPPORT parameter is not valid
#endif

//PSK key exchange support
#ifndef TLS_PSK_SUPPORT
   #define TLS_PSK_SUPPORT DISABLED
#elif (TLS_PSK_SUPPORT != ENABLED && TLS_PSK_SUPPORT != DISABLED)
   #error TLS_PSK_SUPPORT parameter is not valid
#endif

//RSA_PSK key exchange support
#ifndef TLS_RSA_PSK_SUPPORT
   #define TLS_RSA_PSK_SUPPORT DISABLED
#elif (TLS_RSA_PSK_SUPPORT != ENABLED && TLS_RSA_PSK_SUPPORT != DISABLED)
   #error TLS_RSA_PSK_SUPPORT parameter is not valid
#endif

//DHE_PSK key exchange support
#ifndef TLS_DHE_PSK_SUPPORT
   #define TLS_DHE_PSK_SUPPORT DISABLED
#elif (TLS_DHE_PSK_SUPPORT != ENABLED && TLS_DHE_PSK_SUPPORT != DISABLED)
   #error TLS_DHE_PSK_SUPPORT parameter is not valid
#endif

//ECDHE_PSK key exchange support
#ifndef TLS_ECDHE_PSK_SUPPORT
   #define TLS_ECDHE_PSK_SUPPORT DISABLED
#elif (TLS_ECDHE_PSK_SUPPORT != ENABLED && TLS_ECDHE_PSK_SUPPORT != DISABLED)
   #error TLS_ECDHE_PSK_SUPPORT parameter is not valid
#endif

//RSA signature capability
#ifndef TLS_RSA_SIGN_SUPPORT
   #define TLS_RSA_SIGN_SUPPORT ENABLED
#elif (TLS_RSA_SIGN_SUPPORT != ENABLED && TLS_RSA_SIGN_SUPPORT != DISABLED)
   #error TLS_RSA_SIGN_SUPPORT parameter is not valid
#endif

//DSA signature capability
#ifndef TLS_DSA_SIGN_SUPPORT
   #define TLS_DSA_SIGN_SUPPORT DISABLED
#elif (TLS_DSA_SIGN_SUPPORT != ENABLED && TLS_DSA_SIGN_SUPPORT != DISABLED)
   #error TLS_DSA_SIGN_SUPPORT parameter is not valid
#endif

//ECDSA signature capability
#ifndef TLS_ECDSA_SIGN_SUPPORT
   #define TLS_ECDSA_SIGN_SUPPORT ENABLED
#elif (TLS_ECDSA_SIGN_SUPPORT != ENABLED && TLS_ECDSA_SIGN_SUPPORT != DISABLED)
   #error TLS_ECDSA_SIGN_SUPPORT parameter is not valid
#endif

//Stream cipher support
#ifndef TLS_STREAM_CIPHER_SUPPORT
   #define TLS_STREAM_CIPHER_SUPPORT ENABLED
#elif (TLS_STREAM_CIPHER_SUPPORT != ENABLED && TLS_STREAM_CIPHER_SUPPORT != DISABLED)
   #error TLS_STREAM_CIPHER_SUPPORT parameter is not valid
#endif

//CBC block cipher support
#ifndef TLS_CBC_CIPHER_SUPPORT
   #define TLS_CBC_CIPHER_SUPPORT ENABLED
#elif (TLS_CBC_CIPHER_SUPPORT != ENABLED && TLS_CBC_CIPHER_SUPPORT != DISABLED)
   #error TLS_CBC_CIPHER_SUPPORT parameter is not valid
#endif

//CCM AEAD support
#ifndef TLS_CCM_CIPHER_SUPPORT
   #define TLS_CCM_CIPHER_SUPPORT DISABLED
#elif (TLS_CCM_CIPHER_SUPPORT != ENABLED && TLS_CCM_CIPHER_SUPPORT != DISABLED)
   #error TLS_CCM_CIPHER_SUPPORT parameter is not valid
#endif

//CCM_8 AEAD support
#ifndef TLS_CCM_8_CIPHER_SUPPORT
   #define TLS_CCM_8_CIPHER_SUPPORT DISABLED
#elif (TLS_CCM_8_CIPHER_SUPPORT != ENABLED && TLS_CCM_8_CIPHER_SUPPORT != DISABLED)
   #error TLS_CCM_8_CIPHER_SUPPORT parameter is not valid
#endif

//GCM AEAD support
#ifndef TLS_GCM_CIPHER_SUPPORT
   #define TLS_GCM_CIPHER_SUPPORT ENABLED
#elif (TLS_GCM_CIPHER_SUPPORT != ENABLED && TLS_GCM_CIPHER_SUPPORT != DISABLED)
   #error TLS_GCM_CIPHER_SUPPORT parameter is not valid
#endif

//ChaCha20Poly1305 AEAD support
#ifndef TLS_CHACHA20_POLY1305_SUPPORT
   #define TLS_CHACHA20_POLY1305_SUPPORT DISABLED
#elif (TLS_CHACHA20_POLY1305_SUPPORT != ENABLED && TLS_CHACHA20_POLY1305_SUPPORT != DISABLED)
   #error TLS_CHACHA20_POLY1305_SUPPORT parameter is not valid
#endif

//RC4 cipher support
#ifndef TLS_RC4_SUPPORT
   #define TLS_RC4_SUPPORT DISABLED
#elif (TLS_RC4_SUPPORT != ENABLED && TLS_RC4_SUPPORT != DISABLED)
   #error TLS_RC4_SUPPORT parameter is not valid
#endif

//IDEA cipher support
#ifndef TLS_IDEA_SUPPORT
   #define TLS_IDEA_SUPPORT DISABLED
#elif (TLS_IDEA_SUPPORT != ENABLED && TLS_IDEA_SUPPORT != DISABLED)
   #error TLS_IDEA_SUPPORT parameter is not valid
#endif

//DES cipher support
#ifndef TLS_DES_SUPPORT
   #define TLS_DES_SUPPORT DISABLED
#elif (TLS_DES_SUPPORT != ENABLED && TLS_DES_SUPPORT != DISABLED)
   #error TLS_DES_SUPPORT parameter is not valid
#endif

//Triple DES cipher support
#ifndef TLS_3DES_SUPPORT
   #define TLS_3DES_SUPPORT ENABLED
#elif (TLS_3DES_SUPPORT != ENABLED && TLS_3DES_SUPPORT != DISABLED)
   #error TLS_3DES_SUPPORT parameter is not valid
#endif

//AES cipher support
#ifndef TLS_AES_SUPPORT
   #define TLS_AES_SUPPORT ENABLED
#elif (TLS_AES_SUPPORT != ENABLED && TLS_AES_SUPPORT != DISABLED)
   #error TLS_AES_SUPPORT parameter is not valid
#endif

//Camellia cipher support
#ifndef TLS_CAMELLIA_SUPPORT
   #define TLS_CAMELLIA_SUPPORT ENABLED
#elif (TLS_CAMELLIA_SUPPORT != ENABLED && TLS_CAMELLIA_SUPPORT != DISABLED)
   #error TLS_CAMELLIA_SUPPORT parameter is not valid
#endif

//SEED cipher support
#ifndef TLS_SEED_SUPPORT
   #define TLS_SEED_SUPPORT DISABLED
#elif (TLS_SEED_SUPPORT != ENABLED && TLS_SEED_SUPPORT != DISABLED)
   #error TLS_SEED_SUPPORT parameter is not valid
#endif

//ARIA cipher support
#ifndef TLS_ARIA_SUPPORT
   #define TLS_ARIA_SUPPORT DISABLED
#elif (TLS_ARIA_SUPPORT != ENABLED && TLS_ARIA_SUPPORT != DISABLED)
   #error TLS_ARIA_SUPPORT parameter is not valid
#endif

//MD5 hash support
#ifndef TLS_MD5_SUPPORT
   #define TLS_MD5_SUPPORT DISABLED
#elif (TLS_MD5_SUPPORT != ENABLED && TLS_MD5_SUPPORT != DISABLED)
   #error TLS_MD5_SUPPORT parameter is not valid
#endif

//SHA-1 hash support
#ifndef TLS_SHA1_SUPPORT
   #define TLS_SHA1_SUPPORT ENABLED
#elif (TLS_SHA1_SUPPORT != ENABLED && TLS_SHA1_SUPPORT != DISABLED)
   #error TLS_SHA1_SUPPORT parameter is not valid
#endif

//SHA-224 hash support
#ifndef TLS_SHA224_SUPPORT
   #define TLS_SHA224_SUPPORT ENABLED
#elif (TLS_SHA224_SUPPORT != ENABLED && TLS_SHA224_SUPPORT != DISABLED)
   #error TLS_SHA224_SUPPORT parameter is not valid
#endif

//SHA-256 hash support
#ifndef TLS_SHA256_SUPPORT
   #define TLS_SHA256_SUPPORT ENABLED
#elif (TLS_SHA256_SUPPORT != ENABLED && TLS_SHA256_SUPPORT != DISABLED)
   #error TLS_SHA256_SUPPORT parameter is not valid
#endif

//SHA-384 hash support
#ifndef TLS_SHA384_SUPPORT
   #define TLS_SHA384_SUPPORT ENABLED
#elif (TLS_SHA384_SUPPORT != ENABLED && TLS_SHA384_SUPPORT != DISABLED)
   #error TLS_SHA384_SUPPORT parameter is not valid
#endif

//SHA-512 hash support
#ifndef TLS_SHA512_SUPPORT
   #define TLS_SHA512_SUPPORT DISABLED
#elif (TLS_SHA512_SUPPORT != ENABLED && TLS_SHA512_SUPPORT != DISABLED)
   #error TLS_SHA512_SUPPORT parameter is not valid
#endif

//secp160k1 elliptic curve support
#ifndef TLS_SECP160K1_SUPPORT
   #define TLS_SECP160K1_SUPPORT DISABLED
#elif (TLS_SECP160K1_SUPPORT != ENABLED && TLS_SECP160K1_SUPPORT != DISABLED)
   #error TLS_SECP160K1_SUPPORT parameter is not valid
#endif

//secp160r1 elliptic curve support
#ifndef TLS_SECP160R1_SUPPORT
   #define TLS_SECP160R1_SUPPORT DISABLED
#elif (TLS_SECP160R1_SUPPORT != ENABLED && TLS_SECP160R1_SUPPORT != DISABLED)
   #error TLS_SECP160R1_SUPPORT parameter is not valid
#endif

//secp160r2 elliptic curve support
#ifndef TLS_SECP160R2_SUPPORT
   #define TLS_SECP160R2_SUPPORT DISABLED
#elif (TLS_SECP160R2_SUPPORT != ENABLED && TLS_SECP160R2_SUPPORT != DISABLED)
   #error TLS_SECP160R2_SUPPORT parameter is not valid
#endif

//secp192k1 elliptic curve support
#ifndef TLS_SECP192K1_SUPPORT
   #define TLS_SECP192K1_SUPPORT DISABLED
#elif (TLS_SECP192K1_SUPPORT != ENABLED && TLS_SECP192K1_SUPPORT != DISABLED)
   #error TLS_SECP192K1_SUPPORT parameter is not valid
#endif

//secp192r1 elliptic curve support (NIST P-192)
#ifndef TLS_SECP192R1_SUPPORT
   #define TLS_SECP192R1_SUPPORT ENABLED
#elif (TLS_SECP192R1_SUPPORT != ENABLED && TLS_SECP192R1_SUPPORT != DISABLED)
   #error TLS_SECP192R1_SUPPORT parameter is not valid
#endif

//secp224k1 elliptic curve support
#ifndef TLS_SECP224K1_SUPPORT
   #define TLS_SECP224K1_SUPPORT DISABLED
#elif (TLS_SECP224K1_SUPPORT != ENABLED && TLS_SECP224K1_SUPPORT != DISABLED)
   #error TLS_SECP224K1_SUPPORT parameter is not valid
#endif

//secp224r1 elliptic curve support (NIST P-224)
#ifndef TLS_SECP224R1_SUPPORT
   #define TLS_SECP224R1_SUPPORT ENABLED
#elif (TLS_SECP224R1_SUPPORT != ENABLED && TLS_SECP224R1_SUPPORT != DISABLED)
   #error TLS_SECP224R1_SUPPORT parameter is not valid
#endif

//secp256k1 elliptic curve support
#ifndef TLS_SECP256K1_SUPPORT
   #define TLS_SECP256K1_SUPPORT DISABLED
#elif (TLS_SECP256K1_SUPPORT != ENABLED && TLS_SECP256K1_SUPPORT != DISABLED)
   #error TLS_SECP256K1_SUPPORT parameter is not valid
#endif

//secp256r1 elliptic curve support (NIST P-256)
#ifndef TLS_SECP256R1_SUPPORT
   #define TLS_SECP256R1_SUPPORT ENABLED
#elif (TLS_SECP256R1_SUPPORT != ENABLED && TLS_SECP256R1_SUPPORT != DISABLED)
   #error TLS_SECP256R1_SUPPORT parameter is not valid
#endif

//secp384r1 elliptic curve support (NIST P-384) 
#ifndef TLS_SECP384R1_SUPPORT
   #define TLS_SECP384R1_SUPPORT ENABLED
#elif (TLS_SECP384R1_SUPPORT != ENABLED && TLS_SECP384R1_SUPPORT != DISABLED)
   #error TLS_SECP384R1_SUPPORT parameter is not valid
#endif

//secp521r1 elliptic curve support (NIST P-521)
#ifndef TLS_SECP521R1_SUPPORT
   #define TLS_SECP521R1_SUPPORT ENABLED
#elif (TLS_SECP521R1_SUPPORT != ENABLED && TLS_SECP521R1_SUPPORT != DISABLED)
   #error TLS_SECP521R1_SUPPORT parameter is not valid
#endif

//brainpoolP256r1 elliptic curve support
#ifndef TLS_BRAINPOOLP256R1_SUPPORT
   #define TLS_BRAINPOOLP256R1_SUPPORT DISABLED
#elif (TLS_BRAINPOOLP256R1_SUPPORT != ENABLED && TLS_BRAINPOOLP256R1_SUPPORT != DISABLED)
   #error TLS_BRAINPOOLP256R1_SUPPORT parameter is not valid
#endif

//brainpoolP384r1 elliptic curve support
#ifndef TLS_BRAINPOOLP384R1_SUPPORT
   #define TLS_BRAINPOOLP384R1_SUPPORT DISABLED
#elif (TLS_BRAINPOOLP384R1_SUPPORT != ENABLED && TLS_BRAINPOOLP384R1_SUPPORT != DISABLED)
   #error TLS_BRAINPOOLP384R1_SUPPORT parameter is not valid
#endif

//brainpoolP512r1 elliptic curve support
#ifndef TLS_BRAINPOOLP512R1_SUPPORT
   #define TLS_BRAINPOOLP512R1_SUPPORT DISABLED
#elif (TLS_BRAINPOOLP512R1_SUPPORT != ENABLED && TLS_BRAINPOOLP512R1_SUPPORT != DISABLED)
   #error TLS_BRAINPOOLP512R1_SUPPORT parameter is not valid
#endif

//Minimum acceptable size for Diffie-Hellman prime modulus
#ifndef TLS_MIN_DH_MODULUS_SIZE
   #define TLS_MIN_DH_MODULUS_SIZE 1024
#elif (TLS_MIN_DH_MODULUS_SIZE < 512)
   #error TLS_MIN_DH_MODULUS_SIZE parameter is not valid
#endif

//Maximum acceptable size for Diffie-Hellman prime modulus
#ifndef TLS_MAX_DH_MODULUS_SIZE
   #define TLS_MAX_DH_MODULUS_SIZE 4096
#elif (TLS_MAX_DH_MODULUS_SIZE < TLS_MIN_DH_MODULUS_SIZE)
   #error TLS_MAX_DH_MODULUS_SIZE parameter is not valid
#endif

//Minimum acceptable size for RSA modulus
#ifndef TLS_MIN_RSA_MODULUS_SIZE
   #define TLS_MIN_RSA_MODULUS_SIZE 1024
#elif (TLS_MIN_RSA_MODULUS_SIZE < 512)
   #error TLS_MIN_RSA_MODULUS_SIZE parameter is not valid
#endif

//Maximum acceptable size for RSA modulus
#ifndef TLS_MAX_RSA_MODULUS_SIZE
   #define TLS_MAX_RSA_MODULUS_SIZE 4096
#elif (TLS_MAX_RSA_MODULUS_SIZE < TLS_MIN_RSA_MODULUS_SIZE)
   #error TLS_MAX_RSA_MODULUS_SIZE parameter is not valid
#endif

//Minimum acceptable size for DSA prime modulus
#ifndef TLS_MIN_DSA_MODULUS_SIZE
   #define TLS_MIN_DSA_MODULUS_SIZE 1024
#elif (TLS_MIN_DSA_MODULUS_SIZE < 512)
   #error TLS_MIN_DSA_MODULUS_SIZE parameter is not valid
#endif

//Maximum acceptable size for DSA prime modulus
#ifndef TLS_MAX_DSA_MODULUS_SIZE
   #define TLS_MAX_DSA_MODULUS_SIZE 4096
#elif (TLS_MAX_DSA_MODULUS_SIZE < TLS_MIN_DSA_MODULUS_SIZE)
   #error TLS_MAX_DSA_MODULUS_SIZE parameter is not valid
#endif

//Maximum size for premaster secret
#ifndef TLS_MAX_PREMASTER_SECRET_SIZE
   #define TLS_MAX_PREMASTER_SECRET_SIZE 256
#elif (TLS_MAX_PREMASTER_SECRET_SIZE < 48)
   #error TLS_MAX_PREMASTER_SECRET_SIZE parameter is not valid
#endif

//Memory allocation
#ifndef tlsAllocMem
   #define tlsAllocMem(size) osAllocMem(size)
#endif

//Memory deallocation
#ifndef tlsFreeMem
   #define tlsFreeMem(p) osFreeMem(p)
#endif

//Bind TLS to a particular socket
#define tlsSetSocket(context, socket) tlsSetIoCallbacks(context, (TlsIoHandle) socket, \
   (TlsIoSendCallback) socketSend, (TlsIoReceiveCallback) socketReceive)

//Maximum plaintext record length
#define TLS_MAX_RECORD_LENGTH 16384
//Data overhead caused by record encryption
#define TLS_MAX_RECORD_OVERHEAD 512

//Forward declaration of TlsContext structure
struct _TlsContext;
#define TlsContext struct _TlsContext


/**
 * @brief TLS connection end
 **/

typedef enum
{
   TLS_CONNECTION_END_CLIENT = 0,
   TLS_CONNECTION_END_SERVER = 1
} TlsConnectionEnd;


/**
 * @brief Client authentication mode
 **/

typedef enum
{
   TLS_CLIENT_AUTH_NONE     = 0,
   TLS_CLIENT_AUTH_OPTIONAL = 1,
   TLS_CLIENT_AUTH_REQUIRED = 2
} TlsClientAuthMode;


/**
 * @brief Flags used by read and write functions
 **/

typedef enum
{
   TLS_FLAG_WAIT_ALL   = 0x0800,
   TLS_FLAG_BREAK_CHAR = 0x1000,
   TLS_FLAG_BREAK_CRLF = 0x100A,
   TLS_FLAG_WAIT_ACK   = 0x2000,
   TLS_FLAG_NO_DELAY   = 0x4000,
   TLS_FLAG_DELAY      = 0x8000
} TlsFlags;


//The TLS_FLAG_BREAK macro causes the read function to stop reading
//data whenever the specified break character is encountered
#define TLS_FLAG_BREAK(c) (TLS_FLAG_BREAK_CHAR | LSB(c))


/**
 * @brief Content type
 **/

typedef enum
{
   TLS_TYPE_NONE               = 0,
   TLS_TYPE_CHANGE_CIPHER_SPEC = 20,
   TLS_TYPE_ALERT              = 21,
   TLS_TYPE_HANDSHAKE          = 22,
   TLS_TYPE_APPLICATION_DATA   = 23,
   TLS_TYPE_HEARTBEAT          = 24
} TlsContentType;


/**
 * @brief Handshake message type
 **/

typedef enum
{
   TLS_TYPE_HELLO_REQUEST        = 0,
   TLS_TYPE_CLIENT_HELLO         = 1,
   TLS_TYPE_SERVER_HELLO         = 2,
   TLS_TYPE_HELLO_VERIFY_REQUEST = 3,
   TLS_TYPE_NEW_SESSION_TICKET   = 4,
   TLS_TYPE_CERTIFICATE          = 11,
   TLS_TYPE_SERVER_KEY_EXCHANGE  = 12,
   TLS_TYPE_CERTIFICATE_REQUEST  = 13,
   TLS_TYPE_SERVER_HELLO_DONE    = 14,
   TLS_TYPE_CERTIFICATE_VERIFY   = 15,
   TLS_TYPE_CLIENT_KEY_EXCHANGE  = 16,
   TLS_TYPE_FINISHED             = 20,
   TLS_TYPE_CERTIFICATE_URL      = 21,
   TLS_TYPE_CERTIFICATE_STATUS   = 22,
   TLS_TYPE_SUPPLEMENTAL_DATA    = 23
} TlsMessageType;


/**
 * @brief Alert level
 **/

typedef enum
{
   TLS_ALERT_LEVEL_WARNING = 1,
   TLS_ALERT_LEVEL_FATAL   = 2,
} TlsAlertLevel;


/**
 * @brief Alert description
 **/

typedef enum
{
   TLS_ALERT_CLOSE_NOTIFY                    = 0,
   TLS_ALERT_UNEXPECTED_MESSAGE              = 10,
   TLS_ALERT_BAD_RECORD_MAC                  = 20,
   TLS_ALERT_DECRYPTION_FAILED               = 21,
   TLS_ALERT_RECORD_OVERFLOW                 = 22,
   TLS_ALERT_DECOMPRESSION_FAILURE           = 30,
   TLS_ALERT_HANDSHAKE_FAILURE               = 40,
   TLS_ALERT_NO_CERTIFICATE                  = 41,
   TLS_ALERT_BAD_CERTIFICATE                 = 42,
   TLS_ALERT_UNSUPPORTED_CERTIFICATE         = 43,
   TLS_ALERT_CERTIFICATE_REVOKED             = 44,
   TLS_ALERT_CERTIFICATE_EXPIRED             = 45,
   TLS_ALERT_CERTIFICATE_UNKNOWN             = 46,
   TLS_ALERT_ILLEGAL_PARAMETER               = 47,
   TLS_ALERT_UNKNOWN_CA                      = 48,
   TLS_ALERT_ACCESS_DENIED                   = 49,
   TLS_ALERT_DECODE_ERROR                    = 50,
   TLS_ALERT_DECRYPT_ERROR                   = 51,
   TLS_ALERT_EXPORT_RESTRICTION              = 60,
   TLS_ALERT_PROTOCOL_VERSION                = 70,
   TLS_ALERT_INSUFFICIENT_SECURITY           = 71,
   TLS_ALERT_INTERNAL_ERROR                  = 80,
   TLS_ALERT_INAPPROPRIATE_FALLBACK          = 86,
   TLS_ALERT_USER_CANCELED                   = 90,
   TLS_ALERT_NO_RENEGOTIATION                = 100,
   TLS_ALERT_UNSUPPORTED_EXTENSION           = 110,
   TLS_ALERT_CERTIFICATE_UNOBTAINABLE        = 111,
   TLS_ALERT_UNRECOGNIZED_NAME               = 112,
   TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE = 113,
   TLS_ALERT_BAD_CERTIFICATE_HASH_VALUE      = 114,
   TLS_ALERT_UNKNOWN_PSK_IDENTITY            = 115
} TlsAlertDescription;


/**
 * @brief Compression methods
 **/

typedef enum
{
   TLS_COMPRESSION_METHOD_NULL    = 0,
   TLS_COMPRESSION_METHOD_DEFLATE = 1
} TlsCompressionMethodList;


/**
 * @brief Key exchange methods
 **/

typedef enum
{
   TLS_KEY_EXCH_NONE        = 0,
   TLS_KEY_EXCH_RSA         = 1,
   TLS_KEY_EXCH_DH_RSA      = 2,
   TLS_KEY_EXCH_DHE_RSA     = 3,
   TLS_KEY_EXCH_DH_DSS      = 4,
   TLS_KEY_EXCH_DHE_DSS     = 5,
   TLS_KEY_EXCH_DH_ANON     = 6,
   TLS_KEY_EXCH_ECDH_RSA    = 7,
   TLS_KEY_EXCH_ECDHE_RSA   = 8,
   TLS_KEY_EXCH_ECDH_ECDSA  = 9,
   TLS_KEY_EXCH_ECDHE_ECDSA = 10,
   TLS_KEY_EXCH_ECDH_ANON   = 11,
   TLS_KEY_EXCH_PSK         = 12,
   TLS_KEY_EXCH_RSA_PSK     = 13,
   TLS_KEY_EXCH_DHE_PSK     = 14,
   TLS_KEY_EXCH_ECDHE_PSK   = 15,
   TLS_KEY_EXCH_SRP_SHA     = 16,
   TLS_KEY_EXCH_SRP_SHA_RSA = 17,
   TLS_KEY_EXCH_SRP_SHA_DSS = 18
} TlsKeyExchMethod;


/**
 * @brief Certificate types
 **/

typedef enum
{
   TLS_CERT_NONE             = 0,
   TLS_CERT_RSA_SIGN         = 1,
   TLS_CERT_DSS_SIGN         = 2,
   TLS_CERT_RSA_FIXED_DH     = 3,
   TLS_CERT_DSS_FIXED_DH     = 4,
   TLS_CERT_RSA_EPHEMERAL_DH = 5,
   TLS_CERT_DSS_EPHEMERAL_DH = 6,
   TLS_CERT_FORTEZZA_DMS     = 20,
   TLS_CERT_ECDSA_SIGN       = 64,
   TLS_CERT_RSA_FIXED_ECDH   = 65,
   TLS_CERT_ECDSA_FIXED_ECDH = 66
} TlsCertificateType;


/**
 * @brief Hash algorithms
 **/

typedef enum
{
   TLS_HASH_ALGO_NONE   = 0,
   TLS_HASH_ALGO_MD5    = 1,
   TLS_HASH_ALGO_SHA1   = 2,
   TLS_HASH_ALGO_SHA224 = 3,
   TLS_HASH_ALGO_SHA256 = 4,
   TLS_HASH_ALGO_SHA384 = 5,
   TLS_HASH_ALGO_SHA512 = 6
} TlsHashAlgo;


/**
 * @brief Signature algorithms
 **/

typedef enum
{
   TLS_SIGN_ALGO_ANONYMOUS = 0,
   TLS_SIGN_ALGO_RSA       = 1,
   TLS_SIGN_ALGO_DSA       = 2,
   TLS_SIGN_ALGO_ECDSA     = 3
} TlsSignatureAlgo;


/**
 * @brief TLS extension types
 **/

typedef enum
{
   TLS_EXT_SERVER_NAME            = 0,
   TLS_EXT_MAX_FRAGMENT_LENGTH    = 1,
   TLS_EXT_CLIENT_CERTIFICATE_URL = 2,
   TLS_EXT_TRUSTED_CA_KEYS        = 3,
   TLS_EXT_TRUNCATED_HMAC         = 4,
   TLS_EXT_STATUS_REQUEST         = 5,
   TLS_EXT_USER_MAPPING           = 6,
   TLS_EXT_CLIENT_AUTHZ           = 7,
   TLS_EXT_SERVER_AUTHZ           = 8,
   TLS_EXT_CERT_TYPE              = 9,
   TLS_EXT_ELLIPTIC_CURVES        = 10,
   TLS_EXT_EC_POINT_FORMATS       = 11,
   TLS_EXT_SRP                    = 12,
   TLS_EXT_SIGNATURE_ALGORITHMS   = 13,
   TLS_EXT_USE_SRTP               = 14,
   TLS_EXT_HEARTBEAT              = 15,
   TLS_EXT_ALPN                   = 16,
   TLS_EXT_SESSION_TICKET         = 35,
   TLS_EXT_RENEGOTIATION_INFO     = 65281
} TlsExtensionType;


/**
 * @brief Name type
 **/

typedef enum
{
   TLS_NAME_TYPE_HOSTNAME = 0
} TlsNameType;


/**
 * @brief EC named curves
 **/

typedef enum
{
   TLS_EC_CURVE_NONE                     = 0,
   TLS_EC_CURVE_SECT163K1                = 1,     //RFC 4492
   TLS_EC_CURVE_SECT163R1                = 2,     //RFC 4492
   TLS_EC_CURVE_SECT163R2                = 3,     //RFC 4492
   TLS_EC_CURVE_SECT193R1                = 4,     //RFC 4492
   TLS_EC_CURVE_SECT193R2                = 5,     //RFC 4492
   TLS_EC_CURVE_SECT233K1                = 6,     //RFC 4492
   TLS_EC_CURVE_SECT233R1                = 7,     //RFC 4492
   TLS_EC_CURVE_SECT239K1                = 8,     //RFC 4492
   TLS_EC_CURVE_SECT283K1                = 9,     //RFC 4492
   TLS_EC_CURVE_SECT283R1                = 10,    //RFC 4492
   TLS_EC_CURVE_SECT409K1                = 11,    //RFC 4492
   TLS_EC_CURVE_SECT409R1                = 12,    //RFC 4492
   TLS_EC_CURVE_SECT571K1                = 13,    //RFC 4492
   TLS_EC_CURVE_SECT571R1                = 14,    //RFC 4492
   TLS_EC_CURVE_SECP160K1                = 15,    //RFC 4492
   TLS_EC_CURVE_SECP160R1                = 16,    //RFC 4492
   TLS_EC_CURVE_SECP160R2                = 17,    //RFC 4492
   TLS_EC_CURVE_SECP192K1                = 18,    //RFC 4492
   TLS_EC_CURVE_SECP192R1                = 19,    //RFC 4492
   TLS_EC_CURVE_SECP224K1                = 20,    //RFC 4492
   TLS_EC_CURVE_SECP224R1                = 21,    //RFC 4492
   TLS_EC_CURVE_SECP256K1                = 22,    //RFC 4492
   TLS_EC_CURVE_SECP256R1                = 23,    //RFC 4492
   TLS_EC_CURVE_SECP384R1                = 24,    //RFC 4492
   TLS_EC_CURVE_SECP521R1                = 25,    //RFC 4492
   TLS_EC_CURVE_BRAINPOOLP256R1          = 26,    //RFC 7027
   TLS_EC_CURVE_BRAINPOOLP384R1          = 27,    //RFC 7027
   TLS_EC_CURVE_BRAINPOOLP512R1          = 28,    //RFC 7027
   TLS_EC_CURVE_ECDH_X25519              = 29,    //RFC draft
   TLS_EC_CURVE_ECDH_X448                = 30,    //RFC draft
   TLS_EC_CURVE_FFDHE2048                = 256,   //RFC 7919
   TLS_EC_CURVE_FFDHE3072                = 257,   //RFC 7919
   TLS_EC_CURVE_FFDHE4096                = 258,   //RFC 7919
   TLS_EC_CURVE_FFDHE6144                = 259,   //RFC 7919
   TLS_EC_CURVE_FFDHE8192                = 260,   //RFC 7919
   TLS_EC_CURVE_ARBITRARY_EXPLICIT_PRIME = 65281, //RFC 4492
   TLS_EC_CURVE_ARBITRARY_EXPLICIT_CHAR2 = 65282  //RFC 4492
} TlsEcNamedCurve;


/**
 * @brief EC point formats
 **/

typedef enum
{
   TLS_EC_POINT_FORMAT_UNCOMPRESSED              = 0,
   TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME = 1,
   TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2 = 2
} TlsEcPointFormat;


/**
 * @brief EC curve types
 **/

typedef enum
{
   TLS_EC_CURVE_TYPE_EXPLICIT_PRIME = 1,
   TLS_EC_CURVE_TYPE_EXPLICIT_CHAR2 = 2,
   TLS_EC_CURVE_TYPE_NAMED_CURVE    = 3
} TlsEcCurveType;


/**
 * @brief TLS FSM states
 **/

typedef enum
{
   TLS_STATE_INIT                      = 0,
   TLS_STATE_CLIENT_HELLO              = 1,
   TLS_STATE_SERVER_HELLO              = 2,
   TLS_STATE_SERVER_CERTIFICATE        = 3,
   TLS_STATE_SERVER_KEY_EXCHANGE       = 4,
   TLS_STATE_CERTIFICATE_REQUEST       = 5,
   TLS_STATE_SERVER_HELLO_DONE         = 6,
   TLS_STATE_CLIENT_CERTIFICATE        = 7,
   TLS_STATE_CLIENT_KEY_EXCHANGE       = 8,
   TLS_STATE_CERTIFICATE_VERIFY        = 9,
   TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC = 10,
   TLS_STATE_CLIENT_FINISHED           = 11,
   TLS_STATE_SERVER_CHANGE_CIPHER_SPEC = 12,
   TLS_STATE_SERVER_FINISHED           = 13,
   TLS_STATE_APPLICATION_DATA          = 14,
   TLS_STATE_CLOSING                   = 15,
   TLS_STATE_CLOSED                    = 16
} TlsState;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief Random structure
 **/

typedef __start_packed struct
{
   uint32_t gmtUnixTime;    //0-3
   uint8_t randomBytes[28]; //4-31
} __end_packed TlsRandom;


/**
 * @brief Cipher suite
 **/

typedef uint16_t TlsCipherSuite;


/**
 * @brief Cipher suites
 **/

typedef __start_packed struct
{
   uint16_t length;  //0-1
   uint16_t value[]; //2
} __end_packed TlsCipherSuites;


/**
 * @brief Compression method
 **/

typedef uint8_t TlsCompressionMethod;


/**
 * @brief Compression methods
 **/

typedef __start_packed struct
{
   uint8_t length;  //0
   uint8_t value[]; //1
} __end_packed TlsCompressionMethods;


/**
 * @brief Signature algorithm
 **/

typedef __start_packed struct
{
   uint8_t hash;      //0
   uint8_t signature; //1
} __end_packed TlsSignHashAlgo;


/**
 * @brief List of signature algorithms
 **/

typedef __start_packed struct
{
   uint16_t length;         //0-1
   TlsSignHashAlgo value[]; //2
} __end_packed TlsSignHashAlgos;


/**
 * @brief List of certificate authorities
 **/

typedef __start_packed struct
{
   uint16_t length; //0-1
   uint8_t value[]; //2
} __end_packed TlsCertAuthorities;


/**
 * @brief TLS extension
 **/

typedef __start_packed struct
{
   uint16_t type;   //0-1
   uint16_t length; //2-3
   uint8_t value[]; //4
} __end_packed TlsExtension;


/**
 * @brief List of TLS extensions
 **/

typedef __start_packed struct
{
   uint16_t length; //0-1
   uint8_t value[]; //2
} __end_packed TlsExtensions;


/**
 * @brief Server name
 **/

typedef __start_packed struct
{
   uint8_t type;      //0
   uint16_t length;   //1-2
   char_t hostname[]; //2
} __end_packed TlsServerName;


/**
 * @brief List of server names
 **/

typedef __start_packed struct
{
   uint16_t length; //0-1
   uint8_t value[]; //2
} __end_packed TlsServerNameList;


/**
 * @brief Protocol name
 **/

typedef __start_packed struct
{
   uint8_t length; //0
   char_t value[]; //1
} __end_packed TlsProtocolName;


/**
 * @brief List of protocol names
 **/

typedef __start_packed struct
{
   uint16_t length; //0-1
   uint8_t value[]; //2
} __end_packed TlsProtocolNameList;


/**
 * @brief List of supported elliptic curves
 **/

typedef __start_packed struct
{
   uint16_t length;  //0-1
   uint16_t value[]; //2
} __end_packed TlsEllipticCurveList;


/**
 * @brief List of supported EC point formats
 **/

typedef __start_packed struct
{
   uint8_t length;  //0
   uint8_t value[]; //1
} __end_packed TlsEcPointFormatList;


/**
 * @brief PSK identity
 **/

typedef __start_packed struct
{
   uint16_t length; //0-1
   uint8_t value[]; //2
} __end_packed TlsPskIdentity;


/**
 * @brief PSK identity hint
 **/

typedef __start_packed struct
{
   uint16_t length; //0-1
   uint8_t value[]; //2
} __end_packed TlsPskIdentityHint;


/**
 * @brief Digitally-signed element (SSL 3.0, TLS 1.0 and TLS 1.1)
 **/

typedef __start_packed struct
{
   uint16_t length; //0-1
   uint8_t value[]; //2
} __end_packed TlsDigitalSignature;


/**
 * @brief Digitally-signed element (TLS 1.2)
 **/

typedef __start_packed struct
{
   TlsSignHashAlgo algorithm; //0-1
   uint16_t length;           //2-3
   uint8_t value[];           //4
} __end_packed TlsDigitalSignature2;


/**
 * @brief General format of TLS records
 **/

typedef __start_packed struct
{
   uint8_t type;     //0
   uint16_t version; //1-2
   uint16_t length;  //3-4
   uint8_t data[];   //5
} __end_packed TlsRecord;


/**
 * @brief Handshake message
 **/

typedef __start_packed struct
{
   uint8_t msgType;   //0
   uint8_t length[3]; //1-3
   uint8_t data[];    //4
} __end_packed TlsHandshake;


/**
 * @brief ClientHello message
 **/

typedef __start_packed struct
{
   uint8_t msgType;         //0
   uint8_t length[3];       //1-3
   uint16_t clientVersion;  //4-5
   TlsRandom random;        //6-37
   uint8_t sessionIdLength; //38
   uint8_t sessionId[];     //39
} __end_packed TlsClientHello;


/**
 * @brief ServerHello message
 **/

typedef __start_packed struct
{
   uint8_t msgType;         //0
   uint8_t length[3];       //1-3
   uint16_t serverVersion;  //4-5
   TlsRandom random;        //6-37
   uint8_t sessionIdLength; //38
   uint8_t sessionId[];     //39
} __end_packed TlsServerHello;


/**
 * @brief Certificate message
 **/

typedef __start_packed struct
{
   uint8_t msgType;                  //0
   uint8_t length[3];                //1-3
   uint8_t certificateListLength[3]; //4-6
   uint8_t certificateList[];        //7
} __end_packed TlsCertificate;


/**
 * @brief ServerKeyExchange message
 **/

typedef __start_packed struct
{
   uint8_t msgType;   //0
   uint8_t length[3]; //1-3
   uint8_t data[];    //4
} __end_packed TlsServerKeyExchange;


/**
 * @brief CertificateRequest message
 **/

typedef __start_packed struct
{
   uint8_t msgType;                 //0
   uint8_t length[3];               //1-3
   uint8_t certificateTypesLength;  //4
   uint8_t certificateTypes[];      //5
} __end_packed TlsCertificateRequest;


/**
 * @brief ServerHelloDone message
 **/

typedef __start_packed struct
{
   uint8_t msgType;   //0
   uint8_t length[3]; //1-3
} __end_packed TlsServerHelloDone;


/**
 * @brief ClientKeyExchange message
 **/

typedef __start_packed struct
{
   uint8_t msgType;   //0
   uint8_t length[3]; //1-3
   uint8_t data[];    //4
} __end_packed TlsClientKeyExchange;


/**
 * @brief CertificateVerify message
 **/

typedef __start_packed struct
{
   uint8_t msgType;     //0
   uint8_t length[3];   //1-3
   uint8_t signature[]; //4
} __end_packed TlsCertificateVerify;


/**
 * @brief Finished message
 **/

typedef __start_packed struct
{
   uint8_t msgType;      //0
   uint8_t length[3];    //1-3
   uint8_t verifyData[]; //4
} __end_packed TlsFinished;


/**
 * @brief ChangeCipherSpec message
 **/

typedef __start_packed struct
{
   uint8_t type; //0
} __end_packed TlsChangeCipherSpec;


/**
 * @brief Alert message
 **/

typedef __start_packed struct
{
   uint8_t level;       //0
   uint8_t description; //1
} __end_packed TlsAlert;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif


/**
 * @brief Sequence number
 **/

typedef uint8_t TlsSequenceNumber[8];


/**
 * @brief Handle for I/O operations
 **/

typedef void *TlsIoHandle;


/**
 * @brief Send callback function
 **/

typedef error_t (*TlsIoSendCallback)(TlsIoHandle handle,
   const void *data, size_t length, size_t *written, uint_t flags);


/**
 * @brief Receive callback function
 **/

typedef error_t (*TlsIoReceiveCallback)(TlsIoHandle handle,
   void *data, size_t size, size_t *received, uint_t flags);


/**
 * @brief Pre-shared key callback function
 **/

typedef error_t (*TlsPskCallback)(TlsContext *context,
   const char_t *pskIdentity);


/**
 * @brief ECDH key agreement callback function
 **/

typedef error_t (*TlsEcdhCallback)(TlsContext *context);


/**
 * @brief ECDSA signature generation callback function
 **/

typedef error_t (*TlsEcdsaSignCallback)(TlsContext *context,
   const uint8_t *digest, size_t digestLength, EcdsaSignature *signature);


/**
 * @brief ECDSA signature verification callback function
 **/

typedef error_t (*TlsEcdsaVerifyCallback)(TlsContext *context,
   const uint8_t *digest, size_t digestLength, EcdsaSignature *signature);


/**
 * @brief Structure describing a cipher suite
 **/

typedef struct
{
   uint16_t identifier;
   const char_t *name;
   TlsKeyExchMethod keyExchMethod;
   const CipherAlgo *cipherAlgo;
   CipherMode cipherMode;
   const HashAlgo *hashAlgo;
   const HashAlgo *prfHashAlgo;
   uint8_t macKeyLen;
   uint8_t encKeyLen;
   uint8_t fixedIvLen;
   uint8_t recordIvLen;
   uint8_t authTagLen;
   uint8_t verifyDataLen;
} TlsCipherSuiteInfo;


/**
 * @brief TLS session
 **/

typedef struct
{
   uint8_t id[32];            ///<Session identifier
   size_t idLength;           ///<Length of the session identifier
   systime_t timestamp;       ///<Time stamp to manage entry lifetime
   uint16_t cipherSuite;      ///<Cipher suite identifier
   uint8_t compressionMethod; ///<Compression method
   uint8_t masterSecret[48];  ///<Master secret
} TlsSession;


/**
 * @brief Session cache
 **/

typedef struct
{
   OsMutex mutex;         ///<Mutex preventing simultaneous access to the cache
   uint_t size;           ///<Maximum number of entries
   TlsSession sessions[]; ///<Cache entries
} TlsCache;


/**
 * @brief Certificate descriptor
 **/

typedef struct
{
   const char_t *certChain;    ///<End entity certificate chain (PEM format)
   size_t certChainLength;     ///<Length of the certificate chain
   const char_t *privateKey;   ///<Private key (PEM format)
   size_t privateKeyLength;    ///<Length of the private key
   TlsCertificateType type;    ///<End entity certificate type
   TlsSignatureAlgo signAlgo;  ///<Signature algorithm used to sign the end entity certificate
   TlsHashAlgo hashAlgo;       ///<Hash algorithm used to sign the end entity certificate
   TlsEcNamedCurve namedCurve; ///<Named curve used to generate the EC public key
} TlsCertDesc;


/**
 * @brief TLS context
 *
 * An opaque data structure that represents a TLS connection
 *
 **/

struct _TlsContext
{
   TlsState state;                          ///<TLS handshake finite state machine
   TlsConnectionEnd entity;                 ///<Client or server operation

   TlsIoHandle handle;                      ///<Handle for I/O operations
   TlsIoSendCallback sendCallback;          ///<Send callback function
   TlsIoReceiveCallback receiveCallback;    ///<Receive callback function
   const PrngAlgo *prngAlgo;                ///<Pseudo-random number generator to be used
   void *prngContext;                       ///<Pseudo-random number generator context

   const uint16_t *cipherSuites;            ///<List of supported cipher suites
   uint_t numCipherSuites;                  ///<Number of cipher suites in the list

   char_t *serverName;                      ///<Fully qualified DNS hostname of the server

#if (TLS_ECC_CALLBACK_SUPPORT == ENABLED)
   TlsEcdhCallback ecdhCallback;
   TlsEcdsaSignCallback ecdsaSignCallback;
   TlsEcdsaVerifyCallback ecdsaVerifyCallback;
#endif

#if (TLS_ALPN_SUPPORT == ENABLED)
   char_t *protocolList;                    ///<List of supported ALPN protocols
#endif

#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   char_t *psk;                             ///<Pre-shared key
   size_t pskLen;                           ///<Length of the pre-shared key, in bytes
   char_t *pskIdentity;                     ///<PSK identity
   char_t *pskIdentityHint;                 ///<PSK identity hint
   TlsPskCallback pskCallback;              ///<PSK callback function
#endif

#if (TLS_DH_ANON_SUPPORT == ENABLED || TLS_DHE_RSA_SUPPORT == ENABLED || \
   TLS_DHE_DSS_SUPPORT == ENABLED || TLS_DHE_PSK_SUPPORT == ENABLED)
   DhContext dhContext;                     ///<Diffie-Hellman context
#endif

#if (TLS_ECDH_ANON_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   EcdhContext ecdhContext;                 ///<ECDH context
#endif

   TlsCertDesc certs[TLS_MAX_CERTIFICATES]; //End entity certificates
   uint_t numCerts;                         //Number of certificates available
   TlsCertDesc *cert;                       //Pointer to the currently selected certificate

   const char_t *trustedCaList;             ///<List of trusted CA (PEM format)
   size_t trustedCaListLen;                 ///<Number of trusted CA in the list

   TlsCertificateType peerCertType;         ///<Peer's certificate type

#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_SUPPORT == ENABLED || \
   TLS_DHE_RSA_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED)
   RsaPublicKey peerRsaPublicKey;           ///<Peer's RSA public key
#endif

#if (TLS_DSA_SIGN_SUPPORT == ENABLED || TLS_DHE_DSS_SUPPORT == ENABLED)
   DsaPublicKey peerDsaPublicKey;           ///<Peer's DSA public key
#endif

#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED || TLS_ECDHE_ECDSA_SUPPORT == ENABLED)
   EcDomainParameters peerEcParams;         ///<Peer's EC domain parameters
   EcPoint peerEcPublicKey;                 ///<Peer's EC public key
#endif

   TlsCache *cache;                         ///<TLS session cache

   uint8_t sessionId[32];                   ///<Session identifier
   size_t sessionIdLen;                     ///<Length of the session identifier

   uint16_t clientVersion;                  ///<Latest version supported by the client
   uint16_t version;                        ///<Negotiated TLS version
   uint16_t cipherSuite;                    ///<Negotiated cipher suite
   uint8_t compressionMethod;               ///<Negotiated compression algorithm
   uint16_t namedCurve;                     ///<Named curve

   TlsHashAlgo signHashAlgo;                ///<Hash algorithm used for signing
   TlsKeyExchMethod keyExchMethod;          ///<Key exchange method
   const CipherAlgo *cipherAlgo;            ///<Bulk cipher algorithm
   CipherMode cipherMode;                   ///<Cipher mode of operation
   const HashAlgo *hashAlgo;                ///<Hash algorithm for MAC operations
   const HashAlgo *prfHashAlgo;             ///<Hash algorithm for PRF operations
   size_t macKeyLen;                        ///<Number of bytes that are used for generating MAC keys
   size_t encKeyLen;                        ///<Number of bytes that are used for generating encryption keys
   size_t fixedIvLen;                       ///<Amount of data needed to be generated for the IV
   size_t recordIvLen;                      ///<Length of the IV
   size_t authTagLen;                       ///<Length of the authentication tag
   size_t verifyDataLen;                    ///<Length of the verify data

//#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   Md5Context *handshakeMd5Context;         ///<MD5 context used to compute verify data
   Sha1Context *handshakeSha1Context;       ///<SHA-1 context used to compute verify data
//#endif

//#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   HashContext *handshakeHashContext;       ///<Hash context used to compute verify data (TLS 1.2)
//#endif

   uint8_t verifyData[64];                  ///<Verify data

   bool_t ecPointFormatExtFound;            ///<The EcPointFormats extension has been received

   TlsClientAuthMode clientAuthMode;        ///<Client authentication mode
   bool_t clientCertRequested;              ///<This flag tells whether the client certificate is requested

   bool_t resume;                           ///<The connection is established by resuming a session
   bool_t changeCipherSpecSent;             ///<A ChangeCipherSpec message has been sent
   bool_t changeCipherSpecReceived;         ///<A ChangeCipherSpec message has been received from the peer
   bool_t fatalAlertSent;                   ///<A fatal alert message has been sent
   bool_t fatalAlertReceived;               ///<A fatal alert message has been received from the peer
   bool_t closeNotifySent;                  ///<A closure alert has been sent
   bool_t closeNotifyReceived;              ///<A closure alert has been received from the peer

   HmacContext hmacContext;                 ///<HMAC context
   void *writeCipherContext;                ///<Bulk cipher context for write operations
   void *readCipherContext;                 ///<Bulk cipher context for read operations
#if (TLS_GCM_CIPHER_SUPPORT == ENABLED)
   GcmContext *writeGcmContext;             ///<GCM context for write operations
   GcmContext *readGcmContext;              ///<GCM context for read operations
#endif

   uint8_t *txBuffer;                       ///<TX buffer
   size_t txBufferSize;                     ///<TX buffer size
   TlsContentType txBufferType;             ///<Type of data that resides in the TX buffer
   size_t txBufferLen;                      ///<Number of bytes that are pending to be sent
   size_t txBufferPos;                      ///<Current position in TX buffer
   size_t txRecordMaxLen;                   ///<Maximum plaintext fragment length
   size_t txRecordLen;                      ///<Length of the TLS record
   size_t txRecordPos;                      ///<Current position in the TLS record

   uint8_t *rxBuffer;                       ///<RX buffer
   size_t rxBufferSize;                     ///<RX buffer size
   TlsContentType rxBufferType;             ///<Type of data that resides in the RX buffer
   size_t rxBufferLen;                      ///<Number of bytes available for reading
   size_t rxBufferPos;                      ///<Current position in RX buffer
   size_t rxRecordMaxLen;                   ///<Maximum plaintext fragment length
   size_t rxRecordLen;                      ///<Length of the TLS record
   size_t rxRecordPos;                      ///<Current position in the TLS record

   union
   {
      struct
      {
         TlsRandom clientRandom;            ///<Client random value
         TlsRandom serverRandom;            ///<Server random value
      };
      uint8_t random[64];
   };

   uint8_t premasterSecret[TLS_MAX_PREMASTER_SECRET_SIZE]; ///<Premaster secret
   size_t premasterSecretLen;               ///<Length of the premaster secret
   uint8_t masterSecret[48];                ///<Master secret
   uint8_t keyBlock[192];                   ///<Key material
   uint8_t *writeMacKey;                    ///<Write MAC key
   uint8_t *readMacKey;                     ///<Read MAC key
   uint8_t *writeEncKey;                    ///<Encryption key that serves for write operations
   uint8_t *readEncKey;                     ///<Encryption key that serves for read operations
   uint8_t *writeIv;                        ///<Write IV
   uint8_t *readIv;                         ///<Read IV

   TlsSequenceNumber writeSeqNum;           ///<Write sequence number
   TlsSequenceNumber readSeqNum;            ///<Read sequence number
};


//TLS application programming interface (API)
TlsContext *tlsInit(void);

error_t tlsSetIoCallbacks(TlsContext *context, TlsIoHandle handle,
   TlsIoSendCallback sendCallback, TlsIoReceiveCallback receiveCallback);

error_t tlsSetConnectionEnd(TlsContext *context, TlsConnectionEnd entity);
error_t tlsSetPrng(TlsContext *context, const PrngAlgo *prngAlgo, void *prngContext);
error_t tlsSetServerName(TlsContext *context, const char_t *serverName);
error_t tlsSetCache(TlsContext *context, TlsCache *cache);
error_t tlsSetClientAuthMode(TlsContext *context, TlsClientAuthMode mode);

error_t tlsSetBufferSize(TlsContext *context,
   size_t txBufferSize, size_t rxBufferSize);

error_t tlsSetCipherSuites(TlsContext *context,
   const uint16_t *cipherSuites, uint_t length);

error_t tlsSetDhParameters(TlsContext *context,
   const char_t *params, size_t length);

error_t tlsSetEcdhCallback(TlsContext *context, TlsEcdhCallback ecdhCallback);

error_t tlsSetEcdsaSignCallback(TlsContext *context,
   TlsEcdsaSignCallback ecdsaSignCallback);

error_t tlsSetEcdsaVerifyCallback(TlsContext *context,
   TlsEcdsaVerifyCallback ecdsaVerifyCallback);

error_t tlsSetAlpnProtocolList(TlsContext *context, const char_t *protocolList);
const char_t *tlsGetAlpnProtocol(TlsContext *context);

error_t tlsSetPsk(TlsContext *context, const uint8_t *psk, size_t pskLength);
error_t tlsSetPskIdentity(TlsContext *context, const char_t *pskIdentity);
error_t tlsSetPskIdentityHint(TlsContext *context, const char_t *pskIdentityHint);
error_t tlsSetPskCallback(TlsContext *context, TlsPskCallback pskCallback);

error_t tlsSetTrustedCaList(TlsContext *context,
   const char_t *trustedCaList, size_t length);

error_t tlsAddCertificate(TlsContext *context, const char_t *certChain,
   size_t certChainLength, const char_t *privateKey, size_t privateKeyLength);

error_t tlsConnect(TlsContext *context);

error_t tlsWrite(TlsContext *context, const void *data,
   size_t length, size_t *written, uint_t flags);

error_t tlsRead(TlsContext *context, void *data,
   size_t size, size_t *received, uint_t flags);

error_t tlsShutdown(TlsContext *context);
error_t tlsShutdownEx(TlsContext *context, bool_t waitForCloseNotify);

void tlsFree(TlsContext *context);

error_t tlsSaveSession(const TlsContext *context, TlsSession *session);
error_t tlsRestoreSession(TlsContext *context, const TlsSession *session);

TlsCache *tlsInitCache(uint_t size);
void tlsFreeCache(TlsCache *cache);

#endif
