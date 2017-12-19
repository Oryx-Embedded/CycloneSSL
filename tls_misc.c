/**
 * @file tls_misc.c
 * @brief TLS helper functions
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
 * @version 1.8.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include <string.h>
#include "tls.h"
#include "tls_cipher_suites.h"
#include "tls_common.h"
#include "tls_misc.h"
#include "encoding/oid.h"
#include "date_time.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Translate an error code to an alert message
 * @param[in] context Pointer to the TLS context
 * @param[in] errorCode Internal error code
 * @return Error code
 **/

void tlsProcessError(TlsContext *context, error_t errorCode)
{
   //Check current state
   if(context->state != TLS_STATE_CLOSED)
   {
      //Check status code
      switch(errorCode)
      {
      //The timeout interval has elapsed
      case ERROR_TIMEOUT:
         break;
      //The read/write operation would have blocked
      case ERROR_WOULD_BLOCK:
         break;
      //The read/write operation has failed
      case ERROR_WRITE_FAILED:
      case ERROR_READ_FAILED:
         context->state = TLS_STATE_CLOSED;
         break;
      //An inappropriate message was received
      case ERROR_UNEXPECTED_MESSAGE:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
         break;
      //A record is received with an incorrect MAC
      case ERROR_BAD_RECORD_MAC:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_BAD_RECORD_MAC);
         break;
      //Invalid record length
      case ERROR_RECORD_OVERFLOW:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_RECORD_OVERFLOW);
         break;
      //Unable to negotiate an acceptable set of security parameters
      case ERROR_HANDSHAKE_FAILED:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_HANDSHAKE_FAILURE);
         break;
      //A certificate was corrupt
      case ERROR_BAD_CERTIFICATE:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_BAD_CERTIFICATE);
         break;
      //A certificate was of an unsupported type
      case ERROR_UNSUPPORTED_CERTIFICATE:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNSUPPORTED_CERTIFICATE);
         break;
      //A certificate has expired or is not currently valid
      case ERROR_CERTIFICATE_EXPIRED:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_CERTIFICATE_EXPIRED);
         break;
      //A field in the handshake was out of range or inconsistent with other fields
      case ERROR_ILLEGAL_PARAMETER:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_ILLEGAL_PARAMETER);
         break;
      //The certificate could not be matched with a known, trusted CA
      case ERROR_UNKNOWN_CA:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNKNOWN_CA);
         break;
      //A message could not be decoded because some field was incorrect
      case ERROR_DECODING_FAILED:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
         break;
      //A handshake cryptographic operation failed
      case ERROR_INVALID_SIGNATURE:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECRYPT_ERROR);
         break;
      //The protocol version the client has attempted to negotiate is not supported
      case ERROR_VERSION_NOT_SUPPORTED:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_PROTOCOL_VERSION);
         break;
      //Inappropriate fallback detected by the server
      case ERROR_INAPPROPRIATE_FALLBACK:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_INAPPROPRIATE_FALLBACK);
         break;
      //The ServerHello contains an extension not present in the ClientHello
      case ERROR_UNSUPPORTED_EXTENSION:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNSUPPORTED_EXTENSION);
         break;
      //No application protocol supported by the server
      case ERROR_NO_APPLICATION_PROTOCOL:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_NO_APPLICATION_PROTOCOL);
         break;
      //Internal error
      default:
         tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_INTERNAL_ERROR);
         break;
      }
   }
}


/**
 * @brief Generate client or server random value
 * @param[in] context Pointer to the TLS context
 * @param[out] random Pointer to the random value
 * @return Error code
 **/

error_t tlsGenerateRandomValue(TlsContext *context, TlsRandom *random)
{
   error_t error;
   uint32_t time;

   //Verify that the pseudorandom number generator is properly configured
   if(context->prngAlgo != NULL && context->prngContext != NULL)
   {
      //Get current time
      time = (uint32_t) getCurrentUnixTime();

      //Clocks are not required to be set correctly by the basic TLS protocol
      if(time != 0)
      {
         //Generate the random value. The first four bytes code the current
         //time and date in standard Unix format
         random->gmtUnixTime = htonl(time);

         //The last 28 bytes contain securely-generated random bytes
         error = context->prngAlgo->read(context->prngContext, random->randomBytes, 28);
      }
      else
      {
         //Generate a 32-byte random value using a cryptographically-safe
         //pseudorandom number generator
         error = context->prngAlgo->read(context->prngContext, (uint8_t *) random, 32);
      }
   }
   else
   {
      //Report an error
      error = ERROR_NOT_CONFIGURED;
   }

   //Return status code
   return error;
}


/**
 * @brief Set the TLS version to be used
 * @param[in] context Pointer to the TLS context
 * @param[in] version TLS version
 * @return Error code
 **/

error_t tlsSelectVersion(TlsContext *context, uint16_t version)
{
   error_t error;

   //Check TLS version
   if(version >= context->versionMin && version <= context->versionMax)
   {
      //Save the TLS protocol version to be used
      context->version = version;

      //The specified TLS version is acceptable
      error = NO_ERROR;
   }
   else
   {
      //Debug message
      TRACE_WARNING("TLS version not supported!\r\n");

      //The specified TLS version is not acceptable
      error = ERROR_VERSION_NOT_SUPPORTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Set cipher suite
 * @param[in] context Pointer to the TLS context
 * @param[in] identifier Cipher suite identifier
 * @return Error code
 **/

error_t tlsSelectCipherSuite(TlsContext *context, uint16_t identifier)
{
   error_t error;
   uint_t i;
   uint_t n;
   bool_t acceptable;
   const TlsCipherSuiteInfo *cipherSuite;

   //Initialize pointer
   cipherSuite = NULL;

   //Restrict the use of certain cipher suites?
   if(context->numCipherSuites > 0)
   {
      //This flag will be set if the specified cipher suite is acceptable
      acceptable = FALSE;

      //Loop through allowed cipher suites
      for(i = 0; i < context->numCipherSuites; i++)
      {
         //Compare cipher suite identifiers
         if(context->cipherSuites[i] == identifier)
         {
            acceptable = TRUE;
            break;
         }
      }
   }
   else
   {
      //The use of the cipher suite is not restricted
      acceptable = TRUE;
   }

   //No restrictions exist concerning the use of the specified cipher suite?
   if(acceptable)
   {
      //This flag will be set if the specified cipher suite is acceptable
      acceptable = FALSE;

      //Determine the number of supported cipher suites
      n = tlsGetNumSupportedCipherSuites();

      //Loop through the list of supported cipher suites
      for(i = 0; i < n; i++)
      {
         //Point to the current item
         cipherSuite = &tlsSupportedCipherSuites[i];

         //Compare cipher suite identifiers
         if(cipherSuite->identifier == identifier)
         {
            acceptable = TRUE;
            break;
         }
      }
   }

   //SSL 3.0, TLS 1.0 or TLS 1.1 currently selected?
   if(acceptable && context->version <= TLS_VERSION_1_1)
   {
      //TLS 1.2 cipher suites must not be negotiated in older versions of TLS
      if(cipherSuite->prfHashAlgo != NULL)
         acceptable = FALSE;
   }

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(acceptable && context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //The only stream cipher described in TLS 1.2 is RC4, which cannot be
      //randomly accessed. RC4 must not be used with DTLS
      if(cipherSuite->cipherMode == CIPHER_MODE_STREAM)
         acceptable = FALSE;
   }
#endif

   //Ensure that the selected cipher suite matches all the criteria
   if(acceptable)
   {
      //Save the negotiated cipher suite
      context->cipherSuite = *cipherSuite;
      //Set the key exchange method to be used
      context->keyExchMethod = cipherSuite->keyExchMethod;

      //PRF with the SHA-256 is used for all cipher suites published prior
      //than TLS 1.2 when TLS 1.2 is negotiated
      if(context->cipherSuite.prfHashAlgo == NULL)
         context->cipherSuite.prfHashAlgo = SHA256_HASH_ALGO;

      //The length of the verify data depends on the TLS version currently used
      if(context->version == SSL_VERSION_3_0)
      {
         //Verify data is always 36-byte long for SSL 3.0
         context->cipherSuite.verifyDataLen = 36;
      }
      else if(context->version <= TLS_VERSION_1_1)
      {
         //Verify data is always 12-byte long for TLS 1.0 and 1.1
         context->cipherSuite.verifyDataLen = 12;
      }
      else
      {
         //The length of the verify data depends on the cipher suite for TLS 1.2
      }

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //Debug message
      TRACE_ERROR("Cipher suite not supported!\r\n");
      //The specified cipher suite is not supported
      error = ERROR_HANDSHAKE_FAILED;
   }

   //Return status code
   return error;
}


/**
 * @brief Set compression method
 * @param[in] context Pointer to the TLS context
 * @param[in] identifier Compression method identifier
 * @return Error code
 **/

error_t tlsSelectCompressMethod(TlsContext *context, uint8_t identifier)
{
   //Check if the requested compression algorithm is supported
   if(identifier != TLS_COMPRESSION_METHOD_NULL)
      return ERROR_ILLEGAL_PARAMETER;

   //Save compression method identifier
   context->compressMethod = identifier;
   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Select the named curve to be used when performing ECDH key exchange
 * @param[in] context Pointer to the TLS context
 * @param[in] curveList Set of elliptic curves supported by the peer
 * @return Error code
 **/

error_t tlsSelectNamedCurve(TlsContext *context,
   const TlsEllipticCurveList *curveList)
{
   uint_t i;
   uint_t n;

   //Check whether a list of elliptic curves has been provided
   if(curveList != NULL)
   {
      //Process the list and select the relevant elliptic curve...
      context->namedCurve = TLS_EC_CURVE_NONE;
      //Get the number of named curves present in the list
      n = ntohs(curveList->length) / sizeof(uint16_t);

      //The named curve to be used when performing ECDH key exchange must be
      //one of those present in the list
      for(i = 0; i < n; i++)
      {
         //Acceptable elliptic curve found?
         if(tlsGetCurveInfo(ntohs(curveList->value[i])) != NULL)
         {
            //Save the named curve
            context->namedCurve = ntohs(curveList->value[i]);
            //We are done
            break;
         }
      }
   }
   else
   {
      //A client that proposes ECC cipher suites may choose not to include
      //the EllipticCurves extension. In this case, the server is free to
      //choose any one of the elliptic curves it supports
#if (TLS_SECP256R1_SUPPORT == ENABLED)
      context->namedCurve = TLS_EC_CURVE_SECP256R1;
#else
      context->namedCurve = TLS_EC_CURVE_NONE;
#endif
   }

   //If no acceptable choices are presented, return an error
   if(context->namedCurve == TLS_EC_CURVE_NONE)
      return ERROR_FAILURE;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Initialize encryption engine
 * @param[in] context Pointer to the TLS context
 * @param[in] encryptionEngine Pointer to the encryption/decryption engine to
 *   be initialized
 * @param[in] entity Specifies whether client or server write keys shall be used
 * @return Error code
 **/

error_t tlsInitEncryptionEngine(TlsContext *context,
   TlsEncryptionEngine *encryptionEngine, TlsConnectionEnd entity)
{
   error_t error;
   const uint8_t *p;
   TlsCipherSuiteInfo *cipherSuite;

   //Point to the negotiated cipher suite
   cipherSuite = &context->cipherSuite;

   //Save the negotiated TLS version
   encryptionEngine->version = context->version;

   //The sequence number must be set to zero whenever a connection state
   //is made the active state
   memset(&encryptionEngine->seqNum, 0, sizeof(TlsSequenceNumber));

#if (DTLS_SUPPORT == ENABLED)
   //The epoch number is initially zero and is incremented each time a
   //ChangeCipherSpec message is sent
   encryptionEngine->epoch++;

   //Sequence numbers are maintained separately for each epoch, with each
   //sequence number initially being 0 for each epoch
   memset(&encryptionEngine->dtlsSeqNum, 0, sizeof(DtlsSequenceNumber));
#endif

   //Set appropriate length for MAC key, encryption key, IV and
   //authentication tag
   encryptionEngine->macKeyLen = cipherSuite->macKeyLen;
   encryptionEngine->encKeyLen = cipherSuite->encKeyLen;
   encryptionEngine->fixedIvLen = cipherSuite->fixedIvLen;
   encryptionEngine->recordIvLen = cipherSuite->recordIvLen;
   encryptionEngine->authTagLen = cipherSuite->authTagLen;

   //Check whether client or server write keys shall be used
   if(entity == TLS_CONNECTION_END_CLIENT)
   {
      //Point to the key material
      p = context->keyBlock;
      //Save MAC key
      memcpy(encryptionEngine->macKey, p, cipherSuite->macKeyLen);

      //Advance current position in the key block
      p += 2 * cipherSuite->macKeyLen;
      //Save encryption key
      memcpy(encryptionEngine->encKey, p, cipherSuite->encKeyLen);

      //Advance current position in the key block
      p += 2 * cipherSuite->encKeyLen;
      //Save initialization vector
      memcpy(encryptionEngine->iv, p, cipherSuite->fixedIvLen);
   }
   //TLS operates as a server?
   else
   {
      //Point to the key material
      p = context->keyBlock + cipherSuite->macKeyLen;
      //Save MAC key
      memcpy(encryptionEngine->macKey, p, cipherSuite->macKeyLen);

      //Advance current position in the key block
      p += cipherSuite->macKeyLen + cipherSuite->encKeyLen;
      //Save encryption key
      memcpy(encryptionEngine->encKey, p, cipherSuite->encKeyLen);

      //Advance current position in the key block
      p += cipherSuite->encKeyLen + cipherSuite->fixedIvLen;
      //Save initialization vector
      memcpy(encryptionEngine->iv, p, cipherSuite->fixedIvLen);
   }

   //Set cipher and hash algorithms
   encryptionEngine->cipherAlgo = cipherSuite->cipherAlgo;
   encryptionEngine->cipherMode = cipherSuite->cipherMode;
   encryptionEngine->hashAlgo = cipherSuite->hashAlgo;

   //Set HMAC context
   encryptionEngine->hmacContext = &context->hmacContext;

   //Check cipher mode of operation
   if(encryptionEngine->cipherMode == CIPHER_MODE_STREAM ||
      encryptionEngine->cipherMode == CIPHER_MODE_CBC ||
      encryptionEngine->cipherMode == CIPHER_MODE_CCM ||
      encryptionEngine->cipherMode == CIPHER_MODE_GCM)
   {
      //Allocate a memory buffer to hold the encryption context
      encryptionEngine->cipherContext = tlsAllocMem(encryptionEngine->cipherAlgo->contextSize);

      //Successful memory allocation?
      if(encryptionEngine->cipherContext != NULL)
      {
         //Configure the encryption engine with the write key
         error = encryptionEngine->cipherAlgo->init(encryptionEngine->cipherContext,
            encryptionEngine->encKey, encryptionEngine->encKeyLen);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }

#if (TLS_GCM_CIPHER_SUPPORT == ENABLED)
      //GCM AEAD cipher?
      if(encryptionEngine->cipherMode == CIPHER_MODE_GCM)
      {
         //Check status code
         if(!error)
         {
            //Allocate a memory buffer to hold the GCM context
            encryptionEngine->gcmContext = tlsAllocMem(sizeof(GcmContext));

            //Successful memory allocation?
            if(encryptionEngine->gcmContext != NULL)
            {
               //Initialize GCM context
               error = gcmInit(encryptionEngine->gcmContext,
                  encryptionEngine->cipherAlgo, encryptionEngine->cipherContext);
            }
            else
            {
               //Failed to allocate memory
               error = ERROR_OUT_OF_MEMORY;
            }
         }
      }
#endif
   }
   else if(encryptionEngine->cipherMode == CIPHER_MODE_NULL ||
      encryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      //We are done
      error = NO_ERROR;
   }
   else
   {
      //Unsupported mode of operation
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Release encryption engine
 * @param[in] encryptionEngine Pointer to the encryption/decryption engine
 **/

void tlsFreeEncryptionEngine(TlsEncryptionEngine *encryptionEngine)
{
   //Release cipher context
   if(encryptionEngine->cipherContext != NULL)
   {
      tlsFreeMem(encryptionEngine->cipherContext);
      encryptionEngine->cipherContext = NULL;
   }

#if (TLS_GCM_CIPHER_SUPPORT == ENABLED)
   //Release GCM context
   if(encryptionEngine->gcmContext != NULL)
   {
      tlsFreeMem(encryptionEngine->gcmContext);
      encryptionEngine->gcmContext = NULL;
   }
#endif
}


/**
 * @brief Encode a multiple precision integer to an opaque vector
 * @param[in] a Pointer to a multiple precision integer
 * @param[out] data Buffer where to store the opaque vector
 * @param[out] length Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsWriteMpi(const Mpi *a, uint8_t *data, size_t *length)
{
   error_t error;
   size_t n;

   //Retrieve the actual size of the integer
   n = mpiGetByteLength(a);

   //The data is preceded by a 2-byte length field
   STORE16BE(n, data);

   //Convert the integer to an octet string
   error = mpiWriteRaw(a, data + 2, n);
   //Conversion failed?
   if(error)
      return error;

   //Return the total number of bytes that have been written
   *length = n + 2;
   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Read a multiple precision integer from an opaque vector
 * @param[out] a Resulting multiple precision integer
 * @param[in] data Buffer where to read the opaque vector
 * @param[in] size Total number of bytes available in the buffer
 * @param[out] length Total number of bytes that have been read
 * @return Error code
 **/

error_t tlsReadMpi(Mpi *a, const uint8_t *data, size_t size, size_t *length)
{
   error_t error;
   size_t n;

   //Buffer underrun?
   if(size < 2)
      return ERROR_DECODING_FAILED;

   //Decode the length field
   n = LOAD16BE(data);

   //Buffer underrun?
   if(size < (n + 2))
      return ERROR_DECODING_FAILED;

   //Convert the octet string to a multiple precision integer
   error = mpiReadRaw(a, data + 2, n);
   //Any error to report?
   if(error)
      return error;

   //Return the total number of bytes that have been read
   *length = n + 2;
   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Encode an EC point to an opaque vector
 * @param[in] params EC domain parameters
 * @param[in] a Pointer to an EC point
 * @param[out] data Buffer where to store the opaque vector
 * @param[out] length Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsWriteEcPoint(const EcDomainParameters *params,
   const EcPoint *a, uint8_t *data, size_t *length)
{
#if (TLS_ECDH_ANON_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   error_t error;

   //Convert the EC point to an octet string
   error = ecExport(params, a, data + 1, length);
   //Any error to report?
   if(error)
      return error;

   //Set the length of the opaque vector
   data[0] = (uint8_t) (*length);

   //Return the total number of bytes that have been written
   *length += 1;
   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Read an EC point from an opaque vector
 * @param[in] params EC domain parameters
 * @param[out] a Resulting EC point
 * @param[in] data Buffer where to read the opaque vector
 * @param[in] size Total number of bytes available in the buffer
 * @param[out] length Total number of bytes that have been read
 * @return Error code
 **/

error_t tlsReadEcPoint(const EcDomainParameters *params,
   EcPoint *a, const uint8_t *data, size_t size, size_t *length)
{
#if (TLS_ECDH_ANON_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Buffer underrun?
   if(size < 1)
      return ERROR_DECODING_FAILED;

   //The EC point representation is preceded by a length field
   n = data[0];

   //Valid EC point representation?
   if(size < (n + 1))
      return ERROR_DECODING_FAILED;

   //Convert the octet string to an EC point
   error = ecImport(params, a, data + 1, n);
   //Any error to report?
   if(error)
      return error;

   //Return the total number of bytes that have been read
   *length = n + 1;
   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Convert TLS version to string representation
 * @param[in] version Version number
 * @return Cipher suite name
 **/

const char_t *tlsGetVersionName(uint16_t version)
{
   //TLS versions
   static const char_t *label[] =
   {
      "SSL 3.0",
      "TLS 1.0",
      "TLS 1.1",
      "TLS 1.2",
      "DTLS 1.0",
      "DTLS 1.2",
      "Unknown"
   };

   //Check current version
   if(version == SSL_VERSION_3_0)
      return label[0];
   else if(version == TLS_VERSION_1_0)
      return label[1];
   else if(version == TLS_VERSION_1_1)
      return label[2];
   else if(version == TLS_VERSION_1_2)
      return label[3];
   else if(version == DTLS_VERSION_1_0)
      return label[4];
   else if(version == DTLS_VERSION_1_2)
      return label[5];
   else
      return label[6];
}


/**
 * @brief Get the hash algorithm that matches the specified identifier
 * @param[in] hashAlgoId Hash algorithm identifier
 * @return Pointer to the hash algorithm
 **/

const HashAlgo *tlsGetHashAlgo(uint8_t hashAlgoId)
{
   const HashAlgo *hashAlgo;

   //Check hash algorithm identifier
   switch(hashAlgoId)
   {
#if (TLS_MD5_SUPPORT == ENABLED)
   //MD5 hash identifier?
   case TLS_HASH_ALGO_MD5:
      hashAlgo = MD5_HASH_ALGO;
      break;
#endif
#if (TLS_SHA1_SUPPORT == ENABLED)
   //SHA-1 hash identifier?
   case TLS_HASH_ALGO_SHA1:
      hashAlgo = SHA1_HASH_ALGO;
      break;
#endif
#if (TLS_SHA224_SUPPORT == ENABLED)
   //SHA-224 hash identifier?
   case TLS_HASH_ALGO_SHA224:
      hashAlgo = SHA224_HASH_ALGO;
      break;
#endif
#if (TLS_SHA256_SUPPORT == ENABLED)
   //SHA-256 hash identifier?
   case TLS_HASH_ALGO_SHA256:
      hashAlgo = SHA256_HASH_ALGO;
      break;
#endif
#if (TLS_SHA384_SUPPORT == ENABLED)
   //SHA-384 hash identifier?
   case TLS_HASH_ALGO_SHA384:
      hashAlgo = SHA384_HASH_ALGO;
      break;
#endif
#if (TLS_SHA512_SUPPORT == ENABLED)
   //SHA-512 hash identifier?
   case TLS_HASH_ALGO_SHA512:
      hashAlgo = SHA512_HASH_ALGO;
      break;
#endif
   //Unknown hash identifier?
   default:
      hashAlgo = NULL;
      break;
   }

   //Return a pointer to the corresponding hash algorithm
   return hashAlgo;
}


/**
 * @brief Get the EC domain parameters that match the specified named curve
 * @param[in] namedCurve Elliptic curve identifier
 * @return Elliptic curve domain parameters
 **/

const EcCurveInfo *tlsGetCurveInfo(uint16_t namedCurve)
{
   const EcCurveInfo *curveInfo;

   //Default elliptic curve domain parameters
   curveInfo = NULL;

#if (TLS_ECDH_ANON_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //Check named curve
   switch(namedCurve)
   {
#if (TLS_SECP160K1_SUPPORT == ENABLED)
   //secp160k1 elliptic curve?
   case TLS_EC_CURVE_SECP160K1:
      curveInfo = ecGetCurveInfo(SECP160K1_OID, sizeof(SECP160K1_OID));
      break;
#endif
#if (TLS_SECP160R1_SUPPORT == ENABLED)
   //secp160r1 elliptic curve?
   case TLS_EC_CURVE_SECP160R1:
      curveInfo = ecGetCurveInfo(SECP160R1_OID, sizeof(SECP160R1_OID));
      break;
#endif
#if (TLS_SECP160R2_SUPPORT == ENABLED)
   //secp160r2 elliptic curve?
   case TLS_EC_CURVE_SECP160R2:
      curveInfo = ecGetCurveInfo(SECP160R2_OID, sizeof(SECP160R2_OID));
      break;
#endif
#if (TLS_SECP192K1_SUPPORT == ENABLED)
   //secp192k1 elliptic curve?
   case TLS_EC_CURVE_SECP192K1:
      curveInfo = ecGetCurveInfo(SECP192K1_OID, sizeof(SECP192K1_OID));
      break;
#endif
#if (TLS_SECP192R1_SUPPORT == ENABLED)
   //secp192r1 elliptic curve?
   case TLS_EC_CURVE_SECP192R1:
      curveInfo = ecGetCurveInfo(SECP192R1_OID, sizeof(SECP192R1_OID));
      break;
#endif
#if (TLS_SECP224K1_SUPPORT == ENABLED)
   //secp224k1 elliptic curve?
   case TLS_EC_CURVE_SECP224K1:
      curveInfo = ecGetCurveInfo(SECP224K1_OID, sizeof(SECP224K1_OID));
      break;
#endif
#if (TLS_SECP224R1_SUPPORT == ENABLED)
   //secp224r1 elliptic curve?
   case TLS_EC_CURVE_SECP224R1:
      curveInfo = ecGetCurveInfo(SECP224R1_OID, sizeof(SECP224R1_OID));
      break;
#endif
#if (TLS_SECP256K1_SUPPORT == ENABLED)
   //secp256k1 elliptic curve?
   case TLS_EC_CURVE_SECP256K1:
      curveInfo = ecGetCurveInfo(SECP256K1_OID, sizeof(SECP256K1_OID));
      break;
#endif
#if (TLS_SECP256R1_SUPPORT == ENABLED)
   //secp256r1 elliptic curve?
   case TLS_EC_CURVE_SECP256R1:
      curveInfo = ecGetCurveInfo(SECP256R1_OID, sizeof(SECP256R1_OID));
      break;
#endif
#if (TLS_SECP384R1_SUPPORT == ENABLED)
   //secp384r1 elliptic curve?
   case TLS_EC_CURVE_SECP384R1:
      curveInfo = ecGetCurveInfo(SECP384R1_OID, sizeof(SECP384R1_OID));
      break;
#endif
#if (TLS_SECP521R1_SUPPORT == ENABLED)
   //secp521r1 elliptic curve?
   case TLS_EC_CURVE_SECP521R1:
      curveInfo = ecGetCurveInfo(SECP521R1_OID, sizeof(SECP521R1_OID));
      break;
#endif
#if (TLS_BRAINPOOLP256R1_SUPPORT == ENABLED)
   //brainpoolP256r1 elliptic curve?
   case TLS_EC_CURVE_BRAINPOOLP256R1:
      curveInfo = ecGetCurveInfo(BRAINPOOLP256R1_OID, sizeof(BRAINPOOLP256R1_OID));
      break;
#endif
#if (TLS_BRAINPOOLP384R1_SUPPORT == ENABLED)
   //brainpoolP384r1 elliptic curve?
   case TLS_EC_CURVE_BRAINPOOLP384R1:
      curveInfo = ecGetCurveInfo(BRAINPOOLP384R1_OID, sizeof(BRAINPOOLP384R1_OID));
      break;
#endif
#if (TLS_BRAINPOOLP512R1_SUPPORT == ENABLED)
   //brainpoolP512r1 elliptic curve?
   case TLS_EC_CURVE_BRAINPOOLP512R1:
      curveInfo = ecGetCurveInfo(BRAINPOOLP512R1_OID, sizeof(BRAINPOOLP512R1_OID));
      break;
#endif
   //Unknown elliptic curve identifier?
   default:
      curveInfo = NULL;
      break;
   }
#endif

   //Return the elliptic curve domain parameters, if any
   return curveInfo;
}


/**
 * @brief Get the named curve that matches the specified OID
 * @param[in] oid Object identifier
 * @param[in] length OID length
 * @return Named curve
 **/

TlsEcNamedCurve tlsGetNamedCurve(const uint8_t *oid, size_t length)
{
   TlsEcNamedCurve namedCurve;

   //Default named curve
   namedCurve = TLS_EC_CURVE_NONE;

#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED || TLS_ECDHE_ECDSA_SUPPORT == ENABLED)
   //Invalid parameters?
   if(oid == NULL || length == 0)
   {
      namedCurve = TLS_EC_CURVE_NONE;
   }
#if (TLS_SECP160K1_SUPPORT == ENABLED)
   //secp160k1 elliptic curve?
   else if(!oidComp(oid, length, SECP160K1_OID, sizeof(SECP160K1_OID)))
   {
      namedCurve = TLS_EC_CURVE_SECP160K1;
   }
#endif
#if (TLS_SECP160R1_SUPPORT == ENABLED)
   //secp160r1 elliptic curve?
   else if(!oidComp(oid, length, SECP160R1_OID, sizeof(SECP160R1_OID)))
   {
      namedCurve = TLS_EC_CURVE_SECP160R1;
   }
#endif
#if (TLS_SECP160R2_SUPPORT == ENABLED)
   //secp160r2 elliptic curve?
   else if(!oidComp(oid, length, SECP160R2_OID, sizeof(SECP160R2_OID)))
   {
      namedCurve = TLS_EC_CURVE_SECP160R2;
   }
#endif
#if (TLS_SECP192K1_SUPPORT == ENABLED)
   //secp192k1 elliptic curve?
   else if(!oidComp(oid, length, SECP192K1_OID, sizeof(SECP192K1_OID)))
   {
      namedCurve = TLS_EC_CURVE_SECP192K1;
   }
#endif
#if (TLS_SECP192R1_SUPPORT == ENABLED)
   //secp192r1 elliptic curve?
   else if(!oidComp(oid, length, SECP192R1_OID, sizeof(SECP192R1_OID)))
   {
      namedCurve = TLS_EC_CURVE_SECP192R1;
   }
#endif
#if (TLS_SECP224K1_SUPPORT == ENABLED)
   //secp224k1 elliptic curve?
   else if(!oidComp(oid, length, SECP224K1_OID, sizeof(SECP224K1_OID)))
   {
      namedCurve = TLS_EC_CURVE_SECP224K1;
   }
#endif
#if (TLS_SECP224R1_SUPPORT == ENABLED)
   //secp224r1 elliptic curve?
   else if(!oidComp(oid, length, SECP224R1_OID, sizeof(SECP224R1_OID)))
   {
      namedCurve = TLS_EC_CURVE_SECP224R1;
   }
#endif
#if (TLS_SECP256K1_SUPPORT == ENABLED)
   //secp256k1 elliptic curve?
   else if(!oidComp(oid, length, SECP256K1_OID, sizeof(SECP256K1_OID)))
   {
      namedCurve = TLS_EC_CURVE_SECP256K1;
   }
#endif
#if (TLS_SECP256R1_SUPPORT == ENABLED)
   //secp256r1 elliptic curve?
   else if(!oidComp(oid, length, SECP256R1_OID, sizeof(SECP256R1_OID)))
   {
      namedCurve = TLS_EC_CURVE_SECP256R1;
   }
#endif
#if (TLS_SECP384R1_SUPPORT == ENABLED)
   //secp384r1 elliptic curve?
   else if(!oidComp(oid, length, SECP384R1_OID, sizeof(SECP384R1_OID)))
   {
      namedCurve = TLS_EC_CURVE_SECP384R1;
   }
#endif
#if (TLS_SECP521R1_SUPPORT == ENABLED)
   //secp521r1 elliptic curve?
   else if(!oidComp(oid, length, SECP521R1_OID, sizeof(SECP521R1_OID)))
   {
      namedCurve = TLS_EC_CURVE_SECP521R1;
   }
#endif
#if (TLS_BRAINPOOLP256R1_SUPPORT == ENABLED)
   //brainpoolP256r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP256R1_OID, sizeof(BRAINPOOLP256R1_OID)))
   {
      namedCurve = TLS_EC_CURVE_BRAINPOOLP256R1;
   }
#endif
#if (TLS_BRAINPOOLP384R1_SUPPORT == ENABLED)
   //brainpoolP384r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP384R1_OID, sizeof(BRAINPOOLP384R1_OID)))
   {
      namedCurve = TLS_EC_CURVE_BRAINPOOLP384R1;
   }
#endif
#if (TLS_BRAINPOOLP512R1_SUPPORT == ENABLED)
   //brainpoolP512r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP512R1_OID, sizeof(BRAINPOOLP512R1_OID)))
   {
      namedCurve = TLS_EC_CURVE_BRAINPOOLP512R1;
   }
#endif
   //Unknown identifier?
   else
   {
      namedCurve = TLS_EC_CURVE_NONE;
   }
#endif

   //Return the corresponding named curve
   return namedCurve;
}


/**
 * @brief Compute overhead caused by encryption
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @param[in] payloadLen Length of the payload, in bytes
 * @return Overhead, in bytes, caused by encryption
 **/

size_t tlsComputeEncryptionOverhead(TlsEncryptionEngine *encryptionEngine,
   size_t payloadLen)
{
   size_t n;

   //Initialize variable
   n = 0;

   //Message authentication?
   if(encryptionEngine->hashAlgo != NULL)
      n += encryptionEngine->hashAlgo->digestSize;

   //Check cipher mode
   if(encryptionEngine->cipherMode == CIPHER_MODE_CBC)
   {
      //TLS 1.1 and 1.2 use an explicit IV
      if(encryptionEngine->version >= TLS_VERSION_1_1)
         n += encryptionEngine->recordIvLen;

      //Padding is added to force the length of the plaintext to be an
      //integral multiple of the cipher's block length
      n += encryptionEngine->cipherAlgo->blockSize -
         ((payloadLen + n) % encryptionEngine->cipherAlgo->blockSize);
   }
   else if(encryptionEngine->cipherMode == CIPHER_MODE_CCM ||
      encryptionEngine->cipherMode == CIPHER_MODE_GCM)
   {
      //Consider the explicit nonce and the authentication tag
      n += encryptionEngine->recordIvLen + encryptionEngine->authTagLen;
   }
   else if(encryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      //Consider the authentication tag only
      n += encryptionEngine->authTagLen;
   }
   else
   {
      //Stream ciphers do not cause any overhead
   }

   //Return the total overhead caused by encryption
   return n;
}

#endif
