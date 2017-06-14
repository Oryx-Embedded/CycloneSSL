/**
 * @file tls_server_misc.c
 * @brief Helper functions (TLS server)
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
 * @version 1.7.8
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include <string.h>
#include "tls.h"
#include "tls_cipher_suites.h"
#include "tls_server.h"
#include "tls_server_misc.h"
#include "tls_common.h"
#include "tls_record.h"
#include "tls_cache.h"
#include "tls_misc.h"
#include "pem.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED && TLS_SERVER_SUPPORT == ENABLED)


/**
 * @brief Format EcPointFormats extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the EcPointFormats extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatServerEcPointFormatsExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_ECDH_ANON_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //A server that selects an ECC cipher suite in response to a ClientHello
   //message including an EcPointFormats extension appends this extension
   //to its ServerHello message
   if(tlsIsEccCipherSuite(context->cipherSuite.identifier))
   {
      //EcPointFormats extension found in the ClientHello message?
      if(context->ecPointFormatExtFound)
      {
         TlsExtension *extension;
         TlsEcPointFormatList *ecPointFormatList;

         //Add the EcPointFormats extension
         extension = (TlsExtension *) p;
         //Type of the extension
         extension->type = HTONS(TLS_EXT_EC_POINT_FORMATS);

         //Point to the list of supported EC point formats
         ecPointFormatList = (TlsEcPointFormatList *) extension->value;
         //Items in the list are ordered according to server's preferences
         n = 0;

         //The server can parse only the uncompressed point format...
         ecPointFormatList->value[n++] = TLS_EC_POINT_FORMAT_UNCOMPRESSED;
         //Fix the length of the list
         ecPointFormatList->length = n;

         //Consider the 2-byte length field that precedes the list
         n += sizeof(TlsEcPointFormatList);
         //Fix the length of the extension
         extension->length = htons(n);

         //Compute the length, in bytes, of the EcPointFormats extension
         n += sizeof(TlsExtension);
      }
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format RenegotiationInfo extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the RenegotiationInfo extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatServerRenegoInfoExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //Check whether secure renegotiation is enabled
   if(context->secureRenegoEnabled)
   {
      //During secure renegotiation, the server must include a renegotiation_info
      //extension containing the saved client_verify_data and server_verify_data
      if(context->secureRenegoFlag)
      {
         TlsExtension *extension;
         TlsRenegoConnection *renegoConnection;

         //Determine the length of the renegotiated_connection field
         n = context->clientVerifyDataLen + context->serverVerifyDataLen;

         //Add the RenegotiationInfo extension
         extension = (TlsExtension *) p;
         //Type of the extension
         extension->type = HTONS(TLS_EXT_RENEGOTIATION_INFO);

         //Point to the renegotiated_connection field
         renegoConnection = (TlsRenegoConnection *) extension->value;
         //Set the length of the verify data
         renegoConnection->length = n;

         //Copy the saved client_verify_data
         memcpy(renegoConnection->value, context->clientVerifyData,
            context->clientVerifyDataLen);

         //Copy the saved client_verify_data
         memcpy(renegoConnection->value + context->clientVerifyDataLen,
            context->serverVerifyData, context->serverVerifyDataLen);

         //Consider the length field that precedes the renegotiated_connection
         //field
         n += sizeof(TlsRenegoConnection);
         //Fix the length of the extension
         extension->length = htons(n);

         //Compute the length, in bytes, of the RenegotiationInfo extension
         n += sizeof(TlsExtension);
      }
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format PSK identity hint
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the PSK identity hint
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatPskIdentityHint(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n;
   TlsPskIdentityHint *pskIdentityHint;

   //Point to the PSK identity hint
   pskIdentityHint = (TlsPskIdentityHint *) p;

   //Initialize length field
   n = 0;

#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //Any PSK identity hint defined?
   if(context->pskIdentityHint != NULL)
   {
      //Determine the length of the PSK identity hint
      n = strlen(context->pskIdentityHint);
      //Copy PSK identity hint
      memcpy(pskIdentityHint->value, context->pskIdentityHint, n);
   }
#endif

   //The PSK identity hint is preceded by a 2-byte length field
   pskIdentityHint->length = htons(n);

   //Total number of bytes that have been written
   *written = sizeof(TlsPskIdentityHint) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format server's key exchange parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the PSK identity hint
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatServerKeyParams(TlsContext *context,
   uint8_t *p, size_t *written)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Total number of bytes that have been written
   *written = 0;

#if (TLS_DH_ANON_SUPPORT == ENABLED || TLS_DHE_RSA_SUPPORT == ENABLED || \
   TLS_DHE_DSS_SUPPORT == ENABLED || TLS_DHE_PSK_SUPPORT == ENABLED)
   //Diffie-Hellman key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK)
   {
      size_t n;

      //Generate an ephemeral key pair
      error = dhGenerateKeyPair(&context->dhContext,
         context->prngAlgo, context->prngContext);

      //Check status code
      if(!error)
      {
         //Debug message
         TRACE_DEBUG("Diffie-Hellman parameters:\r\n");
         TRACE_DEBUG("  Prime modulus:\r\n");
         TRACE_DEBUG_MPI("    ", &context->dhContext.params.p);
         TRACE_DEBUG("  Generator:\r\n");
         TRACE_DEBUG_MPI("    ", &context->dhContext.params.g);
         TRACE_DEBUG("  Server public value:\r\n");
         TRACE_DEBUG_MPI("    ", &context->dhContext.ya);

         //Encode the prime modulus to an opaque vector
         error = tlsWriteMpi(&context->dhContext.params.p, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Total number of bytes that have been written
         *written += n;

         //Encode the generator to an opaque vector
         error = tlsWriteMpi(&context->dhContext.params.g, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Total number of bytes that have been written
         *written += n;

         //Encode the server's public value to an opaque vector
         error = tlsWriteMpi(&context->dhContext.ya, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Adjust the length of the key exchange parameters
         *written += n;
      }
   }
   else
#endif
#if (TLS_ECDH_ANON_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //ECDH key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      size_t n;
      const EcCurveInfo *curveInfo;

      //Retrieve the elliptic curve to be used
      curveInfo = tlsGetCurveInfo(context->namedCurve);

      //Make sure the elliptic curve is supported
      if(curveInfo != NULL)
      {
         //Load EC domain parameters
         error = ecLoadDomainParameters(&context->ecdhContext.params,
            curveInfo);

         //Check status code
         if(!error)
         {
            //Generate an ephemeral key pair
            error = ecdhGenerateKeyPair(&context->ecdhContext,
               context->prngAlgo, context->prngContext);
         }

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_DEBUG("  Server public key X:\r\n");
            TRACE_DEBUG_MPI("    ", &context->ecdhContext.qa.x);
            TRACE_DEBUG("  Server public key Y:\r\n");
            TRACE_DEBUG_MPI("    ", &context->ecdhContext.qa.y);

            //Set the type of the elliptic curve domain parameters
            *p = TLS_EC_CURVE_TYPE_NAMED_CURVE;

            //Advance data pointer
            p += sizeof(uint8_t);
            //Total number of bytes that have been written
            *written += sizeof(uint8_t);

            //Write elliptic curve identifier
            STORE16BE(context->namedCurve, p);

            //Advance data pointer
            p += sizeof(uint16_t);
            //Total number of bytes that have been written
            *written += sizeof(uint16_t);

            //Write server's public key
            error = tlsWriteEcPoint(&context->ecdhContext.params,
               &context->ecdhContext.qa, p, &n);
         }

         //Check status code
         if(!error)
         {
            //Advance data pointer
            p +=n;
            //Total number of bytes that have been written
            *written += n;
         }
      }
      else
      {
         //The specified elliptic curve is not supported
         error = ERROR_FAILURE;
      }
   }
   else
#endif
   //Any other exchange method?
   {
      //It is not legal to send the ServerKeyExchange message when a key
      //exchange method other than DHE_DSS, DHE_RSA, DH_anon, ECDHE_RSA,
      //ECDHE_ECDSA or ECDH_anon is selected
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Generate signature over the server's key exchange parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the PSK identity hint
 * @param[in] params Pointer to the server's key exchange parameters
 * @param[in] paramsLen Length of the server's key exchange parameters
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsGenerateServerKeySignature(TlsContext *context,
   uint8_t *p, const uint8_t *params, size_t paramsLen, size_t *written)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Total number of bytes that have been written
   *written = 0;

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //SSL 3.0, TLS 1.0 or TLS 1.1 currently selected?
   if(context->version <= TLS_VERSION_1_1)
   {
      TlsDigitalSignature *signature;

      //Point to the digitally-signed element
      signature = (TlsDigitalSignature *) p;

#if (TLS_DHE_RSA_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED)
      //Check whether DHE_RSA or ECDHE_RSA key exchange method is currently used
      if(context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA)
      {
         Md5Context *md5Context;
         Sha1Context *sha1Context;
         RsaPrivateKey privateKey;

         //Initialize RSA private key
         rsaInitPrivateKey(&privateKey);

         //Allocate a memory buffer to hold the MD5 context
         md5Context = tlsAllocMem(sizeof(Md5Context));

         //Successful memory allocation?
         if(md5Context != NULL)
         {
            //Compute MD5(ClientHello.random + ServerHello.random + ServerDhParams)
            md5Init(md5Context);
            md5Update(md5Context, context->random, 64);
            md5Update(md5Context, params, paramsLen);
            md5Final(md5Context, context->serverVerifyData);

            //Release previously allocated memory
            tlsFreeMem(md5Context);
         }
         else
         {
            //Failed to allocate memory
            error = ERROR_OUT_OF_MEMORY;
         }

         //Check status code
         if(!error)
         {
            //Allocate a memory buffer to hold the SHA-1 context
            sha1Context = tlsAllocMem(sizeof(Sha1Context));

            //Successful memory allocation?
            if(sha1Context != NULL)
            {
               //Compute SHA(ClientHello.random + ServerHello.random + ServerDhParams)
               sha1Init(sha1Context);
               sha1Update(sha1Context, context->random, 64);
               sha1Update(sha1Context, params, paramsLen);
               sha1Final(sha1Context, context->serverVerifyData + MD5_DIGEST_SIZE);

               //Release previously allocated memory
               tlsFreeMem(sha1Context);
            }
            else
            {
               //Failed to allocate memory
               error = ERROR_OUT_OF_MEMORY;
            }
         }

         //Check status code
         if(!error)
         {
            //Decode the PEM structure that holds the RSA private key
            error = pemReadRsaPrivateKey(context->cert->privateKey,
               context->cert->privateKeyLength, &privateKey);
         }

         //Check status code
         if(!error)
         {
            //Sign the key exchange parameters using RSA
            error = tlsGenerateRsaSignature(&privateKey,
               context->serverVerifyData, signature->value, written);
         }

         //Release previously allocated resources
         rsaFreePrivateKey(&privateKey);
      }
      else
#endif
#if (TLS_DHE_DSS_SUPPORT == ENABLED)
      //Check whether DHE_DSS key exchange method is currently used
      if(context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS)
      {
         Sha1Context *sha1Context;

         //Allocate a memory buffer to hold the SHA-1 context
         sha1Context = tlsAllocMem(sizeof(Sha1Context));

         //Successful memory allocation?
         if(sha1Context != NULL)
         {
            //Compute SHA(ClientHello.random + ServerHello.random + ServerDhParams)
            sha1Init(sha1Context);
            sha1Update(sha1Context, context->random, 64);
            sha1Update(sha1Context, params, paramsLen);
            sha1Final(sha1Context, context->serverVerifyData);

            //Release previously allocated memory
            tlsFreeMem(sha1Context);
         }
         else
         {
            //Failed to allocate memory
            error = ERROR_OUT_OF_MEMORY;
         }

         //Check status code
         if(!error)
         {
            //Sign the key exchange parameters using DSA
            error = tlsGenerateDsaSignature(context, context->serverVerifyData,
               SHA1_DIGEST_SIZE, signature->value, written);
         }
      }
      else
#endif
#if (TLS_ECDHE_ECDSA_SUPPORT == ENABLED)
      //Check whether ECDHE_ECDSA key exchange method is currently used
      if(context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
      {
         Sha1Context *sha1Context;

         //Allocate a memory buffer to hold the SHA-1 context
         sha1Context = tlsAllocMem(sizeof(Sha1Context));

         //Successful memory allocation?
         if(sha1Context != NULL)
         {
            //Compute SHA(ClientHello.random + ServerHello.random + ServerDhParams)
            sha1Init(sha1Context);
            sha1Update(sha1Context, context->random, 64);
            sha1Update(sha1Context, params, paramsLen);
            sha1Final(sha1Context, context->serverVerifyData);

            //Release previously allocated memory
            tlsFreeMem(sha1Context);
         }
         else
         {
            //Failed to allocate memory
            error = ERROR_OUT_OF_MEMORY;
         }

         //Check status code
         if(!error)
         {
            //Sign the key exchange parameters using ECDSA
            error = tlsGenerateEcdsaSignature(context, context->serverVerifyData,
               SHA1_DIGEST_SIZE, signature->value, written);
         }
      }
      else
#endif
      //Invalid signature algorithm?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }

      //Fix the length of the digitally-signed element
      signature->length = htons(*written);
      //Adjust the length of the signature
      *written += sizeof(TlsDigitalSignature);
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      TlsDigitalSignature2 *signature;
      const HashAlgo *hashAlgo;
      HashContext *hashContext;

      //Point to the digitally-signed element
      signature = (TlsDigitalSignature2 *) p;

      //Retrieve the hash algorithm used for signing
      hashAlgo = tlsGetHashAlgo(context->signHashAlgo);

      //Make sure the hash algorithm is supported
      if(hashAlgo != NULL)
      {
         //Allocate a memory buffer to hold the hash context
         hashContext = tlsAllocMem(hashAlgo->contextSize);

         //Successful memory allocation?
         if(hashContext != NULL)
         {
            //Compute SHA(ClientHello.random + ServerHello.random + ServerDhParams)
            hashAlgo->init(hashContext);
            hashAlgo->update(hashContext, context->random, 64);
            hashAlgo->update(hashContext, params, paramsLen);
            hashAlgo->final(hashContext, NULL);

#if (TLS_DHE_RSA_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED)
            //Check whether DHE_RSA or ECDHE_RSA key exchange method is currently used
            if(context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
               context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA)
            {
               RsaPrivateKey privateKey;

               //Initialize RSA private key
               rsaInitPrivateKey(&privateKey);

               //Set the relevant signature algorithm
               signature->algorithm.signature = TLS_SIGN_ALGO_RSA;
               signature->algorithm.hash = context->signHashAlgo;

               //Decode the PEM structure that holds the RSA private key
               error = pemReadRsaPrivateKey(context->cert->privateKey,
                  context->cert->privateKeyLength, &privateKey);

               //Check status code
               if(!error)
               {
                  //Use the signature algorithm defined in PKCS #1 v1.5
                  error = rsassaPkcs1v15Sign(&privateKey, hashAlgo,
                     hashContext->digest, signature->value, written);
               }

               //Release previously allocated resources
               rsaFreePrivateKey(&privateKey);
            }
            else
#endif
#if (TLS_DHE_DSS_SUPPORT == ENABLED)
            //Check whether DHE_DSS key exchange method is currently used
            if(context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS)
            {
               //Set the relevant signature algorithm
               signature->algorithm.signature = TLS_SIGN_ALGO_DSA;
               signature->algorithm.hash = context->signHashAlgo;

               //Sign the key exchange parameters using DSA
               error = tlsGenerateDsaSignature(context, hashContext->digest,
                  hashAlgo->digestSize, signature->value, written);
            }
            else
#endif
#if (TLS_ECDHE_ECDSA_SUPPORT == ENABLED)
            //Check whether ECDHE_ECDSA key exchange method is currently used
            if(context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
            {
               //Set the relevant signature algorithm
               signature->algorithm.signature = TLS_SIGN_ALGO_ECDSA;
               signature->algorithm.hash = context->signHashAlgo;

               //Sign the key exchange parameters using ECDSA
               error = tlsGenerateEcdsaSignature(context, hashContext->digest,
                  hashAlgo->digestSize, signature->value, written);
            }
            else
#endif
            //Invalid signature algorithm?
            {
               //Report an error
               error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
            }

            //Release previously allocated memory
            tlsFreeMem(hashContext);
         }
         else
         {
            //Failed to allocate memory
            error = ERROR_OUT_OF_MEMORY;
         }
      }
      else
      {
         //Hash algorithm not supported
         error = ERROR_INVALID_SIGNATURE;
      }

      //Fix the length of the digitally-signed element
      signature->length = htons(*written);
      //Adjust the length of the message
      *written += sizeof(TlsDigitalSignature2);
   }
   else
#endif
   {
      //The negotiated TLS version is not valid
      error = ERROR_INVALID_VERSION;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse PSK identity
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the PSK identity hint
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tlsParsePskIdentity(TlsContext *context,
   const uint8_t *p, size_t length, size_t *consumed)
{
   size_t n;
   TlsPskIdentity *pskIdentity;

   //Malformed ClientKeyExchange message?
   if(length < sizeof(TlsPskIdentity))
      return ERROR_DECODING_FAILED;

   //Point to the PSK identity
   pskIdentity = (TlsPskIdentity *) p;

   //Retrieve the length of the PSK identity
   n = ntohs(pskIdentity->length);

   //Make sure the length field is valid
   if(length < (sizeof(TlsPskIdentity) + n))
      return ERROR_DECODING_FAILED;

#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //Check whether the PSK identity has already been configured
   if(context->pskIdentity != NULL)
   {
      //Release memory
      tlsFreeMem(context->pskIdentity);
      context->pskIdentity = NULL;
   }

   //Valid PSK identity?
   if(n > 0)
   {
      //Allocate a memory block to hold the PSK identity
      context->pskIdentity = tlsAllocMem(n + 1);
      //Failed to allocate memory?
      if(context->pskIdentity == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Save the PSK identity
      memcpy(context->pskIdentity, pskIdentity->value, n);
      //Properly terminate the string
      context->pskIdentity[n] = '\0';
   }

   //Any registered callback?
   if(context->pskCallback != NULL)
   {
      error_t error;

      //Invoke user callback function
      if(context->pskIdentity != NULL)
         error = context->pskCallback(context, context->pskIdentity);
      else
         error = context->pskCallback(context, "");

      //Any error to report?
      if(error)
         return ERROR_UNKNOWN_IDENTITY;
   }
#endif

   //Total number of bytes that have been consumed
   *consumed = sizeof(TlsPskIdentity) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse client's key exchange parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the client's key exchange parameters
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tlsParseClientKeyParams(TlsContext *context,
   const uint8_t *p, size_t length, size_t *consumed)
{
   error_t error;

#if (TLS_RSA_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED)
   //RSA key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
   {
      size_t n;
      uint16_t version;
      RsaPrivateKey privateKey;

      //The RSA-encrypted premaster secret in a ClientKeyExchange is preceded by
      //two length bytes. SSL 3.0 implementations do not include these bytes
      if(context->version > SSL_VERSION_3_0)
      {
         //Malformed ClientKeyExchange message?
         if(length < 2)
            return ERROR_DECODING_FAILED;

         //Decode the length field
         n = LOAD16BE(p);

         //Check the length of the RSA-encrypted premaster secret
         if(n > (length - 2))
            return ERROR_DECODING_FAILED;

         //Save the length of the RSA-encrypted premaster secret
         length = n;
         //Advance the pointer over the length field
         p += 2;
         //Total number of bytes that have been consumed
         *consumed = length + 2;
      }
      else
      {
         //Total number of bytes that have been consumed
         *consumed = length;
      }

      //Initialize RSA private key
      rsaInitPrivateKey(&privateKey);

      //Decode the PEM structure that holds the RSA private key
      error = pemReadRsaPrivateKey(context->cert->privateKey,
         context->cert->privateKeyLength, &privateKey);

      //Check status code
      if(!error)
      {
         //Decrypt the premaster secret using the server private key
         error = rsaesPkcs1v15Decrypt(&privateKey, p, length, context->premasterSecret,
            TLS_MAX_PREMASTER_SECRET_SIZE, &context->premasterSecretLen);
      }

      //Release RSA private key
      rsaFreePrivateKey(&privateKey);

      //Retrieve the latest version supported by the client. This is used
      //to detect version roll-back attacks
      version = LOAD16BE(context->premasterSecret);

      //The best way to avoid vulnerability to the Bleichenbacher attack is to
      //treat incorrectly formatted messages in a manner indistinguishable from
      //correctly formatted RSA blocks
      if(error || context->premasterSecretLen != 48 || version != context->clientVersion)
      {
         //When it receives an incorrectly formatted RSA block, the server
         //should generate a random 48-byte value and proceed using it as
         //the premaster secret
         error = context->prngAlgo->read(context->prngContext, context->premasterSecret, 48);

         //Fix the length of the premaster secret
         context->premasterSecretLen = 48;
      }
   }
   else
#endif
#if (TLS_DH_ANON_SUPPORT == ENABLED || TLS_DHE_RSA_SUPPORT == ENABLED || \
   TLS_DHE_DSS_SUPPORT == ENABLED || TLS_DHE_PSK_SUPPORT == ENABLED)
   //Diffie-Hellman key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK)
   {
      size_t n;

      //Convert the client's public value to a multiple precision integer
      error = tlsReadMpi(&context->dhContext.yb, p, length, &n);

      //Check status code
      if(!error)
      {
         //Total number of bytes that have been consumed
         *consumed = n;

         //Verify client's public value
         error = dhCheckPublicKey(&context->dhContext.params, &context->dhContext.yb);
      }

      //Check status code
      if(!error)
      {
         //Calculate the negotiated key Z
         error = dhComputeSharedSecret(&context->dhContext, context->premasterSecret,
            TLS_MAX_PREMASTER_SECRET_SIZE, &context->premasterSecretLen);
      }

      //Check status code
      if(!error)
      {
         //Leading bytes of Z that contain all zero bits are stripped before
         //it is used as the premaster secret (RFC 4346, section 8.2.1)
         for(n = 0; n < context->premasterSecretLen; n++)
         {
            if(context->premasterSecret[n] != 0x00)
               break;
         }

         //Any leading zero bytes?
         if(n > 0)
         {
            //Strip leading zero bytes from the negotiated key
            memmove(context->premasterSecret, context->premasterSecret + n,
               context->premasterSecretLen - n);

            //Adjust the length of the premaster secret
            context->premasterSecretLen -= n;
         }
      }
   }
   else
#endif
#if (TLS_ECDH_ANON_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //ECDH key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      size_t n;

      //Decode client's public key
      error = tlsReadEcPoint(&context->ecdhContext.params,
         &context->ecdhContext.qb, p, length, &n);

      //Check status code
      if(!error)
      {
         //Total number of bytes that have been consumed
         *consumed = n;

         //Verify client's public key and make sure that it is on the same
         //elliptic curve as the server's ECDH key
         error = ecdhCheckPublicKey(&context->ecdhContext.params,
            &context->ecdhContext.qb);
      }

      //Check status code
      if(!error)
      {
         //Calculate the shared secret Z. Leading zeros found in this octet
         //string must not be truncated (see RFC 4492, section 5.10)
         error = ecdhComputeSharedSecret(&context->ecdhContext, context->premasterSecret,
            TLS_MAX_PREMASTER_SECRET_SIZE, &context->premasterSecretLen);
      }
   }
   else
#endif
   //Invalid key exchange method?
   {
      //The specified key exchange method is not supported
      error = ERROR_UNSUPPORTED_KEY_EXCH_METHOD;
   }

   //Return status code
   return error;
}


#endif
