/**
 * @file tls_client_misc.c
 * @brief Helper functions (TLS client)
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
#include "tls_client.h"
#include "tls_client_misc.h"
#include "tls_common.h"
#include "tls_record.h"
#include "tls_cache.h"
#include "tls_misc.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED && TLS_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Format PSK identity
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the PSK identity hint
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatPskIdentity(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n;
   TlsPskIdentity *pskIdentity;

   //Point to the PSK identity
   pskIdentity = (TlsPskIdentity *) p;

   //Initialize length field
   n = 0;

#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //Any registered callback?
   if(context->pskCallback != NULL)
   {
      error_t error;

      //Invoke user callback function
      if(context->pskIdentityHint != NULL)
         error = context->pskCallback(context, context->pskIdentityHint);
      else
         error = context->pskCallback(context, "");

      //Any error to report?
      if(error)
         return ERROR_UNKNOWN_IDENTITY;
   }

   //Any PSK identity defined?
   if(context->pskIdentity != NULL)
   {
      //Determine the length of the PSK identity
      n = strlen(context->pskIdentity);
      //Copy PSK identity
      memcpy(pskIdentity->value, context->pskIdentity, n);
   }
#endif

   //The PSK identity is preceded by a 2-byte length field
   pskIdentity->length = htons(n);

   //Total number of bytes that have been written
   *written = sizeof(TlsPskIdentity) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format client's key exchange parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the PSK identity hint
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientKeyParams(TlsContext *context,
   uint8_t *p, size_t *written)
{
#if (TLS_RSA_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED)
   //RSA key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
   {
      error_t error;
      size_t n;

      //Sanity check
      if(TLS_MAX_PREMASTER_SECRET_SIZE < 48)
         return ERROR_BUFFER_OVERFLOW;

      //If RSA is being used for key agreement and authentication, the
      //client generates a 48-byte premaster secret
      context->premasterSecretLen = 48;

      //The first 2 bytes code the latest version supported by the client
      STORE16BE(TLS_MAX_VERSION, context->premasterSecret);

      //The last 46 bytes contain securely-generated random bytes
      error = context->prngAlgo->read(context->prngContext,
         context->premasterSecret + 2, 46);
      //Any error to report?
      if(error)
         return error;

      //The RSA-encrypted premaster secret in a ClientKeyExchange is preceded by
      //two length bytes. SSL 3.0 implementations do not include these bytes
      if(context->version > SSL_VERSION_3_0)
      {
         //Encrypt the premaster secret using the server public key
         error = rsaesPkcs1v15Encrypt(context->prngAlgo, context->prngContext,
            &context->peerRsaPublicKey, context->premasterSecret, 48, p + 2, &n);
         //RSA encryption failed?
         if(error)
            return error;

         //Write the length field
         STORE16BE(n, p);

         //Length of the resulting octet string
         n += 2;
      }
      else
      {
         //Encrypt the premaster secret using the server public key
         error = rsaesPkcs1v15Encrypt(context->prngAlgo, context->prngContext,
            &context->peerRsaPublicKey, context->premasterSecret, 48, p, &n);
         //RSA encryption failed?
         if(error)
            return error;
      }

      //Total number of bytes that have been written
      *written = n;
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
      error_t error;
      size_t n;

      //Generate an ephemeral key pair
      error = dhGenerateKeyPair(&context->dhContext,
         context->prngAlgo, context->prngContext);
      //Any error to report?
      if(error)
         return error;

      //Encode the client's public value to an opaque vector
      error = tlsWriteMpi(&context->dhContext.ya, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Total number of bytes that have been written
      *written = n;

      //Calculate the negotiated key Z
      error = dhComputeSharedSecret(&context->dhContext, context->premasterSecret,
         TLS_MAX_PREMASTER_SECRET_SIZE, &context->premasterSecretLen);
      //Any error to report?
      if(error)
         return error;

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
      error_t error;
      size_t n;

#if (TLS_ECC_CALLBACK_SUPPORT == ENABLED)
      //Any registered callback?
      if(context->ecdhCallback != NULL)
      {
         //Invoke user callback function
         error = context->ecdhCallback(context);
      }
      else
#endif
      {
         //No callback function defined
         error = ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
      }

      //Check status code
      if(error == ERROR_UNSUPPORTED_ELLIPTIC_CURVE)
      {
         //Generate an ephemeral key pair
         error = ecdhGenerateKeyPair(&context->ecdhContext,
            context->prngAlgo, context->prngContext);
         //Any error to report?
         if(error)
            return error;

         //Calculate the negotiated key Z
         error = ecdhComputeSharedSecret(&context->ecdhContext, context->premasterSecret,
            TLS_MAX_PREMASTER_SECRET_SIZE, &context->premasterSecretLen);
         //Any error to report?
         if(error)
            return error;
      }
      else if(error != NO_ERROR)
      {
         //Report an error
         return error;
      }

      //Encode the client's public key to an opaque vector
      error = tlsWriteEcPoint(&context->ecdhContext.params,
         &context->ecdhContext.qa, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Total number of bytes that have been written
      *written = n;
   }
   else
#endif
   //Invalid key exchange method?
   {
      //The specified key exchange method is not supported
      return ERROR_UNSUPPORTED_KEY_EXCH_METHOD;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse PSK identity hint
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the PSK identity hint
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tlsParsePskIdentityHint(TlsContext *context,
   const uint8_t *p, size_t length, size_t *consumed)
{
   size_t n;
   TlsPskIdentityHint *pskIdentityHint;

   //Malformed ServerKeyExchange message?
   if(length < sizeof(TlsPskIdentityHint))
      return ERROR_DECODING_FAILED;

   //Point to the PSK identity hint
   pskIdentityHint = (TlsPskIdentityHint *) p;

   //Retrieve the length of the PSK identity hint
   n = ntohs(pskIdentityHint->length);

   //Make sure the length field is valid
   if(length < (sizeof(TlsPskIdentityHint) + n))
      return ERROR_DECODING_FAILED;

#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //Check whether the PSK identity hint has already been configured
   if(context->pskIdentityHint != NULL)
   {
      //Release memory
      tlsFreeMem(context->pskIdentityHint);
      context->pskIdentityHint = NULL;
   }

   //The PSK identity hint is optional
   if(n > 0)
   {
      //Allocate a memory block to hold the PSK identity hint
      context->pskIdentityHint = tlsAllocMem(n + 1);
      //Failed to allocate memory?
      if(context->pskIdentityHint == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Save the PSK identity hint
      memcpy(context->pskIdentityHint, pskIdentityHint->value, n);
      //Properly terminate the string
      context->pskIdentityHint[n] = '\0';
   }
#endif

   //Total number of bytes that have been consumed
   *consumed = sizeof(TlsPskIdentityHint) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse server's key exchange parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the server's key exchange parameters
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tlsParseServerKeyParams(TlsContext *context,
   const uint8_t *p, size_t length, size_t *consumed)
{
   error_t error;
   const uint8_t *params;

   //Initialize status code
   error = NO_ERROR;

   //Point to the server's key exchange parameters
   params = p;

#if (TLS_DH_ANON_SUPPORT == ENABLED || TLS_DHE_RSA_SUPPORT == ENABLED || \
   TLS_DHE_DSS_SUPPORT == ENABLED || TLS_DHE_PSK_SUPPORT == ENABLED)
   //Diffie-Hellman key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK)
   {
      uint_t k;
      size_t n;

      //Convert the prime modulus to a multiple precision integer
      error = tlsReadMpi(&context->dhContext.params.p, p, length, &n);

      //Check status code
      if(!error)
      {
         //Get the length of the prime modulus, in bits
         k = mpiGetBitLength(&context->dhContext.params.p);

         //Make sure the prime modulus is acceptable
         if(k < TLS_MIN_DH_MODULUS_SIZE || k > TLS_MAX_DH_MODULUS_SIZE)
            error = ERROR_ILLEGAL_PARAMETER;
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Remaining bytes to process
         length -= n;

         //Convert the generator to a multiple precision integer
         error = tlsReadMpi(&context->dhContext.params.g, p, length, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Remaining bytes to process
         length -= n;

         //Convert the server's public value to a multiple precision integer
         error = tlsReadMpi(&context->dhContext.yb, p, length, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Remaining bytes to process
         length -= n;

         //Verify peer's public value
         error = dhCheckPublicKey(&context->dhContext.params,
            &context->dhContext.yb);
      }

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
         TRACE_DEBUG_MPI("    ", &context->dhContext.yb);
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
      uint8_t curveType;
      uint16_t namedCurve;
      const EcCurveInfo *curveInfo;

      //Malformed ServerKeyExchange message?
      if(length < sizeof(curveType))
         error = ERROR_DECODING_FAILED;

      //Check status code
      if(!error)
      {
         //Retrieve the type of the elliptic curve domain parameters
         curveType = *p;

         //Advance data pointer
         p += sizeof(curveType);
         //Remaining bytes to process
         length -= sizeof(curveType);

         //Only named curves are supported
         if(curveType != TLS_EC_CURVE_TYPE_NAMED_CURVE)
            error = ERROR_ILLEGAL_PARAMETER;
      }

      //Check status code
      if(!error)
      {
         //Malformed ServerKeyExchange message?
         if(length < sizeof(namedCurve))
            error = ERROR_DECODING_FAILED;
      }

      //Check status code
      if(!error)
      {
         //Get elliptic curve identifier
         namedCurve = LOAD16BE(p);

         //Advance data pointer
         p += sizeof(namedCurve);
         //Remaining bytes to process
         length -= sizeof(namedCurve);

         //Retrieve the corresponding EC domain parameters
         curveInfo = tlsGetCurveInfo(namedCurve);

         //Make sure the elliptic curve is supported
         if(curveInfo == NULL)
            error = ERROR_ILLEGAL_PARAMETER;
      }

      //Check status code
      if(!error)
      {
         //Load EC domain parameters
         error = ecLoadDomainParameters(&context->ecdhContext.params,
            curveInfo);
      }

      //Check status code
      if(!error)
      {
         //Read server's public key
         error = tlsReadEcPoint(&context->ecdhContext.params,
            &context->ecdhContext.qb, p, length, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Remaining bytes to process
         length -= n;

         //Verify peer's public key
         error = ecdhCheckPublicKey(&context->ecdhContext.params, &context->ecdhContext.qb);
      }

      //Check status code
      if(!error)
      {
         //Debug message
         TRACE_DEBUG("  Server public key X:\r\n");
         TRACE_DEBUG_MPI("    ", &context->ecdhContext.qb.x);
         TRACE_DEBUG("  Server public key Y:\r\n");
         TRACE_DEBUG_MPI("    ", &context->ecdhContext.qb.y);
      }
   }
   else
#endif
   //Invalid key exchange method?
   {
      //It is not legal to send the ServerKeyExchange message when a key
      //exchange method other than DHE_DSS, DHE_RSA, DH_anon, ECDHE_RSA,
      //ECDHE_ECDSA or ECDH_anon is selected
      error = ERROR_UNEXPECTED_MESSAGE;
   }

   //Total number of bytes that have been consumed
   *consumed = p - params;

   //Return status code
   return error;
}


/**
 * @brief Verify signature over the server's key exchange parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the signature
 * @param[in] length Number of bytes available in the input stream
 * @param[in] params Pointer to the server's key exchange parameters
 * @param[in] paramsLen Length of the server's key exchange parameters
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tlsVerifyServerKeySignature(TlsContext *context, const uint8_t *p,
   size_t length, const uint8_t *params, size_t paramsLen, size_t *consumed)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //SSL 3.0, TLS 1.0 or TLS 1.1 currently selected?
   if(context->version <= TLS_VERSION_1_1)
   {
      TlsDigitalSignature *signature;

      //Point to the digitally-signed element
      signature = (TlsDigitalSignature *) p;

      //Check the length of the digitally-signed element
      if(length < sizeof(TlsDigitalSignature))
         return ERROR_DECODING_FAILED;
      if(length < (sizeof(TlsDigitalSignature) + ntohs(signature->length)))
         return ERROR_DECODING_FAILED;

#if (TLS_DHE_RSA_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED)
      //Check whether DHE_RSA or ECDHE_RSA key exchange method is currently used
      if(context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA)
      {
         Md5Context *md5Context;
         Sha1Context *sha1Context;

         //Allocate a memory buffer to hold the MD5 context
         md5Context = tlsAllocMem(sizeof(Md5Context));

         //Successful memory allocation?
         if(md5Context != NULL)
         {
            //Compute MD5(ClientHello.random + ServerHello.random + ServerDhParams)
            md5Init(md5Context);
            md5Update(md5Context, context->random, 64);
            md5Update(md5Context, params, paramsLen);
            md5Final(md5Context, context->verifyData);

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
               sha1Final(sha1Context, context->verifyData + MD5_DIGEST_SIZE);

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
            //RSA signature verification
            error = tlsVerifyRsaSignature(&context->peerRsaPublicKey,
               context->verifyData, signature->value, ntohs(signature->length));
         }
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
            sha1Final(sha1Context, context->verifyData);

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
            //DSA signature verification
            error = tlsVerifyDsaSignature(context, context->verifyData,
               SHA1_DIGEST_SIZE, signature->value, ntohs(signature->length));
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
            sha1Final(sha1Context, context->verifyData);

            //Release previously allocated memory
            tlsFreeMem(sha1Context);
         }

         //Check status code
         if(!error)
         {
            //ECDSA signature verification
            error = tlsVerifyEcdsaSignature(context, context->verifyData,
               SHA1_DIGEST_SIZE, signature->value, ntohs(signature->length));
         }
      }
      else
#endif
      //Invalid signature algorithm?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }

      //Total number of bytes that have been consumed
      *consumed = sizeof(TlsDigitalSignature) + ntohs(signature->length);
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

      //Check the length of the digitally-signed element
      if(length < sizeof(TlsDigitalSignature2))
         return ERROR_DECODING_FAILED;
      if(length < (sizeof(TlsDigitalSignature2) + ntohs(signature->length)))
         return ERROR_DECODING_FAILED;

      //Retrieve the hash algorithm used for signing
      hashAlgo = tlsGetHashAlgo(signature->algorithm.hash);

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
            if((context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
               context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA) &&
               signature->algorithm.signature == TLS_SIGN_ALGO_RSA)
            {
               //Use the signature verification algorithm defined in PKCS #1 v1.5
               error = rsassaPkcs1v15Verify(&context->peerRsaPublicKey, hashAlgo,
                  hashContext->digest, signature->value, ntohs(signature->length));
            }
            else
#endif
#if (TLS_DHE_DSS_SUPPORT == ENABLED)
            //Check whether DHE_DSS key exchange method is currently used
            if(context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS &&
               signature->algorithm.signature == TLS_SIGN_ALGO_DSA)
            {
               //DSA signature verification
               error = tlsVerifyDsaSignature(context, hashContext->digest,
                  hashAlgo->digestSize, signature->value, ntohs(signature->length));
            }
            else
#endif
#if (TLS_ECDHE_ECDSA_SUPPORT == ENABLED)
            //Check whether DHE_ECDSA key exchange method is currently used
            if(context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA &&
               signature->algorithm.signature == TLS_SIGN_ALGO_ECDSA)
            {
               //ECDSA signature verification
               error = tlsVerifyEcdsaSignature(context, hashContext->digest,
                  hashAlgo->digestSize, signature->value, ntohs(signature->length));
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

      //Total number of bytes that have been consumed
      *consumed = sizeof(TlsDigitalSignature2) + ntohs(signature->length);
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

#endif
