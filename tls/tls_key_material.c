/**
 * @file tls_key_material.c
 * @brief Key material generation
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2026 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.6.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include "tls/tls.h"
#include "tls/tls_key_material.h"
#include "tls/tls_transcript_hash.h"
#include "kdf/tls_kdf.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Generate session keys
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsGenerateSessionKeys(TlsContext *context)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   error_t error;
   size_t keyBlockLen;
   TlsCipherSuiteInfo *cipherSuite;

   //Point to the negotiated cipher suite
   cipherSuite = &context->cipherSuite;

   //Length of necessary key material
   keyBlockLen = 2 * (cipherSuite->macKeyLen + cipherSuite->encKeyLen +
      cipherSuite->fixedIvLen);

   //Make sure that the key block is large enough
   if(keyBlockLen > sizeof(context->keyBlock))
      return ERROR_FAILURE;

   //Debug message
   TRACE_DEBUG("Generating session keys...\r\n");
   TRACE_DEBUG("  Client random bytes:\r\n");
   TRACE_DEBUG_ARRAY("    ", context->clientRandom, 32);
   TRACE_DEBUG("  Server random bytes:\r\n");
   TRACE_DEBUG_ARRAY("    ", context->serverRandom, 32);

   //If a full handshake is being performed, the premaster secret shall be
   //first converted to the master secret
   if(!context->resume)
   {
      //Debug message
      TRACE_DEBUG("  Premaster secret:\r\n");
      TRACE_DEBUG_ARRAY("    ", context->premasterSecret, context->premasterSecretLen);

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
      //If both the ClientHello and ServerHello contain the ExtendedMasterSecret
      //extension, the new session uses the extended master secret computation
      if(context->emsExtReceived)
      {
         //Extended master secret computation
         error = tlsGenerateExtendedMasterSecret(context);
      }
      else
#endif
      {
         //Legacy master secret computation
         error = tlsGenerateMasterSecret(context);
      }

      //Failed to generate master secret?
      if(error)
         return error;

      //The premaster secret should be deleted from memory once the master
      //secret has been computed
      cryptoZeroizeMem(context->premasterSecret, TLS_PREMASTER_SECRET_SIZE);
   }

   //Debug message
   TRACE_DEBUG("  Master secret:\r\n");
   TRACE_DEBUG_ARRAY("    ", context->masterSecret, TLS_MASTER_SECRET_SIZE);

#if (TLS_KEY_LOG_SUPPORT == ENABLED)
   //Log master secret
   tlsDumpSecret(context, "CLIENT_RANDOM", context->masterSecret,
      TLS_MASTER_SECRET_SIZE);
#endif

   //The master secret is used as an entropy source to generate the key material
   error = tlsGenerateKeyBlock(context, keyBlockLen);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("  Key block:\r\n");
   TRACE_DEBUG_ARRAY("    ", context->keyBlock, keyBlockLen);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Master secret computation
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

__weak_func error_t tlsGenerateMasterSecret(TlsContext *context)
{
   error_t error;
   uint8_t random[2 * TLS_RANDOM_SIZE];

   //Concatenate client_random and server_random values
   osMemcpy(random, context->clientRandom, TLS_RANDOM_SIZE);
   osMemcpy(random + 32, context->serverRandom, TLS_RANDOM_SIZE);

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //TLS 1.0 or TLS 1.1 currently selected?
   if(context->version == TLS_VERSION_1_0 || context->version == TLS_VERSION_1_1)
   {
      //TLS 1.0 and 1.1 use a PRF that combines MD5 and SHA-1
      error = tlsPrf(context->premasterSecret, context->premasterSecretLen,
         "master secret", random, sizeof(random), context->masterSecret,
         TLS_MASTER_SECRET_SIZE);
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      //TLS 1.2 PRF uses SHA-256 or a stronger hash algorithm as the core
      //function in its construction
      error = tls12Prf(context->cipherSuite.prfHashAlgo,
         context->premasterSecret, context->premasterSecretLen,
         "master secret", random, sizeof(random), context->masterSecret,
         TLS_MASTER_SECRET_SIZE);
   }
   else
#endif
   //Invalid TLS version?
   {
      //Report an error
      error = ERROR_INVALID_VERSION;
   }

   //Return status code
   return error;
}


/**
 * @brief Extended master secret computation
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsGenerateExtendedMasterSecret(TlsContext *context)
{
#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   error_t error;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //TLS 1.0 or TLS 1.1 currently selected?
   if(context->version == TLS_VERSION_1_0 || context->version == TLS_VERSION_1_1)
   {
      //A temporary buffer is needed to concatenate MD5 and SHA-1 hash
      //values before computing the extended master secret
      uint8_t sessionHash[MD5_DIGEST_SIZE + SHA1_DIGEST_SIZE];

      //Finalize MD5 hash computation
      error = tlsFinalizeTranscriptHash(context, MD5_HASH_ALGO,
         context->transcriptMd5Context, sessionHash);

      //Check status code
      if(!error)
      {
         //Finalize SHA-1 hash computation
         error = tlsFinalizeTranscriptHash(context, SHA1_HASH_ALGO,
            context->transcriptSha1Context, sessionHash + MD5_DIGEST_SIZE);
      }

      //Check status code
      if(!error)
      {
         //Compute the extended master secret (refer to RFC 7627, section 4)
         error = tlsPrf(context->premasterSecret, context->premasterSecretLen,
            "extended master secret", sessionHash, sizeof(sessionHash),
            context->masterSecret, TLS_MASTER_SECRET_SIZE);
      }
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      const HashAlgo *hashAlgo;
      HashContext *hashContext;
      uint8_t digest[MAX_HASH_DIGEST_SIZE];

      //Point to the hash algorithm to be used
      hashAlgo = context->cipherSuite.prfHashAlgo;

      //Allocate hash algorithm context
      hashContext = tlsAllocMem(hashAlgo->contextSize);

      //Successful memory allocation?
      if(hashContext != NULL)
      {
         //The original hash context must be preserved
         osMemcpy(hashContext, context->transcriptHashContext,
            hashAlgo->contextSize);

         //Finalize hash computation
         hashAlgo->final(hashContext, digest);

         //Compute the extended master secret (refer to RFC 7627, section 4)
         error = tls12Prf(hashAlgo, context->premasterSecret,
            context->premasterSecretLen, "extended master secret",
            digest, hashAlgo->digestSize, context->masterSecret,
            TLS_MASTER_SECRET_SIZE);

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
#endif
   //Invalid TLS version?
   {
      //Report an error
      error = ERROR_INVALID_VERSION;
   }

   //Return status code
   return error;
#else
   //Extended master secret computation is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Premaster secret generation (for PSK cipher suites)
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsGeneratePskPremasterSecret(TlsContext *context)
{
   error_t error;

#if (TLS_PSK_KE_SUPPORT == ENABLED)
   //PSK key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK)
   {
      size_t n;

      //Let N be the length of pre-shared key
      n = context->pskLen;

      //Check whether the output buffer is large enough to hold the premaster
      //secret
      if((n * 2 + 4) <= TLS_PREMASTER_SECRET_SIZE)
      {
         //The premaster secret is formed as follows: if the PSK is N octets
         //long, concatenate a uint16 with the value N, N zero octets, a second
         //uint16 with the value N, and the PSK itself
         STORE16BE(n, context->premasterSecret);
         osMemset(context->premasterSecret + 2, 0, n);
         STORE16BE(n, context->premasterSecret + n + 2);
         osMemcpy(context->premasterSecret + n + 4, context->psk, n);

         //Save the length of the premaster secret
         context->premasterSecretLen = n * 2 + 4;

         //Premaster secret successfully generated
         error = NO_ERROR;
      }
      else
      {
         //Report an error
         error = ERROR_BUFFER_OVERFLOW;
      }
   }
   else
#endif
#if (TLS_RSA_PSK_KE_SUPPORT == ENABLED || TLS_DHE_PSK_KE_SUPPORT == ENABLED || \
   TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
   //RSA_PSK, DHE_PSK or ECDHE_PSK key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      size_t n;

      //Let N be the length of pre-shared key
      n = context->pskLen;

      //Check whether the output buffer is large enough to hold the premaster
      //secret
      if((context->premasterSecretLen + n + 4) <= TLS_PREMASTER_SECRET_SIZE)
      {
         //The "other_secret" field comes from the Diffie-Hellman, ECDH or
         //RSA exchange (DHE_PSK, ECDH_PSK and RSA_PSK, respectively)
         osMemmove(context->premasterSecret + 2, context->premasterSecret,
            context->premasterSecretLen);

         //The "other_secret" field is preceded by a 2-byte length field
         STORE16BE(context->premasterSecretLen, context->premasterSecret);

         //if the PSK is N octets long, concatenate a uint16 with the value N
         STORE16BE(n, context->premasterSecret + context->premasterSecretLen + 2);

         //Concatenate the PSK itself
         osMemcpy(context->premasterSecret + context->premasterSecretLen + 4,
            context->psk, n);

         //Adjust the length of the premaster secret
         context->premasterSecretLen += n + 4;

         //Premaster secret successfully generated
         error = NO_ERROR;
      }
      else
      {
         //Report an error
         error = ERROR_BUFFER_OVERFLOW;
      }
   }
   else
#endif
   //Invalid key exchange method?
   {
      //The specified key exchange method is not supported
      error = ERROR_UNSUPPORTED_KEY_EXCH_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Key expansion function
 * @param[in] context Pointer to the TLS context
 * @param[in] keyBlockLen Desired length for the resulting key block
 * @return Error code
 **/

__weak_func error_t tlsGenerateKeyBlock(TlsContext *context, size_t keyBlockLen)
{
   error_t error;
   uint8_t random[2 * TLS_RANDOM_SIZE];

   //Concatenate server_random and client_random values
   osMemcpy(random, context->serverRandom, TLS_RANDOM_SIZE);
   osMemcpy(random + 32, context->clientRandom, TLS_RANDOM_SIZE);

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //TLS 1.0 or TLS 1.1 currently selected?
   if(context->version == TLS_VERSION_1_0 || context->version == TLS_VERSION_1_1)
   {
      //TLS 1.0 and 1.1 use a PRF that combines MD5 and SHA-1
      error = tlsPrf(context->masterSecret, TLS_MASTER_SECRET_SIZE,
         "key expansion", random, sizeof(random), context->keyBlock,
         keyBlockLen);
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      //TLS 1.2 PRF uses SHA-256 or a stronger hash algorithm as the core
      //function in its construction
      error = tls12Prf(context->cipherSuite.prfHashAlgo,
         context->masterSecret, TLS_MASTER_SECRET_SIZE, "key expansion",
         random, sizeof(random), context->keyBlock, keyBlockLen);
   }
   else
#endif
   //Invalid TLS version?
   {
      //Report an error
      error = ERROR_INVALID_VERSION;
   }

   //Return status code
   return error;
}


/**
 * @brief Dump secret key (for debugging purpose only)
 * @param[in] context Pointer to the TLS context
 * @param[in] label Identifying label (NULL-terminated string)
 * @param[in] secret Pointer to the secret key
 * @param[in] secretLen Length of the secret key, in bytes
 **/

void tlsDumpSecret(TlsContext *context, const char_t *label,
   const uint8_t *secret, size_t secretLen)
{
#if (TLS_KEY_LOG_SUPPORT == ENABLED)
   //Any registered callback?
   if(context->keyLogCallback != NULL)
   {
      size_t i;
      size_t n;
      char_t buffer[194];

      //Retrieve the length of the label
      n = osStrlen(label);

      //Sanity check
      if((n + 2 * secretLen + 67) <= sizeof(buffer))
      {
         //Copy the identifying label
         osStrncpy(buffer, label, n);

         //Append a space character
         buffer[n++] = ' ';

         //Convert the client random value to a hex string
         for(i = 0; i < 32; i++)
         {
            //Format current byte
            n += osSprintf(buffer + n, "%02" PRIX8, context->clientRandom[i]);
         }

         //Append a space character
         buffer[n++] = ' ';

         //Convert the secret key to a hex string
         for(i = 0; i < secretLen; i++)
         {
            //Format current byte
            n += osSprintf(buffer + n, "%02" PRIX8, secret[i]);
         }

         //Properly terminate the string with a NULL character
         buffer[n] = '\0';

         //Invoke user callback function
         context->keyLogCallback(context, buffer);
      }
   }
#endif
}

#endif
