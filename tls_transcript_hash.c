/**
 * @file tls_transcript_hash.c
 * @brief Transcript hash calculation
 *
 * @section License
 *
 * Copyright (C) 2010-2018 Oryx Embedded SARL. All rights reserved.
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
 * @version 1.9.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include <string.h>
#include "tls.h"
#include "tls_client.h"
#include "tls_key_material.h"
#include "tls_transcript_hash.h"
#include "tls13_key_material.h"
#include "ssl_misc.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Initialize handshake message hashing
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsInitTranscriptHash(TlsContext *context)
{
#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //MD5 context already instantiated?
   if(context->handshakeMd5Context != NULL)
   {
      tlsFreeMem(context->handshakeMd5Context);
      context->handshakeMd5Context = NULL;
   }
#endif

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //SHA-1 context already instantiated?
   if(context->handshakeSha1Context != NULL)
   {
      tlsFreeMem(context->handshakeSha1Context);
      context->handshakeSha1Context = NULL;
   }
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //Hash algorithm context already instantiated?
   if(context->handshakeHashContext != NULL)
   {
      tlsFreeMem(context->handshakeHashContext);
      context->handshakeHashContext = NULL;
   }
#endif

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //SSL 3.0, TLS 1.0 or TLS 1.1 currently selected?
   if(context->version <= TLS_VERSION_1_1)
   {
      //Allocate MD5 context
      context->handshakeMd5Context = tlsAllocMem(sizeof(Md5Context));
      //Failed to allocate memory?
      if(context->handshakeMd5Context == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Initialize MD5 context
      md5Init(context->handshakeMd5Context);
   }
#endif

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //SSL 3.0, TLS 1.0, TLS 1.1 or TLS 1.2 currently selected?
   if(context->version <= TLS_VERSION_1_2)
   {
      //Allocate SHA-1 context
      context->handshakeSha1Context = tlsAllocMem(sizeof(Sha1Context));
      //Failed to allocate memory?
      if(context->handshakeSha1Context == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Initialize SHA-1 context
      sha1Init(context->handshakeSha1Context);
   }
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.2 or 1.3 currently selected?
   if(context->version >= TLS_VERSION_1_2)
   {
      const HashAlgo *hashAlgo;

      //Point to the hash algorithm to be used
      hashAlgo = context->cipherSuite.prfHashAlgo;
      //Make sure the hash algorithm is valid
      if(hashAlgo == NULL)
         return ERROR_FAILURE;

      //Allocate hash algorithm context
      context->handshakeHashContext = tlsAllocMem(hashAlgo->contextSize);
      //Failed to allocate memory?
      if(context->handshakeHashContext == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Initialize the hash algorithm context
      hashAlgo->init(context->handshakeHashContext);
   }
#endif

#if (TLS_CLIENT_SUPPORT == ENABLED)
   //TLS operates as a client?
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
#if (DTLS_SUPPORT == ENABLED)
      //DTLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
      {
         size_t length;
         DtlsRecord *record;

         //Point to the DTLS record that holds the ClientHello message
         record = (DtlsRecord *) context->txBuffer;

         //Sanity check
         if(context->txBufferLen > sizeof(DtlsRecord))
         {
            //Retrieve the length of the handshake message
            length = context->txBufferLen - sizeof(DtlsRecord);

            //Update the hash value with the ClientHello message
            tlsUpdateTranscriptHash(context, record->data, length);
         }
      }
      else
#endif
      //TLS protocol?
      {
         size_t length;
         TlsRecord *record;

         //Point to the TLS record that holds the ClientHello message
         record = (TlsRecord *) context->txBuffer;

         //Retrieve the length of the handshake message
         length = ntohs(record->length);

         //Sanity check
         if((length + sizeof(TlsRecord)) <= context->txBufferSize)
         {
            //Update the hash value with the ClientHello message
            tlsUpdateTranscriptHash(context, record->data, length);
         }
      }
   }
#endif

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Update hash value with a handshake message
 * @param[in] context Pointer to the TLS context
 * @param[in] data Pointer to the handshake message being hashed
 * @param[in] length Length of the message
 **/

void tlsUpdateTranscriptHash(TlsContext *context, const void *data,
   size_t length)
{
#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //SSL 3.0, TLS 1.0 or TLS 1.1 currently selected?
   if(context->version <= TLS_VERSION_1_1)
   {
      //Valid MD5 context?
      if(context->handshakeMd5Context != NULL)
      {
         //Update MD5 hash value with message contents
         md5Update(context->handshakeMd5Context, data, length);
      }
   }
#endif

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //SSL 3.0, TLS 1.0, TLS 1.1 or TLS 1.2 currently selected?
   if(context->version <= TLS_VERSION_1_2)
   {
      //Valid SHA-1 context?
      if(context->handshakeSha1Context != NULL)
      {
         //Update SHA-1 hash value with message contents
         sha1Update(context->handshakeSha1Context, data, length);
      }
   }
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.2 or TLS 1.3 currently selected?
   if(context->version >= TLS_VERSION_1_2)
   {
      const HashAlgo *hashAlgo;

      //Point to the PRF hash algorithm to be used
      hashAlgo = context->cipherSuite.prfHashAlgo;

      //Valid hash algorithm?
      if(hashAlgo != NULL && context->handshakeHashContext != NULL)
      {
         //Update hash value with message contents
         hashAlgo->update(context->handshakeHashContext, data, length);
      }
   }
#endif
}


/**
 * @brief Finalize hash calculation from previous handshake messages
 * @param[in] context Pointer to the TLS context
 * @param[in] hash Hash function used to digest the handshake messages
 * @param[in] hashContext Pointer to the hash context
 * @param[in] label NULL-terminated string
 * @param[out] output Buffer where to store the resulting hash value
 * @return Error code
 **/

error_t tlsFinalizeTranscriptHash(TlsContext *context, const HashAlgo *hash,
   const void *hashContext, const char_t *label, uint8_t *output)
{
   error_t error;
   HashContext *tempHashContext;

   //Make sure the hash context is valid
   if(hash == NULL || hashContext == NULL)
      return ERROR_INVALID_PARAMETER;

   //Allocate a temporary hash context
   tempHashContext = tlsAllocMem(hash->contextSize);

   //Successful memory allocation?
   if(tempHashContext != NULL)
   {
      //The original hash context must be preserved
      memcpy(tempHashContext, hashContext, hash->contextSize);

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= SSL_VERSION_3_0)
      //SSL 3.0 currently selected?
      if(context->version == SSL_VERSION_3_0)
      {
         size_t labelLen;
         size_t padLen;

         //Retrieve the length of the label
         labelLen = strlen(label);

         //The pad character is repeated 48 times for MD5 or 40 times for SHA-1
         padLen = (hash == MD5_HASH_ALGO) ? 48 : 40;

         //hash(handshakeMessages + label + masterSecret + pad1)
         hash->update(tempHashContext, label, labelLen);
         hash->update(tempHashContext, context->masterSecret, TLS_MASTER_SECRET_SIZE);
         hash->update(tempHashContext, sslPad1, padLen);
         hash->final(tempHashContext, output);

         //hash(masterSecret + pad2 + hash(handshakeMessages + label +
         //masterSecret + pad1))
         hash->init(tempHashContext);
         hash->update(tempHashContext, context->masterSecret, TLS_MASTER_SECRET_SIZE);
         hash->update(tempHashContext, sslPad2, padLen);
         hash->update(tempHashContext, output, hash->digestSize);
         hash->final(tempHashContext, output);

         //Successful processing
         error = NO_ERROR;
      }
      else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //TLS 1.0, TLS 1.1, TLS 1.2 or TLS 1.3 currently selected?
      if(context->version >= TLS_VERSION_1_0 && context->version <= TLS_VERSION_1_3)
      {
         //Compute hash(handshakeMessages)
         hash->final(tempHashContext, output);
         //Successful processing
         error = NO_ERROR;
      }
      else
#endif
      //Invalid TLS version?
      {
         //Report an error
         error = ERROR_INVALID_VERSION;
      }

      //Release previously allocated resources
      tlsFreeMem(tempHashContext);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
}


/**
 * @brief Release transcript hash context
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

void tlsFreeTranscriptHash(TlsContext *context)
{
#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //Release MD5 hash context
   if(context->handshakeMd5Context != NULL)
   {
      memset(context->handshakeMd5Context, 0, sizeof(Md5Context));
      tlsFreeMem(context->handshakeMd5Context);
      context->handshakeMd5Context = NULL;
   }
#endif

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Release SHA-1 hash context
   if(context->handshakeSha1Context != NULL)
   {
      memset(context->handshakeSha1Context, 0, sizeof(Sha1Context));
      tlsFreeMem(context->handshakeSha1Context);
      context->handshakeSha1Context = NULL;
   }
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //Release transcript hash context
   if(context->handshakeHashContext != NULL)
   {
      tlsFreeMem(context->handshakeHashContext);
      context->handshakeHashContext = NULL;
   }
#endif
}


/**
 * @brief Compute verify data from previous handshake messages
 * @param[in] context Pointer to the TLS context
 * @param[in] entity Specifies whether the computation is performed at client
 *   or server side
 * @param[out] verifyData Pointer to the buffer where to store the verify data
 * @param[out] verifyDataLen Length of the verify data
 * @return Error code
 **/

error_t tlsComputeVerifyData(TlsContext *context, TlsConnectionEnd entity,
   uint8_t *verifyData, size_t *verifyDataLen)
{
   error_t error;

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= SSL_VERSION_3_0)
   //SSL 3.0 currently selected?
   if(context->version == SSL_VERSION_3_0)
   {
      const char_t *label;

      //Check whether the computation is performed at client or server side
      if(entity == TLS_CONNECTION_END_CLIENT)
         label = "CLNT";
      else
         label = "SRVR";

      //Compute MD5(masterSecret + pad2 + MD5(handshakeMessages + label +
      //masterSecret + pad1))
      error = tlsFinalizeTranscriptHash(context, MD5_HASH_ALGO,
         context->handshakeMd5Context, label, verifyData);

      //Check status code
      if(!error)
      {
         //Compute SHA(masterSecret + pad2 + SHA(handshakeMessages + label +
         //masterSecret + pad1))
         error = tlsFinalizeTranscriptHash(context, SHA1_HASH_ALGO,
            context->handshakeSha1Context, label, verifyData + MD5_DIGEST_SIZE);
      }
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //TLS 1.0 or 1.1 currently selected?
   if(context->version == TLS_VERSION_1_0 || context->version == TLS_VERSION_1_1)
   {
      const char_t *label;
      uint8_t digest[MD5_DIGEST_SIZE + SHA1_DIGEST_SIZE];

      //Finalize MD5 hash computation
      error = tlsFinalizeTranscriptHash(context, MD5_HASH_ALGO,
         context->handshakeMd5Context, "", digest);

      //Check status code
      if(!error)
      {
         //Finalize SHA-1 hash computation
         error = tlsFinalizeTranscriptHash(context, SHA1_HASH_ALGO,
            context->handshakeSha1Context, "", digest + MD5_DIGEST_SIZE);
      }

      //Check status code
      if(!error)
      {
         //Check whether the computation is performed at client or server side
         if(entity == TLS_CONNECTION_END_CLIENT)
            label = "client finished";
         else
            label = "server finished";

         //The verify data is always 12-byte long for TLS 1.0 and 1.1
         error = tlsPrf(context->masterSecret, TLS_MASTER_SECRET_SIZE,
            label, digest, sizeof(digest), verifyData, 12);
      }
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      const char_t *label;
      const HashAlgo *hashAlgo;
      HashContext *hashContext;

      //Point to the hash algorithm to be used
      hashAlgo = context->cipherSuite.prfHashAlgo;

      //Valid hash algorithm?
      if(hashAlgo != NULL && context->handshakeHashContext != NULL)
      {
         //Allocate hash algorithm context
         hashContext = tlsAllocMem(hashAlgo->contextSize);

         //Successful memory allocation?
         if(hashContext != NULL)
         {
            //The original hash context must be preserved
            memcpy(hashContext, context->handshakeHashContext,
               hashAlgo->contextSize);

            //Finalize hash computation
            hashAlgo->final(hashContext, NULL);

            //Check whether the computation is performed at client or server side
            if(entity == TLS_CONNECTION_END_CLIENT)
               label = "client finished";
            else
               label = "server finished";

            //Compute the verify data
            error = tls12Prf(hashAlgo, context->masterSecret, TLS_MASTER_SECRET_SIZE,
               label, hashContext->digest, hashAlgo->digestSize,
               verifyData, context->cipherSuite.verifyDataLen);

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
         //Invalid hash algorithm
         error = ERROR_FAILURE;
      }
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      uint8_t *baseKey;
      const HashAlgo *hashAlgo;
      uint8_t digest[TLS_MAX_HKDF_DIGEST_SIZE];
      uint8_t finishedKey[TLS_MAX_HKDF_DIGEST_SIZE];

      //The hash function used by HKDF is the cipher suite hash algorithm
      hashAlgo = context->cipherSuite.prfHashAlgo;

      //Valid hash algorithm?
      if(hashAlgo != NULL && context->handshakeHashContext != NULL)
      {
         //Check whether the computation is performed at client or server side
         if(entity == TLS_CONNECTION_END_CLIENT)
            baseKey = context->clientHsTrafficSecret;
         else
            baseKey = context->serverHsTrafficSecret;

         //The key used to compute the Finished message is computed from the
         //base key using HKDF
         error = tls13HkdfExpandLabel(hashAlgo, baseKey, hashAlgo->digestSize,
            "finished", NULL, 0, finishedKey, hashAlgo->digestSize);

         //Check status code
         if(!error)
         {
            //Compute the transcript hash
            error = tlsFinalizeTranscriptHash(context, hashAlgo,
               context->handshakeHashContext, "", digest);
         }

         //Check status code
         if(!error)
         {
            //Compute the verify data
            error = hmacCompute(hashAlgo, finishedKey, hashAlgo->digestSize,
               digest, hashAlgo->digestSize, verifyData);
         }
      }
      else
      {
         //Invalid hash algorithm
         error = ERROR_FAILURE;
      }
   }
   else
#endif
   //Invalid TLS version?
   {
      //Report an error
      error = ERROR_INVALID_VERSION;
   }

   //Check status code
   if(!error)
   {
      //Save the length of the verify data
      *verifyDataLen = context->cipherSuite.verifyDataLen;

      //Debug message
      TRACE_DEBUG("Verify data:\r\n");
      TRACE_DEBUG_ARRAY("  ", verifyData, *verifyDataLen);
   }

   //Return status code
   return error;
}

#endif
