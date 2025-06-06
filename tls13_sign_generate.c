/**
 * @file tls13_sign_generate.c
 * @brief RSA/DSA/ECDSA/SM2/EdDSA signature generation (TLS 1.3)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2025 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include "tls.h"
#include "tls_sign_generate.h"
#include "tls_transcript_hash.h"
#include "tls_misc.h"
#include "tls13_sign_generate.h"
#include "pkix/pem_key_import.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_MAX_VERSION >= TLS_VERSION_1_3)


/**
 * @brief Digital signature generation (TLS 1.3)
 * @param[in] context Pointer to the TLS context
 * @param[out] p Buffer where to store the digitally-signed element
 * @param[out] length Length of the digitally-signed element
 * @return Error code
 **/

error_t tls13GenerateSignature(TlsContext *context, uint8_t *p,
   size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *buffer;
   Tls13DigitalSignature *signature;
   const HashAlgo *hashAlgo;

   //Point to the digitally-signed element
   signature = (Tls13DigitalSignature *) p;
   //The algorithm field specifies the signature scheme
   signature->algorithm = htons(context->signScheme);

   //The hash function used by HKDF is the cipher suite hash algorithm
   hashAlgo = context->cipherSuite.prfHashAlgo;
   //Make sure the hash algorithm is valid
   if(hashAlgo == NULL)
      return ERROR_FAILURE;

   //Calculate the length of the content covered by the digital signature
   n = hashAlgo->digestSize + 98;

   //Allocate a memory buffer
   buffer = tlsAllocMem(n);

   //Successful memory allocation?
   if(buffer != NULL)
   {
      //Form a string that consists of octet 32 (0x20) repeated 64 times
      osMemset(buffer, ' ', 64);

      //Append the context string. It is used to provide separation between
      //signatures made in different contexts, helping against potential
      //cross-protocol attacks
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         osMemcpy(buffer + 64, "TLS 1.3, client CertificateVerify", 33);
      }
      else
      {
         osMemcpy(buffer + 64, "TLS 1.3, server CertificateVerify", 33);
      }

      //Append a single 0 byte which serves as the separator
      buffer[97] = 0x00;

      //Compute the transcript hash
      error = tlsFinalizeTranscriptHash(context, hashAlgo,
         context->transcriptHashContext, "", buffer + 98);

      //Check status code
      if(!error)
      {
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
         //RSA-PSS signature scheme?
         if(context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA256 ||
            context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA384 ||
            context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA512 ||
            context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA256 ||
            context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA384 ||
            context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA512)
         {
            //Generate an RSA-PSS signature
            error = tls13GenerateRsaPssSignature(context, buffer, n, signature);
         }
         else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
         //ECDSA signature scheme?
         if(context->signScheme == TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256 ||
            context->signScheme == TLS_SIGN_SCHEME_ECDSA_SECP384R1_SHA384 ||
            context->signScheme == TLS_SIGN_SCHEME_ECDSA_SECP521R1_SHA512 ||
            context->signScheme == TLS_SIGN_SCHEME_ECDSA_BP256R1_TLS13_SHA256 ||
            context->signScheme == TLS_SIGN_SCHEME_ECDSA_BP384R1_TLS13_SHA384 ||
            context->signScheme == TLS_SIGN_SCHEME_ECDSA_BP512R1_TLS13_SHA512)
         {
            //Generate an ECDSA signature
            error = tls13GenerateEcdsaSignature(context, buffer, n, signature);
         }
         else
#endif
#if (TLS_SM2_SIGN_SUPPORT == ENABLED)
         //SM2 signature scheme?
         if(context->signScheme == TLS_SIGN_SCHEME_SM2SIG_SM3)
         {
            //Generate an SM2 signature
            error = tls13GenerateSm2Signature(context, buffer, n, signature);
         }
         else
#endif
#if (TLS_ED25519_SIGN_SUPPORT == ENABLED)
         //Ed25519 signature scheme?
         if(context->signScheme == TLS_SIGN_SCHEME_ED25519)
         {
            //Generate an Ed25519 signature
            error = tls13GenerateEd25519Signature(context, buffer, n, signature);
         }
         else
#endif
#if (TLS_ED448_SIGN_SUPPORT == ENABLED)
         //Ed448 signature scheme?
         if(context->signScheme == TLS_SIGN_SCHEME_ED448)
         {
            //Generate an Ed448 signature
            error = tls13GenerateEd448Signature(context, buffer, n, signature);
         }
         else
#endif
         //Invalid signature scheme?
         {
            //Report an error
            error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
         }
      }

      //Release memory buffer
      tlsFreeMem(buffer);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Check status code
   if(!error)
   {
      //Total length of the digitally-signed element
      *length = sizeof(Tls13DigitalSignature) + ntohs(signature->length);
   }

   //Return status code
   return error;
}


/**
 * @brief RSA-PSS signature generation (TLS 1.3)
 * @param[in] context Pointer to the TLS context
 * @param[in] message Pointer to the message to be signed
 * @param[in] length Length of the message, in bytes
 * @param[out] signature Buffer where to store the digital signature
 * @return Error code
 **/

error_t tls13GenerateRsaPssSignature(TlsContext *context, const uint8_t *message,
   size_t length, Tls13DigitalSignature *signature)
{
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const HashAlgo *hashAlgo;

   //Retrieve the hash algorithm used for signing
   if(context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA256 ||
      context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA256)
   {
      //Select SHA-256 hash algorithm
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
   }
   else if(context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA384 ||
      context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA384)
   {
      //Select SHA-384 hash algorithm
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
   }
   else if(context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA512 ||
      context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA512)
   {
      //Select SHA-512 hash algorithm
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
   }
   else
   {
      //Invalid signature scheme
      hashAlgo = NULL;
   }

   //Pre-hash the content covered by the digital signature
   if(hashAlgo != NULL)
   {
      error = hashAlgo->compute(message, length, context->clientVerifyData);
   }
   else
   {
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Check status code
   if(!error)
   {
      //RSA signatures must use an RSASSA-PSS algorithm, regardless of whether
      //RSASSA-PKCS1-v1_5 algorithms appear in SignatureAlgorithms
      error = tlsGenerateRsaPssSignature(context, hashAlgo,
         context->clientVerifyData, signature->value, &n);
   }

   //Check status code
   if(!error)
   {
      //The signature is preceded by a 2-byte length field
      signature->length = htons(n);
   }

   //Return status code
   return error;
#else
   //RSA-PSS signature algorithm not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ECDSA signature generation (TLS 1.3)
 * @param[in] context Pointer to the TLS context
 * @param[in] message Pointer to the message to be signed
 * @param[in] length Length of the message, in bytes
 * @param[out] signature Buffer where to store the digital signature
 * @return Error code
 **/

error_t tls13GenerateEcdsaSignature(TlsContext *context, const uint8_t *message,
   size_t length, Tls13DigitalSignature *signature)
{
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const HashAlgo *hashAlgo;

   //Retrieve the hash algorithm used for signing
   if(context->signScheme == TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256 ||
      context->signScheme == TLS_SIGN_SCHEME_ECDSA_BP256R1_TLS13_SHA256)
   {
      //Select SHA-256 hash algorithm
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
   }
   else if(context->signScheme == TLS_SIGN_SCHEME_ECDSA_SECP384R1_SHA384 ||
      context->signScheme == TLS_SIGN_SCHEME_ECDSA_BP384R1_TLS13_SHA384)
   {
      //Select SHA-384 hash algorithm
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
   }
   else if(context->signScheme == TLS_SIGN_SCHEME_ECDSA_SECP521R1_SHA512 ||
      context->signScheme == TLS_SIGN_SCHEME_ECDSA_BP512R1_TLS13_SHA512)
   {
      //Select SHA-512 hash algorithm
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
   }
   else
   {
      //Invalid signature scheme
      hashAlgo = NULL;
   }

   //Pre-hash the content covered by the digital signature
   if(hashAlgo != NULL)
   {
      error = hashAlgo->compute(message, length, context->clientVerifyData);
   }
   else
   {
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Check status code
   if(!error)
   {
      //Generate an ECDSA signature
      error = tlsGenerateEcdsaSignature(context, context->clientVerifyData,
         hashAlgo->digestSize, signature->value, &n);
   }

   //Check status code
   if(!error)
   {
      //The signature is preceded by a 2-byte length field
      signature->length = htons(n);
   }

   //Return status code
   return error;
#else
   //ECDSA signature algorithm not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief SM2 signature generation (TLS 1.3)
 * @param[in] context Pointer to the TLS context
 * @param[in] message Pointer to the message to be signed
 * @param[in] length Length of the message, in bytes
 * @param[out] signature Buffer where to store the digital signature
 * @return Error code
 **/

error_t tls13GenerateSm2Signature(TlsContext *context, const uint8_t *message,
   size_t length, Tls13DigitalSignature *signature)
{
#if (TLS_SM2_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   EcPrivateKey privateKey;
   EcdsaSignature sm2Signature;

   //Initialize EC private key
   ecInitPrivateKey(&privateKey);
   //Initialize SM2 signature
   ecdsaInitSignature(&sm2Signature);

   //Decode the PEM structure that holds the EC private key
   error = pemImportEcPrivateKey(&privateKey, context->cert->privateKey,
      context->cert->privateKeyLen, context->cert->password);

   //Check status code
   if(!error)
   {
      //Generate SM2 signature
      error = sm2GenerateSignature(context->prngAlgo, context->prngContext,
         &privateKey, SM3_HASH_ALGO, SM2_TLS13_ID, osStrlen(SM2_TLS13_ID),
         message, length, &sm2Signature);
   }

   //Check status code
   if(!error)
   {
      //Encode the resulting (R, S) integer pair using ASN.1
      error = ecdsaExportSignature(&sm2Signature, signature->value, &n,
         ECDSA_SIGNATURE_FORMAT_ASN1);
   }

   //Check status code
   if(!error)
   {
      //The signature is preceded by a 2-byte length field
      signature->length = htons(n);
   }

   //Release previously allocated resources
   ecFreePrivateKey(&privateKey);
   ecdsaFreeSignature(&sm2Signature);

   //Return status code
   return error;
#else
   //SM2 signature algorithm not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed25519 signature generation (TLS 1.3)
 * @param[in] context Pointer to the TLS context
 * @param[in] message Pointer to the message to be signed
 * @param[in] length Length of the message, in bytes
 * @param[out] signature Buffer where to store the digital signature
 * @return Error code
 **/

error_t tls13GenerateEd25519Signature(TlsContext *context, const uint8_t *message,
   size_t length, Tls13DigitalSignature *signature)
{
#if (TLS_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   DataChunk messageChunks[1];

   //Data to be signed is run through the EdDSA algorithm without pre-hashing
   messageChunks[0].buffer = message;
   messageChunks[0].length = length;

   //Generate Ed25519 signature in PureEdDSA mode
   error = tlsGenerateEd25519Signature(context, messageChunks,
      arraysize(messageChunks), signature->value, &n);

   //Check status code
   if(!error)
   {
      //The signature is preceded by a 2-byte length field
      signature->length = htons(n);
   }

   //Return status code
   return error;
#else
   //Ed25519 signature algorithm not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed448 signature generation (TLS 1.3)
 * @param[in] context Pointer to the TLS context
 * @param[in] message Pointer to the message to be signed
 * @param[in] length Length of the message, in bytes
 * @param[out] signature Buffer where to store the digital signature
 * @return Error code
 **/

error_t tls13GenerateEd448Signature(TlsContext *context, const uint8_t *message,
   size_t length, Tls13DigitalSignature *signature)
{
#if (TLS_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   DataChunk messageChunks[1];

   //Data to be signed is run through the EdDSA algorithm without pre-hashing
   messageChunks[0].buffer = message;
   messageChunks[0].length = length;

   //Generate Ed448 signature in PureEdDSA mode
   error = tlsGenerateEd448Signature(context, messageChunks,
      arraysize(messageChunks), signature->value, &n);

   //Check status code
   if(!error)
   {
      //The signature is preceded by a 2-byte length field
      signature->length = htons(n);
   }

   //Return status code
   return error;
#else
   //Ed448 signature algorithm not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
