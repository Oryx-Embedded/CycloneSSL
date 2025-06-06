/**
 * @file tls13_sign_verify.c
 * @brief RSA/DSA/ECDSA/SM2/EdDSA signature verification (TLS 1.3)
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
#include "tls_sign_verify.h"
#include "tls_sign_misc.h"
#include "tls_transcript_hash.h"
#include "tls_misc.h"
#include "tls13_sign_verify.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_MAX_VERSION >= TLS_VERSION_1_3)


/**
 * @brief Digital signature verification (TLS 1.3)
 * @param[in] context Pointer to the TLS context
 * @param[in] p Pointer to the digitally-signed element to be verified
 * @param[in] length Length of the digitally-signed element
 * @return Error code
 **/

error_t tls13VerifySignature(TlsContext *context, const uint8_t *p,
   size_t length)
{
   error_t error;
   size_t n;
   uint8_t *buffer;
   TlsSignatureScheme signScheme;
   const Tls13DigitalSignature *signature;
   const HashAlgo *hashAlgo;

   //Point to the digitally-signed element
   signature = (Tls13DigitalSignature *) p;

   //Malformed CertificateVerify message?
   if(length < sizeof(Tls13DigitalSignature))
      return ERROR_DECODING_FAILED;
   if(length != (sizeof(Tls13DigitalSignature) + ntohs(signature->length)))
      return ERROR_DECODING_FAILED;

   //The signature algorithm must be one of those offered in the
   //SignatureAlgorithms extension (refer to RFC 8446, section 4.4.3)
   if(!tlsIsSignAlgoSupported(context, ntohs(signature->algorithm)))
      return ERROR_ILLEGAL_PARAMETER;

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
         osMemcpy(buffer + 64, "TLS 1.3, server CertificateVerify", 33);
      }
      else
      {
         osMemcpy(buffer + 64, "TLS 1.3, client CertificateVerify", 33);
      }

      //Append a single 0 byte which serves as the separator
      buffer[97] = 0x00;

      //Compute the transcript hash
      error = tlsFinalizeTranscriptHash(context, hashAlgo,
         context->transcriptHashContext, "", buffer + 98);

      //Check status code
      if(!error)
      {
         //The algorithm field specifies the signature scheme
         signScheme = (TlsSignatureScheme) ntohs(signature->algorithm);

#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
         //RSASSA-PSS signature scheme?
         if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA256 ||
            signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA384 ||
            signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA512 ||
            signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA256 ||
            signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA384 ||
            signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA512)
         {
            //Verify RSA-PSS signature
            error = tls13VerifyRsaPssSignature(context, buffer, n, signature);
         }
         else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
         //ECDSA signature scheme?
         if(signScheme == TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256 ||
            signScheme == TLS_SIGN_SCHEME_ECDSA_SECP384R1_SHA384 ||
            signScheme == TLS_SIGN_SCHEME_ECDSA_SECP521R1_SHA512 ||
            signScheme == TLS_SIGN_SCHEME_ECDSA_BP256R1_TLS13_SHA256 ||
            signScheme == TLS_SIGN_SCHEME_ECDSA_BP384R1_TLS13_SHA384 ||
            signScheme == TLS_SIGN_SCHEME_ECDSA_BP512R1_TLS13_SHA512)
         {
            //Verify ECDSA signature
            error = tls13VerifyEcdsaSignature(context, buffer, n, signature);
         }
         else
#endif
#if (TLS_SM2_SIGN_SUPPORT == ENABLED)
         //SM2 signature scheme?
         if(signScheme == TLS_SIGN_SCHEME_SM2SIG_SM3)
         {
            //Verify SM2 signature
            error = tls13VerifySm2Signature(context, buffer, n, signature);
         }
         else
#endif
#if (TLS_ED25519_SIGN_SUPPORT == ENABLED)
         //Ed25519 signature scheme?
         if(signScheme == TLS_SIGN_SCHEME_ED25519)
         {
            //Verify Ed25519 signature
            error = tls13VerifyEd25519Signature(context, buffer, n, signature);
         }
         else
#endif
#if (TLS_ED448_SIGN_SUPPORT == ENABLED)
         //Ed448 signature scheme?
         if(signScheme == TLS_SIGN_SCHEME_ED448)
         {
            //Verify Ed448 signature
            error = tls13VerifyEd448Signature(context, buffer, n, signature);
         }
         else
#endif
         //Unknown signature scheme?
         {
            //Report an error
            error = ERROR_ILLEGAL_PARAMETER;
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

   //Return status code
   return error;
}


/**
 * @brief RSA-PSS signature verification (TLS 1.3)
 * @param[in] context Pointer to the TLS context
 * @param[in] message Message whose signature is to be verified
 * @param[in] length Length of the message, in bytes
 * @param[in] signature Pointer to the digital signature to be verified
 * @return Error code
 **/

error_t tls13VerifyRsaPssSignature(TlsContext *context, const uint8_t *message,
   size_t length, const Tls13DigitalSignature *signature)
{
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
   error_t error;
   TlsSignatureScheme signScheme;
   const HashAlgo *hashAlgo;

   //The algorithm field specifies the signature scheme
   signScheme = (TlsSignatureScheme) ntohs(signature->algorithm);

   //The signature algorithm must be compatible with the key in the sender's
   //end-entity certificate (refer to RFC 8446, section 4.4.3)
   if(context->peerCertType == TLS_CERT_RSA_SIGN)
   {
      //Retrieve the hash algorithm used for signing
      if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA256)
      {
         //Select SHA-256 hash algorithm
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
      }
      else if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA384)
      {
         //Select SHA-384 hash algorithm
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
      }
      else if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA512)
      {
         //Select SHA-512 hash algorithm
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
      }
      else
      {
         //Invalid signature scheme
         hashAlgo = NULL;
      }
   }
   else if(context->peerCertType == TLS_CERT_RSA_PSS_SIGN)
   {
      //Retrieve the hash algorithm used for signing
      if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA256)
      {
         //Select SHA-256 hash algorithm
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
      }
      else if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA384)
      {
         //Select SHA-384 hash algorithm
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
      }
      else if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA512)
      {
         //Select SHA-512 hash algorithm
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
      }
      else
      {
         //Invalid signature scheme
         hashAlgo = NULL;
      }
   }
   else
   {
      //Invalid certificate
      hashAlgo = NULL;
   }

   //Pre-hash the content covered by the digital signature
   if(hashAlgo != NULL)
   {
      error = hashAlgo->compute(message, length, context->clientVerifyData);
   }
   else
   {
      error = ERROR_ILLEGAL_PARAMETER;
   }

   //Check status code
   if(!error)
   {
      //Verify RSASSA-PSS signature
      error = rsassaPssVerify(&context->peerRsaPublicKey, hashAlgo,
         hashAlgo->digestSize, context->clientVerifyData, signature->value,
         ntohs(signature->length));
   }

   //Return status code
   return error;
#else
   //RSA-PSS signature algorithm not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ECDSA signature verification (TLS 1.3)
 * @param[in] context Pointer to the TLS context
 * @param[in] message Message whose signature is to be verified
 * @param[in] length Length of the message, in bytes
 * @param[in] signature Pointer to the digital signature to be verified
 * @return Error code
 **/

error_t tls13VerifyEcdsaSignature(TlsContext *context, const uint8_t *message,
   size_t length, const Tls13DigitalSignature *signature)
{
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   TlsSignatureScheme signScheme;
   const HashAlgo *hashAlgo;
   const EcCurve *curve;

   //The algorithm field specifies the signature scheme
   signScheme = (TlsSignatureScheme) ntohs(signature->algorithm);

   //The signature algorithm must be compatible with the key in the sender's
   //end-entity certificate (refer to RFC 8446, section 4.4.3)
   if(context->peerCertType == TLS_CERT_ECDSA_SIGN)
   {
      //Get elliptic curve parameters
      curve = context->peerEcPublicKey.curve;

      //Retrieve the hash algorithm used for signing
      if(curve == NULL)
      {
         //Invalid signature scheme
         hashAlgo = NULL;
      }
      else if(signScheme == TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256 &&
         osStrcmp(curve->name, "secp256r1") == 0)
      {
         //Select SHA-256 hash algorithm
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
      }
      else if(signScheme == TLS_SIGN_SCHEME_ECDSA_SECP384R1_SHA384 &&
         osStrcmp(curve->name, "secp384r1") == 0)
      {
         //Select SHA-384 hash algorithm
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
      }
      else if(signScheme == TLS_SIGN_SCHEME_ECDSA_SECP521R1_SHA512 &&
         osStrcmp(curve->name, "secp521r1") == 0)
      {
         //Select SHA-512 hash algorithm
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
      }
      else if(signScheme == TLS_SIGN_SCHEME_ECDSA_BP256R1_TLS13_SHA256 &&
         osStrcmp(curve->name, "brainpoolP256r1") == 0)
      {
         //Select SHA-256 hash algorithm
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
      }
      else if(signScheme == TLS_SIGN_SCHEME_ECDSA_BP384R1_TLS13_SHA384 &&
         osStrcmp(curve->name, "brainpoolP384r1") == 0)
      {
         //Select SHA-384 hash algorithm
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
      }
      else if(signScheme == TLS_SIGN_SCHEME_ECDSA_BP512R1_TLS13_SHA512 &&
         osStrcmp(curve->name, "brainpoolP512r1") == 0)
      {
         //Select SHA-512 hash algorithm
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
      }
      else
      {
         //Invalid signature scheme
         hashAlgo = NULL;
      }
   }
   else
   {
      //Invalid certificate
      hashAlgo = NULL;
   }

   //Pre-hash the content covered by the digital signature
   if(hashAlgo != NULL)
   {
      error = hashAlgo->compute(message, length, context->clientVerifyData);
   }
   else
   {
      error = ERROR_ILLEGAL_PARAMETER;
   }

   //Check status code
   if(!error)
   {
      //Verify ECDSA signature
      error = tlsVerifyEcdsaSignature(context, context->clientVerifyData,
         hashAlgo->digestSize, signature->value, ntohs(signature->length));
   }

   //Return status code
   return error;
#else
   //ECDSA signature algorithm not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief SM2 signature verification (TLS 1.3)
 * @param[in] context Pointer to the TLS context
 * @param[in] message Message whose signature is to be verified
 * @param[in] length Length of the message, in bytes
 * @param[in] signature Pointer to the digital signature to be verified
 * @return Error code
 **/

error_t tls13VerifySm2Signature(TlsContext *context, const uint8_t *message,
   size_t length, const Tls13DigitalSignature *signature)
{
#if (TLS_SM2_SIGN_SUPPORT == ENABLED)
   error_t error;
   EcdsaSignature sm2Signature;

   //The signature algorithm must be compatible with the key in the sender's
   //end-entity certificate (refer to RFC 8446, section 4.4.3)
   if(context->peerCertType == TLS_CERT_SM2_SIGN)
   {
      //Initialize SM2 signature
      ecdsaInitSignature(&sm2Signature);

      //Read the ASN.1 encoded SM2 signature
      error = ecdsaImportSignature(&sm2Signature,
         context->peerEcPublicKey.curve, signature->value,
         ntohs(signature->length), ECDSA_SIGNATURE_FORMAT_ASN1);

      //Check status code
      if(!error)
      {
         //Verify SM2 signature
         error = sm2VerifySignature(&context->peerEcPublicKey, SM3_HASH_ALGO,
            SM2_TLS13_ID, osStrlen(SM2_TLS13_ID), message, length,
            &sm2Signature);
      }

      //Free previously allocated resources
      ecdsaFreeSignature(&sm2Signature);
   }
   else
   {
      //Invalid certificate
      error = ERROR_ILLEGAL_PARAMETER;
   }

   //Return status code
   return error;
#else
   //SM2 signature algorithm not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed25519 signature verification (TLS 1.3)
 * @param[in] context Pointer to the TLS context
 * @param[in] message Message whose signature is to be verified
 * @param[in] length Length of the message, in bytes
 * @param[in] signature Pointer to the digital signature to be verified
 * @return Error code
 **/

error_t tls13VerifyEd25519Signature(TlsContext *context, const uint8_t *message,
   size_t length, const Tls13DigitalSignature *signature)
{
#if (TLS_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;
   DataChunk messageChunks[1];

   //The signature algorithm must be compatible with the key in the sender's
   //end-entity certificate (refer to RFC 8446, section 4.4.3)
   if(context->peerCertType == TLS_CERT_ED25519_SIGN)
   {
      //Data to be verified is run through the EdDSA algorithm without pre-hashing
      messageChunks[0].buffer = message;
      messageChunks[0].length = length;

      //Verify Ed25519 signature (PureEdDSA mode)
      error = tlsVerifyEd25519Signature(context, messageChunks,
         arraysize(messageChunks), signature->value, ntohs(signature->length));
   }
   else
   {
      //Invalid certificate
      error = ERROR_ILLEGAL_PARAMETER;
   }

   //Return status code
   return error;
#else
   //Ed25519 signature algorithm not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed448 signature verification (TLS 1.3)
 * @param[in] context Pointer to the TLS context
 * @param[in] message Message whose signature is to be verified
 * @param[in] length Length of the message, in bytes
 * @param[in] signature Pointer to the digital signature to be verified
 * @return Error code
 **/

error_t tls13VerifyEd448Signature(TlsContext *context, const uint8_t *message,
   size_t length, const Tls13DigitalSignature *signature)
{
#if (TLS_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;
   DataChunk messageChunks[1];

   //The signature algorithm must be compatible with the key in the sender's
   //end-entity certificate (refer to RFC 8446, section 4.4.3)
   if(context->peerCertType == TLS_CERT_ED448_SIGN)
   {
      //Data to be verified is run through the EdDSA algorithm without pre-hashing
      messageChunks[0].buffer = message;
      messageChunks[0].length = length;

      //Verify Ed448 signature (PureEdDSA mode)
      error = tlsVerifyEd448Signature(context, messageChunks,
         arraysize(messageChunks), signature->value, ntohs(signature->length));
   }
   else
   {
      //Invalid certificate
      error = ERROR_ILLEGAL_PARAMETER;
   }

   //Return status code
   return error;
#else
   //Ed448 signature algorithm not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
