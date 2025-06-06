/**
 * @file tls_sign_generate.c
 * @brief RSA/DSA/ECDSA/EdDSA signature generation
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
#include "tls_sign_misc.h"
#include "tls_transcript_hash.h"
#include "tls_misc.h"
#include "pkix/pem_key_import.h"
#include "pkc/rsa.h"
#include "pkc/rsa_misc.h"
#include "pkc/dsa.h"
#include "ecc/ecdsa.h"
#include "ecc/eddsa.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Digital signature generation (TLS 1.0 or TLS 1.1)
 * @param[in] context Pointer to the TLS context
 * @param[out] p Buffer where to store the digitally-signed element
 * @param[out] length Length of the digitally-signed element
 * @return Error code
 **/

error_t tlsGenerateSignature(TlsContext *context, uint8_t *p,
   size_t *length)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   error_t error;
   size_t n;
   TlsDigitalSignature *signature;

   //The digitally-signed element does not convey the signature algorithm
   //to use, and hence implementations need to inspect the certificate to
   //find out the signature algorithm to use
   signature = (TlsDigitalSignature *) p;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
   //RSA certificate?
   if(context->cert->type == TLS_CERT_RSA_SIGN)
   {
      RsaPrivateKey privateKey;

      //Initialize RSA private key
      rsaInitPrivateKey(&privateKey);

      //Digest all the handshake messages starting at ClientHello using MD5
      error = tlsFinalizeTranscriptHash(context, MD5_HASH_ALGO,
         context->transcriptMd5Context, "", context->clientVerifyData);

      //Check status code
      if(!error)
      {
         //Digest all the handshake messages starting at ClientHello using SHA-1
         error = tlsFinalizeTranscriptHash(context, SHA1_HASH_ALGO,
            context->transcriptSha1Context, "",
            context->clientVerifyData + MD5_DIGEST_SIZE);
      }

      //Check status code
      if(!error)
      {
         //Decode the PEM structure that holds the RSA private key
         error = pemImportRsaPrivateKey(&privateKey, context->cert->privateKey,
            context->cert->privateKeyLen, context->cert->password);
      }

      //Check status code
      if(!error)
      {
         //Generate an RSA signature using the client's private key
         error = tlsGenerateRsaSignature(&privateKey,
            context->clientVerifyData, signature->value, &n);
      }

      //Release previously allocated resources
      rsaFreePrivateKey(&privateKey);
   }
   else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
   //DSA certificate?
   if(context->cert->type == TLS_CERT_DSS_SIGN)
   {
      //Digest all the handshake messages starting at ClientHello
      error = tlsFinalizeTranscriptHash(context, SHA1_HASH_ALGO,
         context->transcriptSha1Context, "", context->clientVerifyData);

      //Check status code
      if(!error)
      {
         //Generate a DSA signature using the client's private key
         error = tlsGenerateDsaSignature(context, context->clientVerifyData,
            SHA1_DIGEST_SIZE, signature->value, &n);
      }
   }
   else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   //ECDSA certificate?
   if(context->cert->type == TLS_CERT_ECDSA_SIGN)
   {
      //Digest all the handshake messages starting at ClientHello
      error = tlsFinalizeTranscriptHash(context, SHA1_HASH_ALGO,
         context->transcriptSha1Context, "", context->clientVerifyData);

      //Check status code
      if(!error)
      {
         //Generate an ECDSA signature using the client's private key
         error = tlsGenerateEcdsaSignature(context, context->clientVerifyData,
            SHA1_DIGEST_SIZE, signature->value, &n);
      }
   }
   else
#endif
   //Invalid certificate?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Check status code
   if(!error)
   {
      //The signature is preceded by a 2-byte length field
      signature->length = htons(n);
      //Total length of the digitally-signed element
      *length = sizeof(TlsDigitalSignature) + n;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Digital signature generation (TLS 1.2)
 * @param[in] context Pointer to the TLS context
 * @param[out] p Buffer where to store the digitally-signed element
 * @param[out] length Length of the digitally-signed element
 * @return Error code
 **/

error_t tls12GenerateSignature(TlsContext *context, uint8_t *p,
   size_t *length)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   error_t error;
   size_t n;
   Tls12DigitalSignature *signature;
   const HashAlgo *hashAlgo;

   //Point to the digitally-signed element
   signature = (Tls12DigitalSignature *) p;
   //The algorithm field specifies the signature scheme
   signature->algorithm = htons(context->signScheme);

   //Check signature scheme
   if(TLS_SIGN_ALGO(context->signScheme) == TLS_SIGN_ALGO_RSA ||
      TLS_SIGN_ALGO(context->signScheme) == TLS_SIGN_ALGO_DSA ||
      TLS_SIGN_ALGO(context->signScheme) == TLS_SIGN_ALGO_ECDSA)
   {
      //Retrieve the hash algorithm used for signing
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO(context->signScheme));
   }
   else if(context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA256 ||
      context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA256)
   {
      //The hashing is intrinsic to the signature algorithm
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
   }
   else if(context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA384 ||
      context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA384)
   {
      //The hashing is intrinsic to the signature algorithm
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
   }
   else if(context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA512 ||
      context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA512)
   {
      //The hashing is intrinsic to the signature algorithm
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
   }
   else
   {
      //Unknown signature scheme
      hashAlgo = NULL;
   }

   //Digest all the handshake messages starting at ClientHello
   if(hashAlgo == SHA1_HASH_ALGO)
   {
      //Use SHA-1 hash algorithm
      error = tlsFinalizeTranscriptHash(context, SHA1_HASH_ALGO,
         context->transcriptSha1Context, "", context->clientVerifyData);
   }
   else if(hashAlgo == context->cipherSuite.prfHashAlgo)
   {
      //Use PRF hash algorithm (SHA-256 or SHA-384)
      error = tlsFinalizeTranscriptHash(context, hashAlgo,
         context->transcriptHashContext, "", context->clientVerifyData);
   }
   else
   {
      //The specified hash algorithm is not supported
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Handshake message hash successfully computed?
   if(!error)
   {
#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
      //RSASSA-PKCS1-v1_5 signature scheme?
      if(TLS_SIGN_ALGO(context->signScheme) == TLS_SIGN_ALGO_RSA)
      {
         //Generate RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
         error = tlsGenerateRsaPkcs1Signature(context, hashAlgo,
            context->clientVerifyData, signature->value, &n);
      }
      else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
      //RSASSA-PSS signature scheme?
      if(context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA256 ||
         context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA384 ||
         context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA512 ||
         context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA256 ||
         context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA384 ||
         context->signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA512)
      {
         //Generate RSA signature (RSASSA-PSS signature scheme)
         error = tlsGenerateRsaPssSignature(context, hashAlgo,
            context->clientVerifyData, signature->value, &n);
      }
      else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
      //DSA signature scheme?
      if(TLS_SIGN_ALGO(context->signScheme) == TLS_SIGN_ALGO_DSA)
      {
         //Generate a DSA signature using the client's private key
         error = tlsGenerateDsaSignature(context, context->clientVerifyData,
            hashAlgo->digestSize, signature->value, &n);
      }
      else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
      //ECDSA signature scheme?
      if(TLS_SIGN_ALGO(context->signScheme) == TLS_SIGN_ALGO_ECDSA)
      {
         //Generate an ECDSA signature using the client's private key
         error = tlsGenerateEcdsaSignature(context, context->clientVerifyData,
            hashAlgo->digestSize, signature->value, &n);
      }
      else
#endif
      //Invalid signature scheme?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }

   //Check status code
   if(!error)
   {
      //The signature is preceded by a 2-byte length field
      signature->length = htons(n);
      //Total length of the digitally-signed element
      *length = sizeof(Tls12DigitalSignature) + n;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Generate RSA signature (TLS 1.0 and TLS 1.1)
 * @param[in] key Signer's RSA private key
 * @param[in] digest Digest of the message to be signed
 * @param[out] signature Resulting signature
 * @param[out] signatureLen Length of the resulting signature
 * @return Error code
 **/

error_t tlsGenerateRsaSignature(const RsaPrivateKey *key,
   const uint8_t *digest, uint8_t *signature, size_t *signatureLen)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1 && \
   TLS_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t k;
   size_t paddingLen;
   uint8_t *em;
   Mpi m;
   Mpi s;

   //Debug message
   TRACE_DEBUG("RSA signature generation...\r\n");
   TRACE_DEBUG("  Modulus:\r\n");
   TRACE_DEBUG_MPI("    ", &key->n);
   TRACE_DEBUG("  Public exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &key->e);
   TRACE_DEBUG("  Private exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &key->d);
   TRACE_DEBUG("  Prime 1:\r\n");
   TRACE_DEBUG_MPI("    ", &key->p);
   TRACE_DEBUG("  Prime 2:\r\n");
   TRACE_DEBUG_MPI("    ", &key->q);
   TRACE_DEBUG("  Prime exponent 1:\r\n");
   TRACE_DEBUG_MPI("    ", &key->dp);
   TRACE_DEBUG("  Prime exponent 2:\r\n");
   TRACE_DEBUG_MPI("    ", &key->dq);
   TRACE_DEBUG("  Coefficient:\r\n");
   TRACE_DEBUG_MPI("    ", &key->qinv);
   TRACE_DEBUG("  Message digest:\r\n");
   TRACE_DEBUG_ARRAY("    ", digest, MD5_DIGEST_SIZE + SHA1_DIGEST_SIZE);

   //Initialize multiple-precision integers
   mpiInit(&m);
   mpiInit(&s);

   //Get the length in octets of the modulus n
   k = mpiGetByteLength(&key->n);

   //Check the length of the modulus
   if(k < (MD5_DIGEST_SIZE + SHA1_DIGEST_SIZE + 11))
      return ERROR_INVALID_KEY;

   //Point to the buffer where the encoded message EM will be generated
   em = signature;

   //The leading 0x00 octet ensures that the encoded message,
   //converted to an integer, is less than the modulus
   em[0] = 0x00;
   //Block type 0x01 is used for private-key operations
   em[1] = 0x01;

   //Compute the length of the padding string PS
   paddingLen = k - (MD5_DIGEST_SIZE + SHA1_DIGEST_SIZE + 3);
   //Fill the padding string with 0xFF
   osMemset(em + 2, 0xFF, paddingLen);
   //Append a 0x00 octet to PS
   em[paddingLen + 2] = 0x00;

   //Append the digest value
   osMemcpy(em + paddingLen + 3, digest, MD5_DIGEST_SIZE + SHA1_DIGEST_SIZE);

   //Debug message
   TRACE_DEBUG("  Encoded message\r\n");
   TRACE_DEBUG_ARRAY("    ", em, k);

   //Start of exception handling block
   do
   {
      //Convert the encoded message EM to an integer message representative m
      error = mpiImport(&m, em, k, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Apply the RSASP1 signature primitive
      error = rsasp1(key, &m, &s);
      //Any error to report?
      if(error)
         break;

      //Convert the signature representative s to a signature of length k octets
      error = mpiExport(&s, signature, k, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Length of the resulting signature
      *signatureLen = k;

      //Debug message
      TRACE_DEBUG("  Signature:\r\n");
      TRACE_DEBUG_ARRAY("    ", signature, *signatureLen);

      //End of exception handling block
   } while(0);

   //Free previously allocated memory
   mpiFree(&m);
   mpiFree(&s);

   //Return status code
   return error;
#else
   //RSA signature algorithm is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Generate RSA signature (TLS 1.2)
 * @param[in] context Pointer to the TLS context
 * @param[in] hashAlgo Hash function used to digest the message
 * @param[in] digest Digest of the message to be signed
 * @param[out] signature Resulting signature
 * @param[out] signatureLen Length of the resulting signature
 * @return Error code
 **/

error_t tlsGenerateRsaPkcs1Signature(TlsContext *context,
   const HashAlgo *hashAlgo, const uint8_t *digest, uint8_t *signature,
   size_t *signatureLen)
{
#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   RsaPrivateKey privateKey;

   //Initialize RSA private key
   rsaInitPrivateKey(&privateKey);

   //Decode the PEM structure that holds the RSA private key
   error = pemImportRsaPrivateKey(&privateKey, context->cert->privateKey,
      context->cert->privateKeyLen, context->cert->password);

   //Check status code
   if(!error)
   {
      //Generate RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
      error = rsassaPkcs1v15Sign(&privateKey, hashAlgo, digest, signature,
         signatureLen);
   }

   //Release previously allocated resources
   rsaFreePrivateKey(&privateKey);

   //Return status code
   return error;
#else
   //RSA signature algorithm is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Generate RSA-PSS signature
 * @param[in] context Pointer to the TLS context
 * @param[in] hashAlgo Hash function used to digest the message
 * @param[in] digest Digest of the message to be signed
 * @param[out] signature Resulting signature
 * @param[out] signatureLen Length of the resulting signature
 * @return Error code
 **/

error_t tlsGenerateRsaPssSignature(TlsContext *context,
   const HashAlgo *hashAlgo, const uint8_t *digest, uint8_t *signature,
   size_t *signatureLen)
{
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
   error_t error;
   RsaPrivateKey privateKey;

   //Initialize RSA private key
   rsaInitPrivateKey(&privateKey);

   //Decode the PEM structure that holds the RSA private key
   error = pemImportRsaPrivateKey(&privateKey, context->cert->privateKey,
      context->cert->privateKeyLen, context->cert->password);

   //Check status code
   if(!error)
   {
      //Generate RSA signature (RSASSA-PSS signature scheme)
      error = rsassaPssSign(context->prngAlgo, context->prngContext,
         &privateKey, hashAlgo, hashAlgo->digestSize, digest, signature,
         signatureLen);
   }

   //Release previously allocated resources
   rsaFreePrivateKey(&privateKey);

   //Return status code
   return error;
#else
   //RSA signature algorithm is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Generate DSA signature
 * @param[in] context Pointer to the TLS context
 * @param[in] digest Digest of the message to be signed
 * @param[in] digestLen Length in octets of the digest
 * @param[out] signature Resulting signature
 * @param[out] signatureLen Length of the resulting signature
 * @return Error code
 **/

error_t tlsGenerateDsaSignature(TlsContext *context, const uint8_t *digest,
   size_t digestLen, uint8_t *signature, size_t *signatureLen)
{
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   DsaPrivateKey privateKey;
   DsaSignature dsaSignature;

   //Initialize DSA private key
   dsaInitPrivateKey(&privateKey);
   //Initialize DSA signature
   dsaInitSignature(&dsaSignature);

   //Decode the PEM structure that holds the DSA private key
   error = pemImportDsaPrivateKey(&privateKey, context->cert->privateKey,
      context->cert->privateKeyLen, context->cert->password);

   //Check status code
   if(!error)
   {
      //Generate DSA signature
      error = dsaGenerateSignature(context->prngAlgo, context->prngContext,
         &privateKey, digest, digestLen, &dsaSignature);
   }

   //Check status code
   if(!error)
   {
      //Encode the resulting (R, S) integer pair using ASN.1
      error = dsaExportSignature(&dsaSignature, signature, signatureLen);
   }

   //Free previously allocated resources
   dsaFreePrivateKey(&privateKey);
   dsaFreeSignature(&dsaSignature);

   //Return status code
   return error;
#else
   //DSA signature algorithm is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Generate ECDSA signature
 * @param[in] context Pointer to the TLS context
 * @param[in] digest Digest of the message to be signed
 * @param[in] digestLen Length in octets of the digest
 * @param[out] signature Resulting signature
 * @param[out] signatureLen Length of the resulting signature
 * @return Error code
 **/

error_t tlsGenerateEcdsaSignature(TlsContext *context, const uint8_t *digest,
   size_t digestLen, uint8_t *signature, size_t *signatureLen)
{
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   EcPrivateKey privateKey;
   EcdsaSignature ecdsaSignature;

   //Initialize ECDSA signature
   ecdsaInitSignature(&ecdsaSignature);

#if (TLS_ECC_CALLBACK_SUPPORT == ENABLED)
   //Any registered callback?
   if(context->ecdsaSignCallback != NULL)
   {
      //Invoke user callback function
      error = context->ecdsaSignCallback(context, digest, digestLen,
         &ecdsaSignature);
   }
   else
#endif
   {
      //Initialize EC private key
      ecInitPrivateKey(&privateKey);

      //Decode the PEM structure that holds the EC private key
      error = pemImportEcPrivateKey(&privateKey, context->cert->privateKey,
         context->cert->privateKeyLen, context->cert->password);

      //Check status code
      if(!error)
      {
         //Generate ECDSA signature
         error = ecdsaGenerateSignature(context->prngAlgo, context->prngContext,
            &privateKey, digest, digestLen, &ecdsaSignature);
      }

      //Release previously allocated resources
      ecFreePrivateKey(&privateKey);
   }

   //Check status code
   if(!error)
   {
      //Encode the resulting (R, S) integer pair using ASN.1
      error = ecdsaExportSignature(&ecdsaSignature, signature, signatureLen,
         ECDSA_SIGNATURE_FORMAT_ASN1);
   }

   //Release previously allocated resources
   ecdsaFreeSignature(&ecdsaSignature);

   //Return status code
   return error;
#else
   //ECDSA signature algorithm is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Generate Ed25519 signature
 * @param[in] context Pointer to the TLS context
 * @param[in] message Array of data chunks representing the message to be
 *   signed
 * @param[in] messageLen Number of data chunks representing the message
 * @param[out] signature Resulting signature
 * @param[out] signatureLen Length of the resulting signature
 * @return Error code
 **/

error_t tlsGenerateEd25519Signature(TlsContext *context,
   const DataChunk *message, uint_t messageLen, uint8_t *signature,
   size_t *signatureLen)
{
#if (TLS_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *q;
   EddsaPrivateKey privateKey;

   //Initialize EdDSA private key
   eddsaInitPrivateKey(&privateKey);

   //Decode the PEM structure that holds the EdDSA private key
   error = pemImportEddsaPrivateKey(&privateKey, context->cert->privateKey,
      context->cert->privateKeyLen, context->cert->password);

   //Check elliptic curve parameters
   if(privateKey.curve == ED25519_CURVE)
   {
      //The public key is optional
      q = (privateKey.q.curve != NULL) ? privateKey.q.q : NULL;

      //Generate Ed25519 signature (PureEdDSA mode)
      error = ed25519GenerateSignatureEx(privateKey.d, q, message, messageLen,
         NULL, 0, 0, signature);

      //Check status code
      if(!error)
      {
         //Length of the resulting EdDSA signature
         *signatureLen = ED25519_SIGNATURE_LEN;
      }
   }
   else
   {
      //The EdDSA private key is not valid
      error = ERROR_INVALID_KEY;
   }

   //Free previously allocated resources
   eddsaFreePrivateKey(&privateKey);

   //Return status code
   return error;
#else
   //EdDSA signature algorithm is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Generate Ed448 signature
 * @param[in] context Pointer to the TLS context
 * @param[in] message Array of data chunks representing the message to be
 *   signed
 * @param[in] messageLen Number of data chunks representing the message
 * @param[out] signature Resulting signature
 * @param[out] signatureLen Length of the resulting signature
 * @return Error code
 **/

error_t tlsGenerateEd448Signature(TlsContext *context,
   const DataChunk *message, uint_t messageLen, uint8_t *signature,
   size_t *signatureLen)
{
#if (TLS_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *q;
   EddsaPrivateKey privateKey;

   //Initialize EdDSA private key
   eddsaInitPrivateKey(&privateKey);

   //Decode the PEM structure that holds the EdDSA private key
   error = pemImportEddsaPrivateKey(&privateKey, context->cert->privateKey,
      context->cert->privateKeyLen, context->cert->password);

   //Check elliptic curve parameters
   if(privateKey.curve == ED448_CURVE)
   {
      //The public key is optional
      q = (privateKey.q.curve != NULL) ? privateKey.q.q : NULL;

      //Generate Ed448 signature (PureEdDSA mode)
      error = ed448GenerateSignatureEx(privateKey.d, q, message, messageLen,
         NULL, 0, 0, signature);

      //Check status code
      if(!error)
      {
         //Length of the resulting EdDSA signature
         *signatureLen = ED448_SIGNATURE_LEN;
      }
   }
   else
   {
      //The EdDSA private key is not valid
      error = ERROR_INVALID_KEY;
   }

   //Free previously allocated resources
   eddsaFreePrivateKey(&privateKey);

   //Return status code
   return error;
#else
   //Ed448 signature algorithm is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
