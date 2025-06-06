/**
 * @file tls_sign_verify.c
 * @brief RSA/DSA/ECDSA/EdDSA signature verification
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
#include "pkc/rsa.h"
#include "pkc/rsa_misc.h"
#include "pkc/dsa.h"
#include "ecc/ecdsa.h"
#include "ecc/eddsa.h"
#include "ecc/ec_misc.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Digital signature verification (TLS 1.0 and TLS 1.1)
 * @param[in] context Pointer to the TLS context
 * @param[in] p Pointer to the digitally-signed element to be verified
 * @param[in] length Length of the digitally-signed element
 * @return Error code
 **/

error_t tlsVerifySignature(TlsContext *context, const uint8_t *p,
   size_t length)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   error_t error;
   const TlsDigitalSignature *signature;

   //The digitally-signed element does not convey the signature algorithm
   //to use, and hence implementations need to inspect the certificate to
   //find out the signature algorithm to use
   signature = (TlsDigitalSignature *) p;

   //Check the length of the digitally-signed element
   if(length < sizeof(TlsDigitalSignature))
      return ERROR_DECODING_FAILED;
   if(length != (sizeof(TlsDigitalSignature) + ntohs(signature->length)))
      return ERROR_DECODING_FAILED;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
   //RSA certificate?
   if(context->peerCertType == TLS_CERT_RSA_SIGN)
   {
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
         //Verify RSA signature using client's public key
         error = tlsVerifyRsaSignature(&context->peerRsaPublicKey,
            context->clientVerifyData, signature->value,
            ntohs(signature->length));
      }
   }
   else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
   //DSA certificate?
   if(context->peerCertType == TLS_CERT_DSS_SIGN)
   {
      //Digest all the handshake messages starting at ClientHello
      error = tlsFinalizeTranscriptHash(context, SHA1_HASH_ALGO,
         context->transcriptSha1Context, "", context->clientVerifyData);

      //Check status code
      if(!error)
      {
         //Verify DSA signature using client's public key
         error = tlsVerifyDsaSignature(context, context->clientVerifyData,
            SHA1_DIGEST_SIZE, signature->value, ntohs(signature->length));
      }
   }
   else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   //ECDSA certificate?
   if(context->peerCertType == TLS_CERT_ECDSA_SIGN)
   {
      //Digest all the handshake messages starting at ClientHello
      error = tlsFinalizeTranscriptHash(context, SHA1_HASH_ALGO,
         context->transcriptSha1Context, "", context->clientVerifyData);

      //Check status code
      if(!error)
      {
         //Verify ECDSA signature using client's public key
         error = tlsVerifyEcdsaSignature(context, context->clientVerifyData,
            SHA1_DIGEST_SIZE, signature->value, ntohs(signature->length));
      }
   }
   else
#endif
   //Invalid signature algorithm?
   {
      //Report an error
      error = ERROR_INVALID_SIGNATURE;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Digital signature verification (TLS 1.2)
 * @param[in] context Pointer to the TLS context
 * @param[in] p Pointer to the digitally-signed element to be verified
 * @param[in] length Length of the digitally-signed element
 * @return Error code
 **/

error_t tls12VerifySignature(TlsContext *context, const uint8_t *p,
   size_t length)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   error_t error;
   TlsSignatureScheme signScheme;
   const Tls12DigitalSignature *signature;
   const HashAlgo *hashAlgo;

   //Point to the digitally-signed element
   signature = (Tls12DigitalSignature *) p;

   //Check the length of the digitally-signed element
   if(length < sizeof(Tls12DigitalSignature))
      return ERROR_DECODING_FAILED;
   if(length != (sizeof(Tls12DigitalSignature) + ntohs(signature->length)))
      return ERROR_DECODING_FAILED;

   //The algorithm field specifies the signature scheme
   signScheme = (TlsSignatureScheme) ntohs(signature->algorithm);

   //The certificates must be signed using an acceptable hash/signature
   //algorithm pair (refer to RFC 5246, section 7.4.6)
   if(!tlsIsSignAlgoSupported(context, signScheme))
      return ERROR_ILLEGAL_PARAMETER;

   //Check signature scheme
   if(TLS_SIGN_ALGO(signScheme) == TLS_SIGN_ALGO_RSA ||
      TLS_SIGN_ALGO(signScheme) == TLS_SIGN_ALGO_DSA ||
      TLS_SIGN_ALGO(signScheme) == TLS_SIGN_ALGO_ECDSA)
   {
      //Retrieve the hash algorithm used for signing
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO(signScheme));
   }
   else if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA256 ||
      signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA256)
   {
      //The hashing is intrinsic to the signature algorithm
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
   }
   else if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA384 ||
      signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA384)
   {
      //The hashing is intrinsic to the signature algorithm
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
   }
   else if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA512 ||
      signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA512)
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
      error = ERROR_INVALID_SIGNATURE;
   }

   //Check status code
   if(!error)
   {
#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
      //RSASSA-PKCS1-v1_5 signature scheme?
      if(TLS_SIGN_ALGO(signScheme) == TLS_SIGN_ALGO_RSA &&
         context->peerCertType == TLS_CERT_RSA_SIGN)
      {
         //Verify RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
         error = rsassaPkcs1v15Verify(&context->peerRsaPublicKey,
            hashAlgo, context->clientVerifyData, signature->value,
            ntohs(signature->length));
      }
      else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
      //RSASSA-PSS signature scheme (with public key OID rsaEncryption)?
      if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA256 ||
         signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA384 ||
         signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA512)
      {
         //The signature algorithm must be compatible with the key in the
         //server's end-entity certificate (refer to RFC 5246, section 7.4.3)
         if(context->peerCertType == TLS_CERT_RSA_SIGN)
         {
            //Verify RSA signature (RSASSA-PSS signature scheme)
            error = rsassaPssVerify(&context->peerRsaPublicKey, hashAlgo,
               hashAlgo->digestSize, context->clientVerifyData,
               signature->value, ntohs(signature->length));
         }
         else
         {
            //Invalid certificate
            error = ERROR_INVALID_SIGNATURE;
         }
      }
      else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
      //RSASSA-PSS signature scheme (with public key OID RSASSA-PSS)?
      if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA256 ||
         signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA384 ||
         signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA512)
      {
         //The signature algorithm must be compatible with the key in the
         //server's end-entity certificate (refer to RFC 5246, section 7.4.3)
         if(context->peerCertType == TLS_CERT_RSA_PSS_SIGN)
         {
            //Verify RSA signature (RSASSA-PSS signature scheme)
            error = rsassaPssVerify(&context->peerRsaPublicKey, hashAlgo,
               hashAlgo->digestSize, context->clientVerifyData,
               signature->value, ntohs(signature->length));
         }
         else
         {
            //Invalid certificate
            error = ERROR_INVALID_SIGNATURE;
         }
      }
      else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
      //DSA signature scheme?
      if(TLS_SIGN_ALGO(signScheme) == TLS_SIGN_ALGO_DSA &&
         context->peerCertType == TLS_CERT_DSS_SIGN)
      {
         //Verify DSA signature using client's public key
         error = tlsVerifyDsaSignature(context, context->clientVerifyData,
            hashAlgo->digestSize, signature->value, ntohs(signature->length));
      }
      else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
      //ECDSA signature scheme?
      if(TLS_SIGN_ALGO(signScheme) == TLS_SIGN_ALGO_ECDSA &&
         context->peerCertType == TLS_CERT_ECDSA_SIGN)
      {
         //Verify ECDSA signature using client's public key
         error = tlsVerifyEcdsaSignature(context, context->clientVerifyData,
            hashAlgo->digestSize, signature->value, ntohs(signature->length));
      }
      else
#endif
      //Invalid signature scheme?
      {
         //Report an error
         error = ERROR_INVALID_SIGNATURE;
      }
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Verify RSA signature (TLS 1.0 and TLS 1.1)
 * @param[in] key Signer's RSA public key
 * @param[in] digest Digest of the message whose signature is to be verified
 * @param[in] signature Signature to be verified
 * @param[in] signatureLen Length of the signature to be verified
 * @return Error code
 **/

error_t tlsVerifyRsaSignature(const RsaPublicKey *key,
   const uint8_t *digest, const uint8_t *signature, size_t signatureLen)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1 && \
   TLS_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   uint_t k;
   uint8_t *em;
   Mpi s;
   Mpi m;

   //Debug message
   TRACE_DEBUG("RSA signature verification...\r\n");
   TRACE_DEBUG("  Modulus:\r\n");
   TRACE_DEBUG_MPI("    ", &key->n);
   TRACE_DEBUG("  Public exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &key->e);
   TRACE_DEBUG("  Message digest:\r\n");
   TRACE_DEBUG_ARRAY("    ", digest, MD5_DIGEST_SIZE + SHA1_DIGEST_SIZE);
   TRACE_DEBUG("  Signature:\r\n");
   TRACE_DEBUG_ARRAY("    ", signature, signatureLen);

   //Get the length in octets of the modulus n
   k = mpiGetByteLength(&key->n);

   //Check the length of the signature
   if(signatureLen != k)
      return ERROR_INVALID_SIGNATURE;

   //Initialize multiple-precision integers
   mpiInit(&s);
   mpiInit(&m);

   //Allocate a memory buffer to hold the encoded message
   em = tlsAllocMem(k);
   //Failed to allocate memory?
   if(em == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Start of exception handling block
   do
   {
      //Convert the signature to an integer signature representative s
      error = mpiImport(&s, signature, signatureLen, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Apply the RSAVP1 verification primitive
      error = rsavp1(key, &s, &m);
      //Any error to report?
      if(error)
         break;

      //Convert the message representative m to an encoded message EM of
      //length k octets
      error = mpiExport(&m, em, k, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Debug message
      TRACE_DEBUG("  Encoded message\r\n");
      TRACE_DEBUG_ARRAY("    ", em, k);

      //Verify the encoded message EM
      error = tlsVerifyRsaEm(digest, em, k);

      //End of exception handling block
   } while(0);

   //Release multiple precision integers
   mpiFree(&s);
   mpiFree(&m);
   //Release previously allocated memory
   tlsFreeMem(em);

   //Return status code
   return error;
#else
   //RSA signature algorithm is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Verify RSA encoded message
 * @param[in] digest Digest value
 * @param[in] em Encoded message
 * @param[in] emLen Length of the encoded message
 * @return Error code
 **/

error_t tlsVerifyRsaEm(const uint8_t *digest, const uint8_t *em, size_t emLen)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1 && \
   TLS_RSA_SIGN_SUPPORT == ENABLED)
   size_t i;
   size_t j;
   size_t n;
   uint8_t bad;

   //Check the length of the encoded message
   if(emLen < (MD5_DIGEST_SIZE + SHA1_DIGEST_SIZE + 11))
      return ERROR_INVALID_LENGTH;

   //Point to the first byte of the encoded message
   i = 0;

   //The first octet of EM must have hexadecimal value 0x00
   bad = em[i++];
   //The second octet of EM must have hexadecimal value 0x01
   bad |= em[i++] ^ 0x01;

   //Determine the length of the padding string PS
   n = emLen - MD5_DIGEST_SIZE - SHA1_DIGEST_SIZE - 3;

   //Each byte of PS must be set to 0xFF when the block type is 0x01
   for(j = 0; j < n; j++)
   {
      bad |= em[i++] ^ 0xFF;
   }

   //The padding string must be followed by a 0x00 octet
   bad |= em[i++];

   //Recover the underlying hash value, and then compare it to the newly
   //computed hash value
   for(j = 0; j < (MD5_DIGEST_SIZE + SHA1_DIGEST_SIZE); j++)
   {
      bad |= em[i++] ^ digest[j];
   }

   //Verification result
   return (bad != 0) ? ERROR_INVALID_SIGNATURE : NO_ERROR;
#else
   //RSA signature algorithm is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Verify DSA signature
 * @param[in] context Pointer to the TLS context
 * @param[in] digest Digest of the message whose signature is to be verified
 * @param[in] digestLen Length in octets of the digest
 * @param[in] signature Signature to be verified
 * @param[in] signatureLen Length of the signature to be verified
 * @return Error code
 **/

error_t tlsVerifyDsaSignature(TlsContext *context, const uint8_t *digest,
   size_t digestLen, const uint8_t *signature, size_t signatureLen)
{
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   DsaSignature dsaSignature;

   //Initialize DSA signature
   dsaInitSignature(&dsaSignature);

   //Read the ASN.1 encoded DSA signature
   error = dsaImportSignature(&dsaSignature, signature, signatureLen);

   //Check status code
   if(!error)
   {
      //DSA signature verification
      error = dsaVerifySignature(&context->peerDsaPublicKey,
         digest, digestLen, &dsaSignature);
   }
   else
   {
      //Malformed DSA signature
      error = ERROR_INVALID_SIGNATURE;
   }

   //Free previously allocated resources
   dsaFreeSignature(&dsaSignature);

   //Return status code
   return error;
#else
   //DSA signature algorithm is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Verify ECDSA signature
 * @param[in] context Pointer to the TLS context
 * @param[in] digest Digest of the message whose signature is to be verified
 * @param[in] digestLen Length in octets of the digest
 * @param[in] signature Signature to be verified
 * @param[in] signatureLen Length of the signature to be verified
 * @return Error code
 **/

error_t tlsVerifyEcdsaSignature(TlsContext *context, const uint8_t *digest,
   size_t digestLen, const uint8_t *signature, size_t signatureLen)
{
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   EcdsaSignature ecdsaSignature;

   //Initialize ECDSA signature
   ecdsaInitSignature(&ecdsaSignature);

   //Read the ASN.1 encoded ECDSA signature
   error = ecdsaImportSignature(&ecdsaSignature,
      context->peerEcPublicKey.curve, signature, signatureLen,
      ECDSA_SIGNATURE_FORMAT_ASN1);

   //Check status code
   if(!error)
   {
#if (TLS_ECC_CALLBACK_SUPPORT == ENABLED)
      //Any registered callback?
      if(context->ecdsaVerifyCallback != NULL)
      {
         //Invoke user callback function
         error = context->ecdsaVerifyCallback(context, digest, digestLen,
            &ecdsaSignature);
      }
      else
#endif
      {
         //No callback function defined
         error = ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
      }

      //Check status code
      if(error == ERROR_UNSUPPORTED_ELLIPTIC_CURVE ||
         error == ERROR_UNSUPPORTED_HASH_ALGO)
      {
         //ECDSA signature verification
         error = ecdsaVerifySignature(&context->peerEcPublicKey, digest,
            digestLen, &ecdsaSignature);
      }
   }
   else
   {
      //Malformed ECDSA signature
      error = ERROR_INVALID_SIGNATURE;
   }

   //Free previously allocated resources
   ecdsaFreeSignature(&ecdsaSignature);

   //Return status code
   return error;
#else
   //ECDSA signature algorithm is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Verify Ed25519 signature
 * @param[in] context Pointer to the TLS context
 * @param[in] message Array of data chunks representing the message whose
 *   signature is to be verified
 * @param[in] messageLen Number of data chunks representing the message
 * @param[in] signature Signature to be verified
 * @param[in] signatureLen Length of the signature to be verified
 * @return Error code
 **/

error_t tlsVerifyEd25519Signature(TlsContext *context,
   const DataChunk *message, uint_t messageLen, const uint8_t *signature,
   size_t signatureLen)
{
#if (TLS_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Valid Ed25519 public key?
   if(context->peerEddsaPublicKey.curve == ED25519_CURVE)
   {
      //The Ed25519 signature shall consist of 32 octets
      if(signatureLen == ED25519_SIGNATURE_LEN)
      {
         //Verify Ed25519 signature (PureEdDSA mode)
         error = ed25519VerifySignatureEx(context->peerEddsaPublicKey.q,
            message, messageLen, NULL, 0, 0, signature);
      }
      else
      {
         //The length of the Ed25519 signature is not valid
         error = ERROR_INVALID_SIGNATURE;
      }
   }
   else
   {
      //The public key is not valid
      error = ERROR_INVALID_KEY;
   }

   //Return status code
   return error;
#else
   //Ed25519 signature algorithm is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Verify Ed448 signature
 * @param[in] context Pointer to the TLS context
 * @param[in] message Array of data chunks representing the message whose
 *   signature is to be verified
 * @param[in] messageLen Number of data chunks representing the message
 * @param[in] signature Signature to be verified
 * @param[in] signatureLen Length of the signature to be verified
 * @return Error code
 **/

error_t tlsVerifyEd448Signature(TlsContext *context,
   const DataChunk *message, uint_t messageLen, const uint8_t *signature,
   size_t signatureLen)
{
#if (TLS_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Valid Ed448 public key?
   if(context->peerEddsaPublicKey.curve == ED448_CURVE)
   {
      //The Ed448 signature shall consist of 32 octets
      if(signatureLen == ED448_SIGNATURE_LEN)
      {
         //Verify Ed448 signature (PureEdDSA mode)
         error = ed448VerifySignatureEx(context->peerEddsaPublicKey.q, message,
            messageLen, NULL, 0, 0, signature);
      }
      else
      {
         //The length of the Ed448 signature is not valid
         error = ERROR_INVALID_SIGNATURE;
      }
   }
   else
   {
      //The public key is not valid
      error = ERROR_INVALID_KEY;
   }

   //Return status code
   return error;
#else
   //Ed448 signature algorithm is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
