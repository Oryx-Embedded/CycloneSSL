/**
 * @file tls_signature.c
 * @brief RSA/DSA/ECDSA signature generation and verification
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
 * @version 1.8.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include <string.h>
#include "tls.h"
#include "tls_handshake_hash.h"
#include "tls_signature.h"
#include "tls_misc.h"
#include "certificate/pem_import.h"
#include "pkc/rsa.h"
#include "pkc/dsa.h"
#include "ecc/ecdsa.h"
#include "ecc/ed25519.h"
#include "ecc/ed448.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Select the hash algorithm to be used when generating signatures
 * @param[in] context Pointer to the TLS context
 * @param[in] cert End entity certificate
 * @param[in] supportedSignAlgos List of supported signature/hash algorithm pairs
 * @return Error code
 **/

error_t tlsSelectSignHashAlgo(TlsContext *context, const TlsCertDesc *cert,
   const TlsSignHashAlgos *supportedSignAlgos)
{
   uint_t i;
   uint_t n;
   TlsHashAlgo hashAlgoId;
   const HashAlgo *hashAlgo;
   const TlsSignHashAlgo *p;

   //Default signature algorithm
   context->signAlgo = TLS_SIGN_ALGO_ANONYMOUS;
   context->signHashAlgo = TLS_HASH_ALGO_NONE;

   //RSA, DSA or ECDSA signature algorithm?
   if(cert->signAlgo == TLS_SIGN_ALGO_RSA ||
      cert->signAlgo == TLS_SIGN_ALGO_DSA ||
      cert->signAlgo == TLS_SIGN_ALGO_ECDSA)
   {
      //Check whether the peer has provided a list of supported hash/signature
      //algorithm pairs
      if(supportedSignAlgos != NULL)
      {
         //Process the list and select the relevant signature algorithm
         p = supportedSignAlgos->value;
         //Get the number of hash/signature algorithm pairs present in the list
         n = ntohs(supportedSignAlgos->length) / sizeof(TlsSignHashAlgo);

         //The hash algorithm to be used when generating signatures must be
         //one of those present in the list
         for(i = 0; i < n; i++)
         {
#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_DSA_SIGN_SUPPORT == ENABLED || \
   TLS_ECDSA_SIGN_SUPPORT == ENABLED)
            //RSASSA-PKCS1-v1_5, DSA or ECDSA signature scheme?
            if(p[i].signature == cert->signAlgo)
            {
               //Retrieve the hash algorithm identifier
               hashAlgoId = (TlsHashAlgo) p[i].hash;
            }
            else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
            //RSASSA-PSS signature scheme?
            if(p[i].hash == TLS_HASH_ALGO_INTRINSIC &&
               cert->signAlgo == TLS_SIGN_ALGO_RSA)
            {
               //The hashing is intrinsic to the signature algorithm
               if(p[i].signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256)
                  hashAlgoId = TLS_HASH_ALGO_SHA256;
               else if(p[i].signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384)
                  hashAlgoId = TLS_HASH_ALGO_SHA384;
               else if(p[i].signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512)
                  hashAlgoId = TLS_HASH_ALGO_SHA512;
               else
                  hashAlgoId = TLS_HASH_ALGO_NONE;
            }
            else
#endif
            //Invalid signature scheme?
            {
               hashAlgoId = TLS_HASH_ALGO_NONE;
            }

            //Get the hash algorithm that matches the specified identifier
            hashAlgo = tlsGetHashAlgo(hashAlgoId);

            //Check whether the hash algorithm is supported
            if(hashAlgo != NULL)
            {
               //The client implementation can only generate a CertificateVerify
               //using SHA-1 or the hash used by the PRF. Supporting all hash
               //algorithms would require the client to maintain hashes for every
               //possible signature algorithm that the server may request...
               if(context->entity == TLS_CONNECTION_END_SERVER ||
                  hashAlgoId == TLS_HASH_ALGO_SHA1 ||
                  hashAlgo == context->cipherSuite.prfHashAlgo)
               {
                  //Acceptable hash algorithm found
                  context->signAlgo = (TlsSignatureAlgo) p[i].signature;
                  context->signHashAlgo = (TlsHashAlgo) p[i].hash;
                  break;
               }
            }
         }
      }
      else
      {
         //Select the default hash algorithm to be used when generating RSA,
         //DSA or ECDSA signatures
         if(tlsGetHashAlgo(TLS_HASH_ALGO_SHA1) != NULL)
         {
            //Select SHA-1 hash algorithm
            context->signAlgo = cert->signAlgo;
            context->signHashAlgo = TLS_HASH_ALGO_SHA1;
         }
         else if(tlsGetHashAlgo(TLS_HASH_ALGO_SHA224) != NULL)
         {
            //Select SHA-224 hash algorithm
            context->signAlgo = cert->signAlgo;
            context->signHashAlgo = TLS_HASH_ALGO_SHA224;
         }
         else if(tlsGetHashAlgo(TLS_HASH_ALGO_SHA256) != NULL)
         {
            //Select SHA-256 hash algorithm
            context->signAlgo = cert->signAlgo;
            context->signHashAlgo = TLS_HASH_ALGO_SHA256;
         }
         else if(tlsGetHashAlgo(TLS_HASH_ALGO_SHA384) != NULL)
         {
            //Select SHA-384 hash algorithm
            context->signAlgo = cert->signAlgo;
            context->signHashAlgo = TLS_HASH_ALGO_SHA384;
         }
         else if(tlsGetHashAlgo(TLS_HASH_ALGO_SHA512) != NULL)
         {
            //Select SHA-512 hash algorithm
            context->signAlgo = cert->signAlgo;
            context->signHashAlgo = TLS_HASH_ALGO_SHA512;
         }
         else
         {
            //Just for sanity
         }
      }
   }
#if (TLS_ED25519_SUPPORT == ENABLED || TLS_ED448_SUPPORT == ENABLED)
   //EdDSA signature algorithm?
   else if(cert->signAlgo == TLS_SIGN_ALGO_ED25519 ||
      cert->signAlgo == TLS_SIGN_ALGO_ED448)
   {
      //Ed25519 and Ed448 are used in PureEdDSA mode, without pre-hashing
      context->signAlgo = cert->signAlgo;
      context->signHashAlgo = TLS_HASH_ALGO_INTRINSIC;
   }
#endif
   //Unsupported signature algorithm?
   else
   {
      //Just for sanity
   }

   //If no acceptable choices are presented, return an error
   if(context->signAlgo == TLS_SIGN_ALGO_ANONYMOUS ||
      context->signHashAlgo == TLS_HASH_ALGO_NONE)
   {
      return ERROR_FAILURE;
   }
   else
   {
      return NO_ERROR;
   }
}


#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)

/**
 * @brief Digital signature generation(SSL 3.0, TLS 1.0 or TLS 1.1)
 * @param[in] context Pointer to the TLS context
 * @param[out] p Buffer where to store the digitally-signed element
 * @param[out] length Length of the digitally-signed element
 * @return Error code
 **/

error_t tlsGenerateSignature(TlsContext *context, uint8_t *p,
   size_t *length)
{
   error_t error;
   size_t n;
   TlsDigitalSignature *signature;

   //Point to the digitally-signed element
   signature = (TlsDigitalSignature *) p;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
   //RSA certificate?
   if(context->cert->type == TLS_CERT_RSA_SIGN)
   {
      RsaPrivateKey privateKey;

      //Initialize RSA private key
      rsaInitPrivateKey(&privateKey);

      //Digest all the handshake messages starting at ClientHello using MD5
      error = tlsFinalizeHandshakeHash(context, MD5_HASH_ALGO,
         context->handshakeMd5Context, "", context->clientVerifyData);

      //Check status code
      if(!error)
      {
         //Digest all the handshake messages starting at ClientHello using SHA-1
         error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
            context->handshakeSha1Context, "",
            context->clientVerifyData + MD5_DIGEST_SIZE);
      }

      //Check status code
      if(!error)
      {
         //Decode the PEM structure that holds the RSA private key
         error = pemImportRsaPrivateKey(context->cert->privateKey,
            context->cert->privateKeyLen, &privateKey);
      }

      //Check status code
      if(!error)
      {
         //Generate a RSA signature using the client's private key
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
      error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
         context->handshakeSha1Context, "", context->clientVerifyData);

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
      error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
         context->handshakeSha1Context, "", context->clientVerifyData);

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
   //Invalid signature algorithm?
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
}


/**
 * @brief Digital signature verification (SSL 3.0, TLS 1.0 and TLS 1.1)
 * @param[in] context Pointer to the TLS context
 * @param[in] p Pointer to the digitally-signed element to be verified
 * @param[in] length Length of the digitally-signed element
 * @return Error code
 **/

error_t tlsVerifySignature(TlsContext *context, const uint8_t *p,
   size_t length)
{
   error_t error;
   const TlsDigitalSignature *signature;

   //Point to the digitally-signed element
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
      error = tlsFinalizeHandshakeHash(context, MD5_HASH_ALGO,
         context->handshakeMd5Context, "", context->clientVerifyData);

      //Check status code
      if(!error)
      {
         //Digest all the handshake messages starting at ClientHello using SHA-1
         error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
            context->handshakeSha1Context, "",
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
      error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
         context->handshakeSha1Context, "", context->clientVerifyData);

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
      error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
         context->handshakeSha1Context, "", context->clientVerifyData);

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
}

#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)

/**
 * @brief Digital signature generation(TLS 1.2)
 * @param[in] context Pointer to the TLS context
 * @param[out] p Buffer where to store the digitally-signed element
 * @param[out] length Length of the digitally-signed element
 * @return Error code
 **/

error_t tls12GenerateSignature(TlsContext *context, uint8_t *p,
   size_t *length)
{
   error_t error;
   size_t n;
   Tls12DigitalSignature *signature;
   const HashAlgo *hashAlgo;

   //Point to the digitally-signed element
   signature = (Tls12DigitalSignature *) p;

   //Retrieve the hash algorithm to be used for signing
   if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256)
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
   else if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384)
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
   else if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512)
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
   else
      hashAlgo = tlsGetHashAlgo(context->signHashAlgo);

   //Digest all the handshake messages starting at ClientHello
   if(hashAlgo == SHA1_HASH_ALGO)
   {
      //Use SHA-1 hash algorithm
      error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
         context->handshakeSha1Context, "", context->clientVerifyData);
   }
   else if(hashAlgo == context->cipherSuite.prfHashAlgo)
   {
      //Use PRF hash algorithm (SHA-256 or SHA-384)
      error = tlsFinalizeHandshakeHash(context, hashAlgo,
         context->handshakeHashContext, "", context->clientVerifyData);
   }
   else
   {
      //The specified hash algorithm is not supported
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Handshake message hash successfully computed?
   if(!error)
   {
#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
      //RSA certificate?
      if(context->cert->type == TLS_CERT_RSA_SIGN)
      {
         RsaPrivateKey privateKey;

         //Initialize RSA private key
         rsaInitPrivateKey(&privateKey);

         //Decode the PEM structure that holds the RSA private key
         error = pemImportRsaPrivateKey(context->cert->privateKey,
            context->cert->privateKeyLen, &privateKey);

         //Check status code
         if(!error)
         {
#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
            //RSASSA-PKCS1-v1_5 signature scheme?
            if(context->signAlgo == TLS_SIGN_ALGO_RSA)
            {
               //Set the relevant signature algorithm
               signature->algorithm.signature = TLS_SIGN_ALGO_RSA;
               signature->algorithm.hash = context->signHashAlgo;

               //Generate RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
               error = rsassaPkcs1v15Sign(&privateKey, hashAlgo,
                  context->clientVerifyData, signature->value, &n);
            }
            else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
            //RSASSA-PSS signature scheme?
            if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256 ||
               context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384 ||
               context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512)
            {
               //Set the relevant signature algorithm
               signature->algorithm.signature = context->signAlgo;
               signature->algorithm.hash = TLS_HASH_ALGO_INTRINSIC;

               //Generate RSA signature (RSASSA-PSS signature scheme)
               error = rsassaPssSign(context->prngAlgo, context->prngContext,
                  &privateKey, hashAlgo, hashAlgo->digestSize,
                  context->clientVerifyData, signature->value, &n);
            }
            else
#endif
            //Invalid signature scheme?
            {
               //Report an error
               error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
            }
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
         //Set the relevant signature algorithm
         signature->algorithm.signature = TLS_SIGN_ALGO_DSA;
         signature->algorithm.hash = context->signHashAlgo;

         //Generate a DSA signature using the client's private key
         error = tlsGenerateDsaSignature(context, context->clientVerifyData,
            hashAlgo->digestSize, signature->value, &n);
      }
      else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
      //ECDSA certificate?
      if(context->cert->type == TLS_CERT_ECDSA_SIGN)
      {
         //Set the relevant signature algorithm
         signature->algorithm.signature = TLS_SIGN_ALGO_ECDSA;
         signature->algorithm.hash = context->signHashAlgo;

         //Generate an ECDSA signature using the client's private key
         error = tlsGenerateEcdsaSignature(context, context->clientVerifyData,
            hashAlgo->digestSize, signature->value, &n);
      }
      else
#endif
      //Invalid signature algorithm?
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
   error_t error;
   const Tls12DigitalSignature *signature;
   const HashAlgo *hashAlgo;

   //Point to the digitally-signed element
   signature = (Tls12DigitalSignature *) p;

   //Check the length of the digitally-signed element
   if(length < sizeof(Tls12DigitalSignature))
      return ERROR_DECODING_FAILED;
   if(length != (sizeof(Tls12DigitalSignature) + ntohs(signature->length)))
      return ERROR_DECODING_FAILED;

   //Retrieve the hash algorithm used for signing
   if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256)
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
   else if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384)
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
   else if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512)
      hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
   else
      hashAlgo = tlsGetHashAlgo(signature->algorithm.hash);

   //Digest all the handshake messages starting at ClientHello
   if(hashAlgo == SHA1_HASH_ALGO)
   {
      //Use SHA-1 hash algorithm
      error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
         context->handshakeSha1Context, "", context->clientVerifyData);
   }
   else if(hashAlgo == context->cipherSuite.prfHashAlgo)
   {
      //Use PRF hash algorithm (SHA-256 or SHA-384)
      error = tlsFinalizeHandshakeHash(context, hashAlgo,
         context->handshakeHashContext, "", context->clientVerifyData);
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
      if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA)
      {
         //Verify RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
         error = rsassaPkcs1v15Verify(&context->peerRsaPublicKey, hashAlgo,
            context->clientVerifyData, signature->value, ntohs(signature->length));
      }
      else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
      //RSASSA-PSS signature scheme?
      if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256 ||
         signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384 ||
         signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512)
      {
         //Verify RSA signature (RSASSA-PSS signature scheme)
         error = rsassaPssVerify(&context->peerRsaPublicKey, hashAlgo,
            hashAlgo->digestSize, context->clientVerifyData, signature->value,
            ntohs(signature->length));
      }
      else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
      //DSA signature scheme?
      if(signature->algorithm.signature == TLS_SIGN_ALGO_DSA)
      {
         //Verify DSA signature using client's public key
         error = tlsVerifyDsaSignature(context, context->clientVerifyData,
            hashAlgo->digestSize, signature->value, ntohs(signature->length));
      }
      else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
      //ECDSA signature scheme?
      if(signature->algorithm.signature == TLS_SIGN_ALGO_ECDSA)
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
}

#endif
#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)

/**
 * @brief Generate RSA signature (SSL 3.0, TLS 1.0 and TLS 1.1)
 * @param[in] key Signer's RSA private key
 * @param[in] digest Digest of the message to be signed
 * @param[out] signature Resulting signature
 * @param[out] signatureLen Length of the resulting signature
 * @return Error code
 **/

error_t tlsGenerateRsaSignature(const RsaPrivateKey *key,
   const uint8_t *digest, uint8_t *signature, size_t *signatureLen)
{
#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_DHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_RSA_SUPPORT == ENABLED)
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
   memset(em + 2, 0xFF, paddingLen);
   //Append a 0x00 octet to PS
   em[paddingLen + 2] = 0x00;

   //Append the digest value
   memcpy(em + paddingLen + 3, digest, MD5_DIGEST_SIZE + SHA1_DIGEST_SIZE);

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
   //RSA signature generation is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Verify RSA signature (SSL 3.0, TLS 1.0 and TLS 1.1)
 * @param[in] key Signer's RSA public key
 * @param[in] digest Digest of the message whose signature is to be verified
 * @param[in] signature Signature to be verified
 * @param[in] signatureLen Length of the signature to be verified
 * @return Error code
 **/

error_t tlsVerifyRsaSignature(const RsaPublicKey *key,
   const uint8_t *digest, const uint8_t *signature, size_t signatureLen)
{
#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_DHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_RSA_SUPPORT == ENABLED)
   error_t error;
   uint_t i;
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

      //Assume an error...
      error = ERROR_INVALID_SIGNATURE;

      //The first octet of EM must have a value of 0x00
      if(em[0] != 0x00)
         break;
      //The block type BT shall be 0x01
      if(em[1] != 0x01)
         break;

      //Check the padding string PS
      for(i = 2; i < k; i++)
      {
         //A 0x00 octet indicates the end of the padding string
         if(em[i] == 0x00)
            break;

         //Each byte of PS must be set to 0xFF when the block type is 0x01
         if(em[i] != 0xFF)
            break;
      }

      //Check whether the padding string is properly terminated
      if(i >= k || em[i] != 0x00)
         break;

      //The length of PS cannot be less than 8 octets
      if(i < 10)
         break;

      //Check the length of the digest
      if((k - i - 1) != (MD5_DIGEST_SIZE + SHA1_DIGEST_SIZE))
         break;
      //Check the digest value
      if(memcmp(digest, em + i + 1, MD5_DIGEST_SIZE + SHA1_DIGEST_SIZE))
         break;

      //The RSA signature is valid
      error = NO_ERROR;

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
   //RSA signature verification is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif


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
#if (TLS_DSA_SIGN_SUPPORT == ENABLED || TLS_DHE_DSS_SUPPORT == ENABLED)
   error_t error;
   DsaPrivateKey privateKey;
   DsaSignature dsaSignature;

   //Initialize DSA private key
   dsaInitPrivateKey(&privateKey);
   //Initialize DSA signature
   dsaInitSignature(&dsaSignature);

   //Decode the PEM structure that holds the DSA private key
   error = pemImportDsaPrivateKey(context->cert->privateKey,
      context->cert->privateKeyLen, &privateKey);

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
      error = dsaWriteSignature(&dsaSignature, signature, signatureLen);
   }

   //Free previously allocated resources
   dsaFreePrivateKey(&privateKey);
   dsaFreeSignature(&dsaSignature);

   //Return status code
   return error;
#else
   //DSA signature generation is not supported
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
#if (TLS_DSA_SIGN_SUPPORT == ENABLED || TLS_DHE_DSS_SUPPORT == ENABLED)
   error_t error;
   DsaSignature dsaSignature;

   //Initialize DSA signature
   dsaInitSignature(&dsaSignature);

   //Read the ASN.1 encoded DSA signature
   error = dsaReadSignature(signature, signatureLen, &dsaSignature);

   //Check status code
   if(!error)
   {
      //DSA signature verification
      error = dsaVerifySignature(&context->peerDsaPublicKey,
         digest, digestLen, &dsaSignature);
   }

   //Free previously allocated resources
   dsaFreeSignature(&dsaSignature);

   //Return status code
   return error;
#else
   //DSA signature verification is not supported
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
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED || TLS_ECDHE_ECDSA_SUPPORT == ENABLED)
   error_t error;
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
      EcDomainParameters params;
      Mpi privateKey;

      //Initialize EC domain parameters
      ecInitDomainParameters(&params);
      //Initialize EC private key
      mpiInit(&privateKey);

      //Decode the PEM structure that holds the EC domain parameters
      error = pemImportEcParameters(context->cert->privateKey,
         context->cert->privateKeyLen, &params);

      //Check status code
      if(!error)
      {
         //Decode the PEM structure that holds the EC private key
         error = pemImportEcPrivateKey(context->cert->privateKey,
            context->cert->privateKeyLen, &privateKey);
      }

      //Check status code
      if(!error)
      {
         //Generate ECDSA signature
         error = ecdsaGenerateSignature(&params, context->prngAlgo,
            context->prngContext, &privateKey, digest, digestLen,
            &ecdsaSignature);
      }

      //Release previously allocated resources
      ecFreeDomainParameters(&params);
      mpiFree(&privateKey);
   }

   //Check status code
   if(!error)
   {
      //Encode the resulting (R, S) integer pair using ASN.1
      error = ecdsaWriteSignature(&ecdsaSignature, signature, signatureLen);
   }

   //Release previously allocated resources
   ecdsaFreeSignature(&ecdsaSignature);

   //Return status code
   return error;
#else
   //ECDSA signature generation is not supported
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
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED || TLS_ECDHE_ECDSA_SUPPORT == ENABLED)
   error_t error;
   EcdsaSignature ecdsaSignature;

   //Initialize ECDSA signature
   ecdsaInitSignature(&ecdsaSignature);

   //Read the ASN.1 encoded ECDSA signature
   error = ecdsaReadSignature(signature, signatureLen, &ecdsaSignature);

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
         error = ecdsaVerifySignature(&context->peerEcParams,
            &context->peerEcPublicKey, digest, digestLen, &ecdsaSignature);
      }
   }

   //Free previously allocated resources
   ecdsaFreeSignature(&ecdsaSignature);

   //Return status code
   return error;
#else
   //ECDSA signature verification is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Generate EdDSA signature
 * @param[in] context Pointer to the TLS context
 * @param[in] message Pointer to the message to be signed
 * @param[in] messageLen Length of the message, in bytes
 * @param[out] signature Resulting signature
 * @param[out] signatureLen Length of the resulting signature
 * @return Error code
 **/

error_t tlsGenerateEddsaSignature(TlsContext *context, const uint8_t *message,
   size_t messageLen, uint8_t *signature, size_t *signatureLen)
{
   error_t error;

#if (TLS_ED25519_SUPPORT == ENABLED)
   //Ed25519 elliptic curve?
   if(context->cert->type == TLS_CERT_ED25519_SIGN)
   {
      EddsaPrivateKey privateKey;

      //Initialize EdDSA private key
      eddsaInitPrivateKey(&privateKey);

      //Decode the PEM structure that holds the EdDSA private key
      error = pemImportEddsaPrivateKey(context->cert->privateKey,
         context->cert->privateKeyLen, &privateKey);

      //Check the length of the EdDSA private key
      if(mpiGetByteLength(&privateKey.d) == ED25519_PRIVATE_KEY_LEN)
      {
         uint8_t d[ED25519_PRIVATE_KEY_LEN];

         //Retrieve private key
         error = mpiExport(&privateKey.d, d, ED25519_PRIVATE_KEY_LEN,
            MPI_FORMAT_LITTLE_ENDIAN);

         //Check status code
         if(!error)
         {
            //Generate Ed25519 signature (PureEdDSA mode)
            error = ed25519GenerateSignature(d, NULL, message, messageLen,
               NULL, 0, 0, signature);
         }

         //Length of the resulting EdDSA signature
         *signatureLen = ED25519_SIGNATURE_LEN;
      }
      else
      {
         //The length of the EdDSA private key is not valid
         error = ERROR_INVALID_KEY;
      }

      //Free previously allocated resources
      eddsaFreePrivateKey(&privateKey);
   }
   else
#endif
#if (TLS_ED448_SUPPORT == ENABLED)
   //Ed448 elliptic curve?
   if(context->cert->type == TLS_CERT_ED448_SIGN)
   {
      EddsaPrivateKey privateKey;

      //Initialize EdDSA private key
      eddsaInitPrivateKey(&privateKey);

      //Decode the PEM structure that holds the EdDSA private key
      error = pemImportEddsaPrivateKey(context->cert->privateKey,
         context->cert->privateKeyLen, &privateKey);

      //Check the length of the EdDSA private key
      if(mpiGetByteLength(&privateKey.d) == ED448_PRIVATE_KEY_LEN)
      {
         uint8_t d[ED448_PRIVATE_KEY_LEN];

         //Retrieve private key
         error = mpiExport(&privateKey.d, d, ED448_PRIVATE_KEY_LEN,
            MPI_FORMAT_LITTLE_ENDIAN);

         //Check status code
         if(!error)
         {
            //Generate Ed448 signature (PureEdDSA mode)
            error = ed448GenerateSignature(d, NULL, message, messageLen,
               NULL, 0, 0, signature);
         }

         //Length of the resulting EdDSA signature
         *signatureLen = ED448_SIGNATURE_LEN;
      }
      else
      {
         //The length of the EdDSA private key is not valid
         error = ERROR_INVALID_KEY;
      }

      //Free previously allocated resources
      eddsaFreePrivateKey(&privateKey);
   }
   else
#endif
   //Invalid signature algorithm?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Verify EdDSA signature
 * @param[in] context Pointer to the TLS context
 * @param[in] message Message whose signature is to be verified
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] signature Signature to be verified
 * @param[in] signatureLen Length of the signature to be verified
 * @return Error code
 **/

error_t tlsVerifyEddsaSignature(TlsContext *context, const uint8_t *message,
   size_t messageLen, const uint8_t *signature, size_t signatureLen)
{
   error_t error;

#if (TLS_ED25519_SUPPORT == ENABLED)
   //Ed25519 elliptic curve?
   if(context->peerEcParams.type == EC_CURVE_TYPE_ED25519)
   {
      //Check the length of the EdDSA signature
      if(signatureLen == ED25519_SIGNATURE_LEN)
      {
         uint8_t publicKey[ED25519_PUBLIC_KEY_LEN];

         //Get peer's public key
         error = mpiExport(&context->peerEcPublicKey.x, publicKey,
            ED25519_PUBLIC_KEY_LEN, MPI_FORMAT_LITTLE_ENDIAN);

         //Check status code
         if(!error)
         {
            //Verify Ed25519 signature (PureEdDSA mode)
            error = ed25519VerifySignature(publicKey, message, messageLen,
               NULL, 0, 0, signature);
         }
      }
      else
      {
         //The length of the EdDSA signature is not valid
         error = ERROR_INVALID_SIGNATURE;
      }
   }
   else
#endif
#if (TLS_ED448_SUPPORT == ENABLED)
   //Ed448 elliptic curve?
   if(context->peerEcParams.type == EC_CURVE_TYPE_ED448)
   {
      //Check the length of the EdDSA signature
      if(signatureLen == ED448_SIGNATURE_LEN)
      {
         uint8_t publicKey[ED448_PUBLIC_KEY_LEN];

         //Get peer's public key
         error = mpiExport(&context->peerEcPublicKey.x, publicKey,
            ED448_PUBLIC_KEY_LEN, MPI_FORMAT_LITTLE_ENDIAN);

         //Check status code
         if(!error)
         {
            //Verify Ed448 signature (PureEdDSA mode)
            error = ed448VerifySignature(publicKey, message, messageLen,
               NULL, 0, 0, signature);
         }
      }
      else
      {
         //The length of the EdDSA signature is not valid
         error = ERROR_INVALID_SIGNATURE;
      }
   }
   else
#endif
   //Invalid signature algorithm?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
}

#endif
