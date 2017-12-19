/**
 * @file tls_signature.c
 * @brief RSA/DSA/ECDSA signature generation and verification
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
#include "tls_signature.h"
#include "tls_misc.h"
#include "certificate/pem_import.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Select the hash algorithm to be used when generating signatures
 * @param[in] context Pointer to the TLS context
 * @param[in] signAlgo Desired signature algorithm (RSA, DSA or ECDSA)
 * @param[in] supportedSignAlgos List of supported signature/hash algorithm pairs
 * @return Error code
 **/

error_t tlsSelectSignHashAlgo(TlsContext *context,
   TlsSignatureAlgo signAlgo, const TlsSignHashAlgos *supportedSignAlgos)
{
   uint_t i;
   uint_t n;

   //Check whether the peer has provided a list of supported
   //hash/signature algorithm pairs?
   if(supportedSignAlgos != NULL)
   {
      //Process the list and select the relevant hash algorithm...
      context->signHashAlgo = TLS_HASH_ALGO_NONE;
      //Get the number of hash/signature algorithm pairs present in the list
      n = ntohs(supportedSignAlgos->length) / sizeof(TlsSignHashAlgo);

      //The hash algorithm to be used when generating signatures must be
      //one of those present in the list
      for(i = 0; i < n; i++)
      {
         //Acceptable signature algorithm found?
         if(supportedSignAlgos->value[i].signature == signAlgo)
         {
            //TLS operates as a client?
            if(context->entity == TLS_CONNECTION_END_CLIENT)
            {
               //Check whether the associated hash algorithm is supported
               if(tlsGetHashAlgo(supportedSignAlgos->value[i].hash) == context->cipherSuite.prfHashAlgo)
               {
                  context->signHashAlgo = (TlsHashAlgo) supportedSignAlgos->value[i].hash;
               }
#if (TLS_SHA1_SUPPORT == ENABLED)
               else if(supportedSignAlgos->value[i].hash == TLS_HASH_ALGO_SHA1)
               {
                  context->signHashAlgo = (TlsHashAlgo) supportedSignAlgos->value[i].hash;
               }
#endif
            }
            //TLS operates as a server?
            else
            {
               //Check whether the associated hash algorithm is supported
               switch(supportedSignAlgos->value[i].hash)
               {
#if (TLS_MD5_SUPPORT == ENABLED)
               //MD5 hash identifier?
               case TLS_HASH_ALGO_MD5:
#endif
#if (TLS_SHA1_SUPPORT == ENABLED)
               //SHA-1 hash identifier?
               case TLS_HASH_ALGO_SHA1:
#endif
#if (TLS_SHA224_SUPPORT == ENABLED)
               //SHA-224 hash identifier?
               case TLS_HASH_ALGO_SHA224:
#endif
#if (TLS_SHA256_SUPPORT == ENABLED)
               //SHA-256 hash identifier?
               case TLS_HASH_ALGO_SHA256:
#endif
#if (TLS_SHA384_SUPPORT == ENABLED)
               //SHA-384 hash identifier?
               case TLS_HASH_ALGO_SHA384:
#endif
#if (TLS_SHA512_SUPPORT == ENABLED)
               //SHA-512 hash identifier?
               case TLS_HASH_ALGO_SHA512:
#endif
                  //Select the hash algorithm to be used for signing
                  context->signHashAlgo = (TlsHashAlgo) supportedSignAlgos->value[i].hash;
                  break;
               default:
                  break;
               }
            }

            //Acceptable hash algorithm found?
            if(context->signHashAlgo != TLS_HASH_ALGO_NONE)
               break;
         }
      }
   }
   else
   {
      //Use default hash algorithm when generating RSA, DSA or ECDSA signatures
#if (TLS_SHA1_SUPPORT == ENABLED)
      context->signHashAlgo = TLS_HASH_ALGO_SHA1;
#elif (TLS_SHA224_SUPPORT == ENABLED)
      context->signHashAlgo = TLS_HASH_ALGO_SHA224;
#elif (TLS_SHA256_SUPPORT == ENABLED)
      context->signHashAlgo = TLS_HASH_ALGO_SHA256;
#elif (TLS_SHA384_SUPPORT == ENABLED)
      context->signHashAlgo = TLS_HASH_ALGO_SHA384;
#elif (TLS_SHA512_SUPPORT == ENABLED)
      context->signHashAlgo = TLS_HASH_ALGO_SHA512;
#endif
   }

   //If no acceptable choices are presented, return an error
   if(context->signHashAlgo == TLS_HASH_ALGO_NONE)
      return ERROR_FAILURE;

   //Successful processing
   return NO_ERROR;
}


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
      error = mpiReadRaw(&m, em, k);
      //Conversion failed?
      if(error)
         break;

      //Apply the RSASP1 signature primitive
      error = rsasp1(key, &m, &s);
      //Any error to report?
      if(error)
         break;

      //Convert the signature representative s to a signature of length k octets
      error = mpiWriteRaw(&s, signature, k);
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
      error = mpiReadRaw(&s, signature, signatureLen);
      //Conversion failed?
      if(error)
         break;

      //Apply the RSAVP1 verification primitive
      error = rsavp1(key, &s, &m);
      //Any error to report?
      if(error)
         break;

      //Convert the message representative m to an encoded message EM of length k octets
      error = mpiWriteRaw(&m, em, k);
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
            context->prngContext, &privateKey, digest, digestLen, &ecdsaSignature);
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

#endif
