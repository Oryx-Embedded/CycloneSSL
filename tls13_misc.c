/**
 * @file tls13_misc.c
 * @brief TLS 1.3 helper functions
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
#include "tls_cipher_suites.h"
#include "tls_extensions.h"
#include "tls_certificate.h"
#include "tls_transcript_hash.h"
#include "tls_ffdhe.h"
#include "tls_record.h"
#include "tls_misc.h"
#include "tls13_key_material.h"
#include "tls13_ticket.h"
#include "tls13_misc.h"
#include "kdf/hkdf.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_MAX_VERSION >= TLS_VERSION_1_3)

//Downgrade protection mechanism (TLS 1.1 or below)
const uint8_t tls11DowngradeRandom[8] =
{
   0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00
};

//Downgrade protection mechanism (TLS 1.2)
const uint8_t tls12DowngradeRandom[8] =
{
   0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01
};

//Special random value for HelloRetryRequest message
const uint8_t tls13HelloRetryRequestRandom[32] =
{
   0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
   0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
   0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
   0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};


/**
 * @brief Compute PSK binder value
 * @param[in] context Pointer to the TLS context
 * @param[in] clientHello Pointer to the ClientHello message
 * @param[in] clientHelloLen Length of the ClientHello message
 * @param[in] truncatedClientHelloLen Length of the partial ClientHello message
 * @param[in] identity Pointer to the PSK identity
 * @param[out] binder Buffer where to store the resulting PSK binder
 * @param[in] binderLen Expected length of the PSK binder
 * @return Error code
 **/

error_t tls13ComputePskBinder(TlsContext *context, const void *clientHello,
   size_t clientHelloLen, size_t truncatedClientHelloLen,
   const Tls13PskIdentity *identity, uint8_t *binder, size_t binderLen)
{
   error_t error;
   const HashAlgo *hash;
   uint8_t *hashContext;
   uint8_t key[TLS_MAX_HKDF_DIGEST_SIZE];
   uint8_t digest[TLS_MAX_HKDF_DIGEST_SIZE];

   //Check parameters
   if(truncatedClientHelloLen >= clientHelloLen)
      return ERROR_INVALID_PARAMETER;

   //The hash function used by HKDF is the cipher suite hash algorithm
   hash = context->cipherSuite.prfHashAlgo;
   //Make sure the hash algorithm is valid
   if(hash == NULL)
      return ERROR_FAILURE;

   //Check the length of the PSK binder
   if(binderLen != hash->digestSize)
      return ERROR_INVALID_LENGTH;

   //Allocate a memory buffer to hold the hash context
   hashContext = tlsAllocMem(hash->contextSize);
   //Failed to allocate memory?
   if(hashContext == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Intialize transcript hash
   if(context->transcriptHashContext != NULL)
   {
      osMemcpy(hashContext, context->transcriptHashContext, hash->contextSize);
   }
   else
   {
      hash->init(hashContext);
   }

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      DtlsHandshake header;

      //Handshake message type
      header.msgType = TLS_TYPE_CLIENT_HELLO;
      //Number of bytes in the message
      STORE24BE(clientHelloLen, header.length);
      //Message sequence number
      header.msgSeq = htons(context->txMsgSeq);
      //Fragment offset
      STORE24BE(0, header.fragOffset);
      //Fragment length
      STORE24BE(clientHelloLen, header.fragLength);

      //Digest the handshake message header
      hash->update(hashContext, &header, sizeof(DtlsHandshake));
   }
   else
#endif
   //TLS protocol?
   {
      TlsHandshake header;

      //Handshake message type
      header.msgType = TLS_TYPE_CLIENT_HELLO;
      //Number of bytes in the message
      STORE24BE(clientHelloLen, header.length);

      //Digest the handshake message header
      hash->update(hashContext, &header, sizeof(TlsHandshake));
   }

   //Digest the partial ClientHello
   hash->update(hashContext, clientHello, truncatedClientHelloLen);
   //Calculate transcript hash
   hash->final(hashContext, digest);

   //Release previously allocated memory
   tlsFreeMem(hashContext);

   //Debug message
   TRACE_DEBUG("Transcript hash (partial ClientHello):\r\n");
   TRACE_DEBUG_ARRAY("  ", digest, hash->digestSize);

   //Although PSKs can be established out of band, PSKs can also be established
   //in a previous connection
   if(tls13IsPskValid(context))
   {
      //Calculate early secret
      error = hkdfExtract(hash, context->psk, context->pskLen, NULL, 0,
         context->secret);
      //Any error to report?
      if(error)
         return error;

      //Debug message
      TRACE_DEBUG("Early secret:\r\n");
      TRACE_DEBUG_ARRAY("  ", context->secret, hash->digestSize);

      //Calculate binder key
      error = tls13DeriveSecret(context, context->secret, hash->digestSize,
         "ext binder", "", 0, key, hash->digestSize);
      //Any error to report?
      if(error)
         return error;
   }
   else if(tls13IsTicketValid(context))
   {
      //Calculate early secret
      error = hkdfExtract(hash, context->ticketPsk, context->ticketPskLen,
         NULL, 0, context->secret);
      //Any error to report?
      if(error)
         return error;

      //Debug message
      TRACE_DEBUG("Early secret:\r\n");
      TRACE_DEBUG_ARRAY("  ", context->secret, hash->digestSize);

      //Calculate binder key
      error = tls13DeriveSecret(context, context->secret, hash->digestSize,
         "res binder", "", 0, key, hash->digestSize);
      //Any error to report?
      if(error)
         return error;
   }
   else
   {
      //The pre-shared key is not valid
      return ERROR_FAILURE;
   }

   //Debug message
   TRACE_DEBUG("Binder key:\r\n");
   TRACE_DEBUG_ARRAY("  ", key, hash->digestSize);

   //The PskBinderEntry is computed in the same way as the Finished message
   //but with the base key being the binder key
   error = tls13HkdfExpandLabel(context->transportProtocol, hash, key,
      hash->digestSize, "finished", NULL, 0, key, hash->digestSize);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("Finished key:\r\n");
   TRACE_DEBUG_ARRAY("  ", key, hash->digestSize);

   //Compute PSK binder
   error = hmacCompute(hash, key, hash->digestSize, digest, hash->digestSize,
      binder);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("PSK binder:\r\n");
   TRACE_DEBUG_ARRAY("  ", binder, binderLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Key share generation
 * @param[in] context Pointer to the TLS context
 * @param[in] namedGroup Named group
 * @return Error code
 **/

error_t tls13GenerateKeyShare(TlsContext *context, uint16_t namedGroup)
{
   error_t error;

#if ((TLS13_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED) && \
   TLS_FFDHE_SUPPORT == ENABLED)
   //Finite field group?
   if(tls13IsFfdheGroupSupported(context, namedGroup))
   {
      const TlsFfdheGroup *ffdheGroup;

      //Get the FFDHE parameters that match the specified named group
      ffdheGroup = tlsGetFfdheGroup(context, namedGroup);

      //Valid FFDHE group?
      if(ffdheGroup != NULL)
      {
         //Save the named group
         context->namedGroup = namedGroup;

         //Load FFDHE parameters
         error = tlsLoadFfdheParameters(&context->dhContext.params, ffdheGroup);

         //Check status code
         if(!error)
         {
            //Generate an ephemeral key pair
            error = dhGenerateKeyPair(&context->dhContext, context->prngAlgo,
               context->prngContext);
         }
      }
      else
      {
         //The specified FFDHE group is not supported
         error = ERROR_ILLEGAL_PARAMETER;
      }
   }
   else
#endif
#if (TLS13_ECDHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //Elliptic curve group?
   if(tls13IsEcdheGroupSupported(context, namedGroup))
   {
      const EcCurve *curve;

      //Retrieve the elliptic curve to be used
      curve = tlsGetCurve(context, namedGroup);

      //Valid elliptic curve?
      if(curve != NULL)
      {
         //Save the named group
         context->namedGroup = namedGroup;

         //Save elliptic curve parameters
         error = ecdhSetCurve(&context->ecdhContext, curve);

         //Check status code
         if(!error)
         {
            //Generate an ephemeral key pair
            error = ecdhGenerateKeyPair(&context->ecdhContext,
               context->prngAlgo, context->prngContext);
         }
      }
      else
      {
         //Unsupported elliptic curve
         error = ERROR_ILLEGAL_PARAMETER;
      }
   }
   else
#endif
#if (TLS13_MLKEM_KE_SUPPORT == ENABLED || TLS13_PSK_MLKEM_KE_SUPPORT == ENABLED)
   //ML-KEM key exchange method?
   if(tls13IsMlkemGroupSupported(context, namedGroup))
   {
      const KemAlgo *kemAlgo;

      //Retrieve the ML-KEM algorithm to be used
      kemAlgo = tls13GetMlkemAlgo(context, namedGroup);

      //Valid algorithm?
      if(kemAlgo != NULL)
      {
         //Save the named group
         context->namedGroup = namedGroup;

         //Initialize KEM context
         kemFree(&context->kemContext);
         kemInit(&context->kemContext, kemAlgo);

         //Generate a public key pk and a secret key sk
         error = kemGenerateKeyPair(&context->kemContext, context->prngAlgo,
            context->prngContext);
      }
      else
      {
         //Unsupported ML-KEM key exchange method
         error = ERROR_ILLEGAL_PARAMETER;
      }
   }
   else
#endif
#if (TLS13_HYBRID_KE_SUPPORT == ENABLED || TLS13_PSK_HYBRID_KE_SUPPORT == ENABLED)
   //Hybrid key exchange method?
   if(tls13IsHybridGroupSupported(context, namedGroup))
   {
      const EcCurve *curve;
      const KemAlgo *kemAlgo;

      //Retrieve the traditional and the next-gen algorithms to be used
      curve = tls13GetTraditionalAlgo(context, namedGroup);
      kemAlgo = tls13GetNextGenAlgo(context, namedGroup);

      //Valid algorithms?
      if(curve != NULL && kemAlgo != NULL)
      {
         //Save the named group
         context->namedGroup = namedGroup;

         //Save elliptic curve parameters
         error = ecdhSetCurve(&context->ecdhContext, curve);

         //Check status code
         if(!error)
         {
            //DH key exchange can be modeled as a KEM, with KeyGen corresponding
            //to selecting an exponent x as the secret key and computing the
            //public key g^x
            error = ecdhGenerateKeyPair(&context->ecdhContext,
               context->prngAlgo, context->prngContext);
         }

         //Check status code
         if(!error)
         {
            //Initialize KEM context
            kemFree(&context->kemContext);
            kemInit(&context->kemContext, kemAlgo);

            //Generate a public key pk and a secret key sk
            error = kemGenerateKeyPair(&context->kemContext, context->prngAlgo,
               context->prngContext);
         }
      }
      else
      {
         //Unsupported hybrid key exchange method
         error = ERROR_ILLEGAL_PARAMETER;
      }
   }
   else
#endif
   //Unknown group?
   {
      //Report an error
      error = ERROR_ILLEGAL_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief (EC)DHE shared secret generation
 * @param[in] context Pointer to the TLS context
 * @param[in] keyShare Pointer to the peer's (EC)DHE parameters
 * @param[in] length Length of the (EC)DHE parameters, in bytes
 * @return Error code
 **/

error_t tls13GenerateSharedSecret(TlsContext *context, const uint8_t *keyShare,
   size_t length)
{
   error_t error;

#if (TLS13_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED)
   //Finite field group?
   if(tls13IsFfdheGroupSupported(context, context->namedGroup))
   {
      size_t n;

      //Retrieve the length of the modulus
      n = mpiGetByteLength(&context->dhContext.params.p);

      //For a given Diffie-Hellman group, the padding results in all public
      //keys having the same length (refer to RFC 8446, section 4.2.8.1)
      if(length == n)
      {
         //The Diffie-Hellman public value is encoded as a big-endian integer
         error = dhImportPeerPublicKey(&context->dhContext, keyShare, length,
            MPI_FORMAT_BIG_ENDIAN);

         //Check status code
         if(!error)
         {
            //The negotiated key (Z) is converted to a byte string by encoding
            //in big-endian and left padded with zeros up to the size of the
            //prime (refer to RFC 8446, section 7.4.1)
            error = dhComputeSharedSecret(&context->dhContext,
               context->premasterSecret, TLS_PREMASTER_SECRET_SIZE,
               &context->premasterSecretLen);
         }
      }
      else
      {
         //The length of the public key is not valid
         error = ERROR_ILLEGAL_PARAMETER;
      }
   }
   else
#endif
#if (TLS13_ECDHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //Elliptic curve group?
   if(tls13IsEcdheGroupSupported(context, context->namedGroup))
   {
      //Read peer's public key (refer to RFC 8446, section 4.2.8.2)
      error = ecdhImportPeerPublicKey(&context->ecdhContext,
         keyShare, length, EC_PUBLIC_KEY_FORMAT_X963);

      //Check status code
      if(!error)
      {
         //ECDH shared secret calculation is performed according to IEEE Std
         //1363-2000 (refer to RFC 8446, section 7.4.2)
         error = ecdhComputeSharedSecret(&context->ecdhContext,
            context->premasterSecret, TLS_PREMASTER_SECRET_SIZE,
            &context->premasterSecretLen);
      }
   }
   else
#endif
   //Unknown group?
   {
      //Report an error
      error = ERROR_HANDSHAKE_FAILED;
   }

   //Return status code
   return error;
}


/**
 * @brief Encapsulation algorithm
 * @param[in] context Pointer to the TLS context
 * @param[in] namedGroup Named group
 * @param[in] keyShare Pointer to the client's key share
 * @param[in] length Length of the client's key share, in bytes
 * @return Error code
 **/

error_t tls13Encapsulate(TlsContext *context, uint16_t namedGroup,
   const uint8_t *keyShare, size_t length)
{

   error_t error;

#if (TLS13_MLKEM_KE_SUPPORT == ENABLED || TLS13_PSK_MLKEM_KE_SUPPORT == ENABLED)
   //ML-KEM key exchange method?
   if(tls13IsMlkemGroupSupported(context, namedGroup))
   {
      const KemAlgo *kemAlgo;

      //Retrieve the ML-KEM algorithm to be used
      kemAlgo = tls13GetMlkemAlgo(context, namedGroup);

      //Valid algorithm?
      if(kemAlgo != NULL)
      {
         //The length of the public key is fixed
         if(length == kemAlgo->publicKeySize)
         {
            //Save the named group
            context->namedGroup = namedGroup;

            //Initialize KEM context
            kemFree(&context->kemContext);
            kemInit(&context->kemContext, kemAlgo);

            //The encapsulation algorithm takes as input a public key pk and
            //outputs a ciphertext ct and shared secret ss
            error = kemLoadPublicKey(&context->kemContext, keyShare);
         }
         else
         {
            //The length of the key share is not valid
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }
      else
      {
         //Unsupported ML-KEM key exchange method
         error = ERROR_ILLEGAL_PARAMETER;
      }
   }
   else
#endif
#if (TLS13_HYBRID_KE_SUPPORT == ENABLED || TLS13_PSK_HYBRID_KE_SUPPORT == ENABLED)
   //Hybrid key exchange method?
   if(tls13IsHybridGroupSupported(context, namedGroup))
   {
      size_t keyShareOffset;
      size_t sharedSecretOffset;
      const EcCurve *curve;
      const KemAlgo *kemAlgo;

      //Retrieve the traditional and the next-gen algorithms to be used
      curve = tls13GetTraditionalAlgo(context, namedGroup);
      kemAlgo = tls13GetNextGenAlgo(context, namedGroup);

      //Valid algorithms?
      if(curve != NULL && kemAlgo != NULL)
      {
         //The client's share is a fixed-size concatenation of the ECDH ephemeral
         //key share and the pk outputs of the KEM KeyGen algorithm
         if(length > kemAlgo->publicKeySize)
         {
            //Save the named group
            context->namedGroup = namedGroup;

            //Initialize KEM context
            kemFree(&context->kemContext);
            kemInit(&context->kemContext, kemAlgo);

            //NIST's special publication 800-56C approves the usage of HKDF with two
            //distinct shared secrets, with the condition that the first one is
            //computed by a FIPS-approved key-establishment scheme
            if(context->namedGroup == TLS_GROUP_X25519_MLKEM768)
            {
               keyShareOffset = kemAlgo->publicKeySize;
               sharedSecretOffset = kemAlgo->sharedSecretSize;
            }
            else
            {
               keyShareOffset = 0;
               sharedSecretOffset = 0;
            }

            //Save elliptic curve parameters
            error = ecdhSetCurve(&context->ecdhContext, curve);

            //Check status code
            if(!error)
            {
               //DH key exchange can be modeled as a KEM, with encapsulation
               //corresponding to selecting an exponent y, computing the
               //ciphertext g^y and the shared secret g^(xy)
               error = ecdhGenerateKeyPair(&context->ecdhContext,
                  context->prngAlgo, context->prngContext);
            }

            //Check status code
            if(!error)
            {
               //The ECDHE share is the serialized value of the uncompressed ECDH
               //point representation
               error = ecdhImportPeerPublicKey(&context->ecdhContext,
                  keyShare + keyShareOffset, length - kemAlgo->publicKeySize,
                  EC_PUBLIC_KEY_FORMAT_X963);
            }

            //Check status code
            if(!error)
            {
               //Compute the shared secret g^(xy)
               error = ecdhComputeSharedSecret(&context->ecdhContext,
                  context->premasterSecret + sharedSecretOffset,
                  TLS_PREMASTER_SECRET_SIZE - sharedSecretOffset,
                  &context->premasterSecretLen);
            }

            //Check status code
            if(!error)
            {
               //X25519MLKEM768 group?
               if(context->namedGroup == TLS_GROUP_X25519_MLKEM768)
               {
                  keyShareOffset = 0;
               }
               else
               {
                  keyShareOffset = length - kemAlgo->publicKeySize;
               }

               //The encapsulation algorithm takes as input a public key pk and
               //outputs a ciphertext ct and shared secret ss
               error = kemLoadPublicKey(&context->kemContext,
                  keyShare + keyShareOffset);
            }
         }
         else
         {
            //The length of the key share is not valid
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }
      else
      {
         //Unsupported hybrid key exchange method
         error = ERROR_ILLEGAL_PARAMETER;
      }
   }
   else
#endif
   //Unknown key exchange method?
   {
      //Report an error
      error = ERROR_ILLEGAL_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Decapsulation algorithm
 * @param[in] context Pointer to the TLS context
 * @param[in] keyShare Pointer to the server's key share
 * @param[in] length Length of the client's key share, in bytes
 * @return Error code
 **/

error_t tls13Decapsulate(TlsContext *context, const uint8_t *keyShare,
   size_t length)
{
   error_t error;

#if (TLS13_MLKEM_KE_SUPPORT == ENABLED || TLS13_PSK_MLKEM_KE_SUPPORT == ENABLED)
   //ML-KEM key exchange method?
   if(tls13IsMlkemGroupSupported(context, context->namedGroup))
   {
      const KemAlgo *kemAlgo;

      //Retrieve the ML-KEM algorithm to be used
      kemAlgo = tls13GetMlkemAlgo(context, context->namedGroup);

      //The length of the ciphertext is fixed
      if(length == kemAlgo->ciphertextSize)
      {
         //The decapsulation algorithm takes as input a secret key sk and
         //ciphertext ct and outputs a shared secret ss
         error = kemDecapsulate(&context->kemContext, keyShare,
            context->premasterSecret);

         //Check status code
         if(!error)
         {
            //The shared secret output from the ML-KEM Decaps is inserted into
            //the TLS 1.3 key schedule in place of the (EC)DHE shared secret
            context->premasterSecretLen = kemAlgo->sharedSecretSize;
         }
      }
      else
      {
         //The length of the key share is not valid
         error = ERROR_ILLEGAL_PARAMETER;
      }
   }
   else
#endif
#if (TLS13_HYBRID_KE_SUPPORT == ENABLED || TLS13_PSK_HYBRID_KE_SUPPORT == ENABLED)
   //Hybrid key exchange method?
   if(tls13IsHybridGroupSupported(context, context->namedGroup))
   {
      size_t keyShareOffset;
      size_t sharedSecretOffset;
      const KemAlgo *kemAlgo;

      //Point to the KEM algorithm
      kemAlgo = context->kemContext.kemAlgo;

      //The server's share is a fixed-size concatenation of the ECDH ephemeral
      //key share and the ct outputs of the KEM Encaps algorithm
      if(length > kemAlgo->ciphertextSize)
      {
         //NIST's special publication 800-56C approves the usage of HKDF with two
         //distinct shared secrets, with the condition that the first one is
         //computed by a FIPS-approved key-establishment scheme
         if(context->namedGroup == TLS_GROUP_X25519_MLKEM768)
         {
            keyShareOffset = kemAlgo->ciphertextSize;
            sharedSecretOffset = kemAlgo->sharedSecretSize;
         }
         else
         {
            keyShareOffset = 0;
            sharedSecretOffset = 0;
         }

         //Decode the server's ECDH ephemeral share
         error = ecdhImportPeerPublicKey(&context->ecdhContext,
            keyShare + keyShareOffset, length - kemAlgo->ciphertextSize,
            EC_PUBLIC_KEY_FORMAT_X963);

         //Check status code
         if(!error)
         {
            //DH key exchange can be modeled as a KEM, with decapsulation
            //corresponding to computing the shared secret g^(xy)
            error = ecdhComputeSharedSecret(&context->ecdhContext,
               context->premasterSecret + sharedSecretOffset,
               TLS_PREMASTER_SECRET_SIZE - sharedSecretOffset,
               &context->premasterSecretLen);
         }

         //Check status code
         if(!error)
         {
            //X25519MLKEM768 group?
            if(context->namedGroup == TLS_GROUP_X25519_MLKEM768)
            {
               keyShareOffset = 0;
               sharedSecretOffset = 0;
            }
            else
            {
               keyShareOffset = length - kemAlgo->ciphertextSize;
               sharedSecretOffset = context->premasterSecretLen;
            }

            //The decapsulation algorithm takes as input a secret key sk and
            //ciphertext ct and outputs a shared secret ss
            error = kemDecapsulate(&context->kemContext, keyShare + keyShareOffset,
               context->premasterSecret + sharedSecretOffset);
         }

         //Check status code
         if(!error)
         {
            //The two shared secrets are concatenated together and used as the
            //shared secret in the existing TLS 1.3 key schedule
            context->premasterSecretLen += kemAlgo->sharedSecretSize;
         }
      }
      else
      {
         //The length of the key share is not valid
         error = ERROR_ILLEGAL_PARAMETER;
      }
   }
   else
#endif
   //Unknown key exchange method?
   {
      //Report an error
      error = ERROR_ILLEGAL_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Compute message authentication code
 * @param[in] context Pointer to the TLS context
 * @param[in] encryptionEngine Pointer to the encryption/decryption engine
 * @param[in] record Pointer to the TLS record
 * @param[in] data Pointer to the record data
 * @param[in] dataLen Length of the data
 * @param[out] mac The computed MAC value
 * @return Error code
 **/

error_t tls13ComputeMac(TlsContext *context, TlsEncryptionEngine *encryptionEngine,
   void *record, const uint8_t *data, size_t dataLen, uint8_t *mac)
{
   size_t aadLen;
   size_t nonceLen;
   uint8_t aad[13];
   uint8_t nonce[12];
   HmacContext *hmacContext;

   //Point to the HMAC context
   hmacContext = encryptionEngine->hmacContext;

   //Initialize HMAC calculation
   hmacInit(hmacContext, encryptionEngine->hashAlgo,
      encryptionEngine->encKey, encryptionEngine->encKeyLen);

   //Additional data to be authenticated
   tlsFormatAad(context, encryptionEngine, record, aad, &aadLen);

   //Generate the nonce
   tlsFormatNonce(context, encryptionEngine, record, data, nonce,
      &nonceLen);

   //Compute HMAC(write_key, nonce || additional_data || plaintext)
   hmacUpdate(hmacContext, nonce, nonceLen);
   hmacUpdate(hmacContext, aad, aadLen);
   hmacUpdate(hmacContext, data, dataLen);

   //Finalize HMAC computation
   hmacFinal(hmacContext, mac);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Hash ClientHello1 in the transcript when HelloRetryRequest is used
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tls13DigestClientHello1(TlsContext *context)
{
   TlsHandshake *message;
   const HashAlgo *hash;

   //Invalid hash context?
   if(context->transcriptHashContext == NULL)
      return ERROR_FAILURE;

   //The hash function used by HKDF is the cipher suite hash algorithm
   hash = context->cipherSuite.prfHashAlgo;
   //Make sure the hash algorithm is valid
   if(hash == NULL)
      return ERROR_FAILURE;

   //Point to the buffer where to format the handshake message
   message = (TlsHandshake *) context->txBuffer;

   //Handshake message type
   message->msgType = TLS_TYPE_MESSAGE_HASH;
   //Number of bytes in the message
   STORE24BE(hash->digestSize, message->length);

   //Compute Hash(ClientHello1)
   hash->final(context->transcriptHashContext, message->data);
   //Re-initialize hash algorithm context
   hash->init(context->transcriptHashContext);

   //When the server responds to a ClientHello with a HelloRetryRequest, the
   //value of ClientHello1 is replaced with a special synthetic handshake
   //message of handshake type MessageHash containing Hash(ClientHello1)
   hash->update(context->transcriptHashContext, message,
      hash->digestSize + sizeof(TlsHandshake));

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Check whether an externally established PSK is valid
 * @param[in] context Pointer to the TLS context
 * @return TRUE is the PSK is valid, else FALSE
 **/

bool_t tls13IsPskValid(TlsContext *context)
{
   bool_t valid = FALSE;

   //Make sure the hash algorithm associated with the PSK is valid
   if(tlsGetHashAlgo(context->pskHashAlgo) != NULL)
   {
      //Valid PSK?
      if(context->psk != NULL && context->pskLen > 0)
      {
         //Check whether TLS operates as a client or a server
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            //Valid PSK identity?
            if(context->pskIdentity != NULL)
            {
               valid = TRUE;
            }
         }
         else
         {
            valid = TRUE;
         }
      }
   }

   //Return TRUE is the PSK is valid, else FALSE
   return valid;
}


/**
 * @brief Check whether a given named group is supported
 * @param[in] context Pointer to the TLS context
 * @param[in] namedGroup Named group
 * @return TRUE is the named group is supported, else FALSE
 **/

bool_t tls13IsGroupSupported(TlsContext *context, uint16_t namedGroup)
{
   bool_t acceptable;

   //Initialize flag
   acceptable = FALSE;

   //Check whether the specified named group is supported
   if(tls13IsFfdheGroupSupported(context, namedGroup))
   {
      acceptable = TRUE;
   }
   else if(tls13IsEcdheGroupSupported(context, namedGroup))
   {
      acceptable = TRUE;
   }
   else if(tls13IsMlkemGroupSupported(context, namedGroup))
   {
      acceptable = TRUE;
   }
   else if(tls13IsHybridGroupSupported(context, namedGroup))
   {
      acceptable = TRUE;
   }
   else
   {
      acceptable = FALSE;
   }

   //Return TRUE is the named group is supported
   return acceptable;
}


/**
 * @brief Check whether a given FFDHE group is supported
 * @param[in] context Pointer to the TLS context
 * @param[in] namedGroup Named group
 * @return TRUE is the FFDHE group is supported, else FALSE
 **/

bool_t tls13IsFfdheGroupSupported(TlsContext *context, uint16_t namedGroup)
{
   bool_t acceptable;

   //Initialize flag
   acceptable = FALSE;

#if ((TLS13_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED) && \
   TLS_FFDHE_SUPPORT == ENABLED)
   //Finite field group?
   if(namedGroup == TLS_GROUP_FFDHE2048 ||
      namedGroup == TLS_GROUP_FFDHE3072 ||
      namedGroup == TLS_GROUP_FFDHE4096 ||
      namedGroup == TLS_GROUP_FFDHE6144 ||
      namedGroup == TLS_GROUP_FFDHE8192)
   {
      //Any TLS 1.3 cipher suite proposed by the client?
      if((context->cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         //Check whether the FFDHE group is supported
         if(tlsGetFfdheGroup(context, namedGroup) != NULL)
         {
            acceptable = TRUE;
         }
      }
   }
#endif

   //Return TRUE is the named group is supported
   return acceptable;
}


/**
 * @brief Check whether a given ECDHE group is supported
 * @param[in] context Pointer to the TLS context
 * @param[in] namedGroup Named group
 * @return TRUE is the ECDHE group is supported, else FALSE
 **/

bool_t tls13IsEcdheGroupSupported(TlsContext *context, uint16_t namedGroup)
{
   bool_t acceptable;

   //Initialize flag
   acceptable = FALSE;

#if (TLS13_ECDHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED)
   //Elliptic curve group?
   if(namedGroup == TLS_GROUP_SECP256R1 ||
      namedGroup == TLS_GROUP_SECP384R1 ||
      namedGroup == TLS_GROUP_SECP521R1 ||
      namedGroup == TLS_GROUP_X25519 ||
      namedGroup == TLS_GROUP_X448 ||
      namedGroup == TLS_GROUP_BRAINPOOLP256R1_TLS13 ||
      namedGroup == TLS_GROUP_BRAINPOOLP384R1_TLS13 ||
      namedGroup == TLS_GROUP_BRAINPOOLP512R1_TLS13)
   {
      //Any TLS 1.3 cipher suite proposed by the client?
      if((context->cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         //Check whether the ECDHE group is supported
         if(tlsGetCurve(context, namedGroup) != NULL)
         {
            acceptable = TRUE;
         }
      }
   }
   else if(namedGroup == TLS_GROUP_CURVE_SM2)
   {
      //Any ShangMi cipher suite proposed by the client?
      if((context->cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_SM) != 0)
      {
         //Check whether the SM2 group is supported
         if(tlsGetCurve(context, namedGroup) != NULL)
         {
            acceptable = TRUE;
         }
      }
   }
   else
   {
      //Unknown group
   }
#endif

   //Return TRUE is the named group is supported
   return acceptable;
}


/**
 * @brief Check whether a given ML-KEM exchange method is supported
 * @param[in] context Pointer to the TLS context
 * @param[in] namedGroup Named group
 * @return TRUE is the ML-KEM key exchange is supported, else FALSE
 **/

bool_t tls13IsMlkemGroupSupported(TlsContext *context, uint16_t namedGroup)
{
   bool_t acceptable;

   //Initialize flag
   acceptable = FALSE;

#if (TLS13_MLKEM_KE_SUPPORT == ENABLED || TLS13_PSK_MLKEM_KE_SUPPORT == ENABLED)
   //ML-KEM key exchange method?
   if(namedGroup == TLS_GROUP_MLKEM512 ||
      namedGroup == TLS_GROUP_MLKEM768 ||
      namedGroup == TLS_GROUP_MLKEM1024)
   {
      //Any TLS 1.3 cipher suite proposed by the client?
      if((context->cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         //Check whether the ML-KEM key exchange method is supported
         if(tls13GetMlkemAlgo(context, namedGroup) != NULL)
         {
            acceptable = TRUE;
         }
      }
   }
   else
   {
      //Unknown group
   }
#endif

   //Return TRUE is the named group is supported
   return acceptable;
}


/**
 * @brief Check whether a given hybrid key exchange method is supported
 * @param[in] context Pointer to the TLS context
 * @param[in] namedGroup Named group
 * @return TRUE is the hybrid key exchange is supported, else FALSE
 **/

bool_t tls13IsHybridGroupSupported(TlsContext *context, uint16_t namedGroup)
{
   bool_t acceptable;

   //Initialize flag
   acceptable = FALSE;

#if (TLS13_HYBRID_KE_SUPPORT == ENABLED || TLS13_PSK_HYBRID_KE_SUPPORT == ENABLED)
   //Hybrid key exchange method?
   if(namedGroup == TLS_GROUP_SECP256R1_MLKEM768 ||
      namedGroup == TLS_GROUP_SECP384R1_MLKEM1024 ||
      namedGroup == TLS_GROUP_CURVE_SM2_MLKEM768 ||
      namedGroup == TLS_GROUP_X25519_MLKEM768)
   {
      //Any TLS 1.3 cipher suite proposed by the client?
      if((context->cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         //Check whether the hybrid key exchange method is supported
         if(tls13GetTraditionalAlgo(context, namedGroup) != NULL &&
            tls13GetNextGenAlgo(context, namedGroup) != NULL)
         {
            acceptable = TRUE;
         }
      }
   }
   else
   {
      //Unknown group
   }
#endif

   //Return TRUE is the named group is supported
   return acceptable;
}


/**
 * @brief Get the ML-KEM algorithm that matches the specified named group
 * @param[in] context Pointer to the TLS context
 * @param[in] namedGroup Hybrid key exchange method
 * @return ML-KEM algorithm
 **/

const KemAlgo *tls13GetMlkemAlgo(TlsContext *context, uint16_t namedGroup)
{
   const KemAlgo *kemAlgo;

   //Default KEM algorithm
   kemAlgo = NULL;

#if (TLS13_MLKEM_KE_SUPPORT == ENABLED || TLS13_PSK_MLKEM_KE_SUPPORT == ENABLED)
   //Check named group
   switch(namedGroup)
   {
#if (TLS_MLKEM512_SUPPORT == ENABLED)
   //ML-KEM-512 key encapsulation mechanism?
   case TLS_GROUP_MLKEM512:
      kemAlgo = MLKEM512_KEM_ALGO;
      break;
#endif
#if (TLS_MLKEM768_SUPPORT == ENABLED)
   //ML-KEM-768 key encapsulation mechanism?
   case TLS_GROUP_MLKEM768:
      kemAlgo = MLKEM768_KEM_ALGO;
      break;
#endif
#if (TLS_MLKEM1024_SUPPORT == ENABLED)
   //ML-KEM-1024 key encapsulation mechanism?
   case TLS_GROUP_MLKEM1024:
      kemAlgo = MLKEM1024_KEM_ALGO;
      break;
#endif
   //Unknown group?
   default:
      kemAlgo = NULL;
      break;
   }

   //Restrict the use of certain algorithms
   if(context->numSupportedGroups > 0)
   {
      uint_t i;

      //Loop through the list of allowed named groups
      for(i = 0; i < context->numSupportedGroups; i++)
      {
         //Compare named groups
         if(context->supportedGroups[i] == namedGroup)
            break;
      }

      //Check whether the use of the algorithm is restricted
      if(i >= context->numSupportedGroups)
      {
         kemAlgo = NULL;
      }
   }
#endif

   //Return KEM algorithm, if any
   return kemAlgo;
}


/**
 * @brief Get the traditional algorithm used by the hybrid key exchange method
 * @param[in] context Pointer to the TLS context
 * @param[in] namedGroup Hybrid key exchange method
 * @return Traditional algorithm
 **/

const EcCurve *tls13GetTraditionalAlgo(TlsContext *context,
   uint16_t namedGroup)
{
   const EcCurve *curve;

   //Default elliptic curve parameters
   curve = NULL;

#if (TLS13_HYBRID_KE_SUPPORT == ENABLED || TLS13_PSK_HYBRID_KE_SUPPORT == ENABLED)
   //Check named group
   switch(namedGroup)
   {
#if (TLS_SECP256R1_SUPPORT == ENABLED)
   //secp256r1 elliptic curve?
   case TLS_GROUP_SECP256R1_MLKEM768:
      curve = ecGetCurve(SECP256R1_OID, sizeof(SECP256R1_OID));
      break;
#endif
#if (TLS_SECP384R1_SUPPORT == ENABLED)
   //secp384r1 elliptic curve?
   case TLS_GROUP_SECP384R1_MLKEM1024:
      curve = ecGetCurve(SECP384R1_OID, sizeof(SECP384R1_OID));
      break;
#endif
#if (TLS_SM2_SUPPORT == ENABLED)
   //SM2 elliptic curve?
   case TLS_GROUP_CURVE_SM2_MLKEM768:
      curve = ecGetCurve(SM2_OID, sizeof(SM2_OID));
      break;
#endif
#if (TLS_X25519_SUPPORT == ENABLED)
   //Curve25519 elliptic curve?
   case TLS_GROUP_X25519_MLKEM768:
      curve = ecGetCurve(X25519_OID, sizeof(X25519_OID));
      break;
#endif
   //Unknown group?
   default:
      curve = NULL;
      break;
   }

   //Restrict the use of certain algorithms
   if(context->numSupportedGroups > 0)
   {
      uint_t i;

      //Loop through the list of allowed named groups
      for(i = 0; i < context->numSupportedGroups; i++)
      {
         //Compare named groups
         if(context->supportedGroups[i] == namedGroup)
            break;
      }

      //Check whether the use of the algorithm is restricted
      if(i >= context->numSupportedGroups)
      {
         curve = NULL;
      }
   }
#endif

   //Return the elliptic curve parameters, if any
   return curve;
}


/**
 * @brief Get the next-gen algorithm used by the hybrid key exchange method
 * @param[in] context Pointer to the TLS context
 * @param[in] namedGroup Hybrid key exchange method
 * @return Next-gen algorithm
 **/

const KemAlgo *tls13GetNextGenAlgo(TlsContext *context, uint16_t namedGroup)
{
   const KemAlgo *kemAlgo;

   //Default KEM algorithm
   kemAlgo = NULL;

#if (TLS13_HYBRID_KE_SUPPORT == ENABLED || TLS13_PSK_HYBRID_KE_SUPPORT == ENABLED)
   //Check named group
   switch(namedGroup)
   {
#if (TLS_MLKEM768_SUPPORT == ENABLED)
   //ML-KEM-768 key encapsulation mechanism?
   case TLS_GROUP_SECP256R1_MLKEM768:
   case TLS_GROUP_CURVE_SM2_MLKEM768:
   case TLS_GROUP_X25519_MLKEM768:
      kemAlgo = MLKEM768_KEM_ALGO;
      break;
#endif
#if (TLS_MLKEM1024_SUPPORT == ENABLED)
   //ML-KEM-1024 key encapsulation mechanism?
   case TLS_GROUP_SECP384R1_MLKEM1024:
      kemAlgo = MLKEM1024_KEM_ALGO;
      break;
#endif
   //Unknown group?
   default:
      kemAlgo = NULL;
      break;
   }

   //Restrict the use of certain algorithms
   if(context->numSupportedGroups > 0)
   {
      uint_t i;

      //Loop through the list of allowed named groups
      for(i = 0; i < context->numSupportedGroups; i++)
      {
         //Compare named groups
         if(context->supportedGroups[i] == namedGroup)
            break;
      }

      //Check whether the use of the algorithm is restricted
      if(i >= context->numSupportedGroups)
      {
         kemAlgo = NULL;
      }
   }
#endif

   //Return KEM algorithm, if any
   return kemAlgo;
}


/**
 * @brief Check whether the specified key share group is a duplicate
 * @param[in] namedGroup Named group
 * @param[in] p List of key share entries
 * @param[in] length Length of the list, in bytes
 * @return Error code
 **/

error_t tls13CheckDuplicateKeyShare(uint16_t namedGroup, const uint8_t *p,
   size_t length)
{
   size_t n;
   const Tls13KeyShareEntry *keyShareEntry;

   //Parse the list of key share entries offered by the peer
   while(length > 0)
   {
      //Malformed extension?
      if(length < sizeof(Tls13KeyShareEntry))
         return ERROR_DECODING_FAILED;

      //Point to the current key share entry
      keyShareEntry = (Tls13KeyShareEntry *) p;
      //Retrieve the length of the key_exchange field
      n = ntohs(keyShareEntry->length);

      //Malformed extension?
      if(length < (sizeof(Tls13KeyShareEntry) + n))
         return ERROR_DECODING_FAILED;

      //Clients must not offer multiple KeyShareEntry values for the same
      //group. Servers may check for violations of this rule and abort the
      //handshake with an illegal_parameter alert
      if(ntohs(keyShareEntry->group) == namedGroup)
         return ERROR_ILLEGAL_PARAMETER;

      //Jump to the next key share entry
      p += sizeof(Tls13KeyShareEntry) + n;
      //Number of bytes left to process
      length -= sizeof(Tls13KeyShareEntry) + n;
   }

   //Successful verification
   return NO_ERROR;
}


/**
 * @brief Format certificate extensions
 * @param[in] p Output stream where to write the list of extensions
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tls13FormatCertExtensions(uint8_t *p, size_t *written)
{
   TlsExtensionList *extensionList;

   //Point to the list of extensions
   extensionList = (TlsExtensionList *) p;

   //Extensions in the Certificate message from the server must correspond to
   //ones from the ClientHello message. Extensions in the Certificate message
   //from the client must correspond to extensions in the CertificateRequest
   //message from the server
   extensionList->length = HTONS(0);

   //Total number of bytes that have been written
   *written = sizeof(TlsExtensionList);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse certificate extensions
 * @param[in] p Input stream where to read the list of extensions
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tls13ParseCertExtensions(const uint8_t *p, size_t length,
   size_t *consumed)
{
   error_t error;
   size_t n;
   TlsHelloExtensions extensions;
   const TlsExtensionList *extensionList;

   //Point to the list of extensions
   extensionList = (TlsExtensionList *) p;

   //Malformed CertificateEntry?
   if(length < sizeof(TlsExtensionList))
      return ERROR_DECODING_FAILED;

   //Retrieve the length of the list
   n = sizeof(TlsExtensionList) + ntohs(extensionList->length);

   //Malformed CertificateEntry?
   if(length < n)
      return ERROR_DECODING_FAILED;

   //Parse the list of extensions for the current CertificateEntry
   error = tlsParseHelloExtensions(TLS_TYPE_CERTIFICATE, p, n,
      &extensions);
   //Any error to report?
   if(error)
      return error;

   //Check the list of extensions
   error = tlsCheckHelloExtensions(TLS_TYPE_CERTIFICATE, TLS_VERSION_1_3,
      &extensions);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been consumed
   *consumed = n;

   //Successful processing
   return NO_ERROR;
}

#endif
