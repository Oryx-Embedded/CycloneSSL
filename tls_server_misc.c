/**
 * @file tls_server_misc.c
 * @brief Helper functions for TLS server
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
#include "tls_cipher_suites.h"
#include "tls_handshake_misc.h"
#include "tls_server.h"
#include "tls_server_misc.h"
#include "tls_common.h"
#include "tls_record.h"
#include "tls_signature.h"
#include "tls_cache.h"
#include "tls_misc.h"
#include "certificate/pem_import.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED && TLS_SERVER_SUPPORT == ENABLED)


/**
 * @brief Format SNI extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the ServerName extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatServerSniExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_SNI_SUPPORT == ENABLED)
   //A server that receives a ClientHello containing the SNI extension may use
   //the information contained in the extension to guide its selection of an
   //appropriate certificate to return to the client. In this event, the server
   //shall include an extension of type SNI in the ServerHello
   if(context->serverName != NULL)
   {
      TlsExtension *extension;

      //Add SNI (Server Name Indication) extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_SERVER_NAME);

      //The extension data field of this extension shall be empty (refer to
      //RFC 6066, section 3)
      extension->length = HTONS(0);

      //Compute the length, in bytes, of the ServerName extension
      n = sizeof(TlsExtension);
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format MaxFragmentLength extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the MaxFragmentLength extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatServerMaxFragLenExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   //An extension type must not appear in the ServerHello unless the same
   //extension type appeared in the corresponding ClientHello
   if(context->maxFragLenExtReceived)
   {
      //Servers that receive an ClientHello containing a MaxFragmentLength
      //extension may accept the requested maximum fragment length by including
      //an extension of type MaxFragmentLength in the ServerHello
      if(context->maxFragLen == 512 || context->maxFragLen == 1024 ||
         context->maxFragLen == 2048 || context->maxFragLen == 4096)
      {
         TlsExtension *extension;

         //Add the MaxFragmentLength extension
         extension = (TlsExtension *) p;
         //Type of the extension
         extension->type = HTONS(TLS_EXT_MAX_FRAGMENT_LENGTH);

         //The data field of this extension shall contain a MaxFragmentLength
         //whose value is the same as the requested maximum fragment length
         switch(context->maxFragLen)
         {
         case 512:
            extension->value[0] = TLS_MAX_FRAGMENT_LENGHT_512;
            break;
         case 1024:
            extension->value[0] = TLS_MAX_FRAGMENT_LENGHT_1024;
            break;
         case 2048:
            extension->value[0] = TLS_MAX_FRAGMENT_LENGHT_2048;
            break;
         default:
            extension->value[0] = TLS_MAX_FRAGMENT_LENGHT_4096;
            break;
         }

         //The extension data field contains a single byte
         n = sizeof(uint8_t);
         //Set the length of the extension
         extension->length = HTONS(n);

         //Compute the length, in bytes, of the MaxFragmentLength extension
         n += sizeof(TlsExtension);
      }
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format EcPointFormats extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the EcPointFormats extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatServerEcPointFormatsExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_ECDH_ANON_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //An extension type must not appear in the ServerHello unless the same
   //extension type appeared in the corresponding ClientHello
   if(context->ecPointFormatsExtReceived)
   {
      //A server that selects an ECC cipher suite in response to a ClientHello
      //message including an EcPointFormats extension appends this extension
      //to its ServerHello message
      if(tlsIsEccCipherSuite(context->cipherSuite.identifier))
      {
         TlsExtension *extension;
         TlsEcPointFormatList *ecPointFormatList;

         //Add the EcPointFormats extension
         extension = (TlsExtension *) p;
         //Type of the extension
         extension->type = HTONS(TLS_EXT_EC_POINT_FORMATS);

         //Point to the list of supported EC point formats
         ecPointFormatList = (TlsEcPointFormatList *) extension->value;
         //Items in the list are ordered according to server's preferences
         n = 0;

         //The server can parse only the uncompressed point format...
         ecPointFormatList->value[n++] = TLS_EC_POINT_FORMAT_UNCOMPRESSED;
         //Fix the length of the list
         ecPointFormatList->length = (uint8_t) n;

         //Consider the 2-byte length field that precedes the list
         n += sizeof(TlsEcPointFormatList);
         //Fix the length of the extension
         extension->length = htons(n);

         //Compute the length, in bytes, of the EcPointFormats extension
         n += sizeof(TlsExtension);
      }
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format ALPN extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the ALPN extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatServerAlpnExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_ALPN_SUPPORT == ENABLED)
   //The ALPN extension may be returned to the client within the extended
   //ServerHello message
   if(context->selectedProtocol != NULL)
   {
      //Empty strings must not be included
      if(context->selectedProtocol[0] != '\0')
      {
         TlsExtension *extension;
         TlsProtocolName *protocolName;
         TlsProtocolNameList *protocolNameList;

         //Add ALPN (Application-Layer Protocol Negotiation) extension
         extension = (TlsExtension *) p;
         //Type of the extension
         extension->type = HTONS(TLS_EXT_ALPN);

         //Point to the list of protocol names
         protocolNameList = (TlsProtocolNameList *) extension->value;
         //The list must contain exactly one protocol name
         protocolName = (TlsProtocolName *) protocolNameList->value;

         //Retrieve the length of the protocol name
         n = strlen(context->selectedProtocol);

         //Fill in the length field
         protocolName->length = n;
         //Copy protocol name
         memcpy(protocolName->value, context->selectedProtocol, n);

         //Adjust the length of the list
         n += sizeof(TlsProtocolName);
         //Fix the length of the list
         protocolNameList->length = htons(n);

         //Consider the 2-byte length field that precedes the list
         n += sizeof(TlsProtocolNameList);
         //Fix the length of the extension
         extension->length = htons(n);

         //Compute the length, in bytes, of the ALPN extension
         n += sizeof(TlsExtension);
      }
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format ExtendedMasterSecret extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the ExtendedMasterSecret extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatServerEmsExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //If the server receives a ClientHello without the ExtendedMasterSecret
   //extension, then it must not include the extension in the ServerHello
   if(context->extendedMasterSecretExtReceived)
   {
      TlsExtension *extension;

      //Add the ExtendedMasterSecret extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_EXTENDED_MASTER_SECRET);

      //The extension data field of this extension is empty
      extension->length = HTONS(0);

      //Compute the length, in bytes, of the ExtendedMasterSecret extension
      n = sizeof(TlsExtension);
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format RenegotiationInfo extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the RenegotiationInfo extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatServerRenegoInfoExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //Check whether secure renegotiation is enabled
   if(context->secureRenegoEnabled)
   {
      //During secure renegotiation, the server must include a renegotiation_info
      //extension containing the saved client_verify_data and server_verify_data
      if(context->secureRenegoFlag)
      {
         TlsExtension *extension;
         TlsRenegoInfo *renegoInfo;

         //Determine the length of the renegotiated_connection field
         n = context->clientVerifyDataLen + context->serverVerifyDataLen;

         //Add the RenegotiationInfo extension
         extension = (TlsExtension *) p;
         //Type of the extension
         extension->type = HTONS(TLS_EXT_RENEGOTIATION_INFO);

         //Point to the renegotiated_connection field
         renegoInfo = (TlsRenegoInfo *) extension->value;
         //Set the length of the verify data
         renegoInfo->length = n;

         //Copy the saved client_verify_data
         memcpy(renegoInfo->value, context->clientVerifyData,
            context->clientVerifyDataLen);

         //Copy the saved client_verify_data
         memcpy(renegoInfo->value + context->clientVerifyDataLen,
            context->serverVerifyData, context->serverVerifyDataLen);

         //Consider the length field that precedes the renegotiated_connection
         //field
         n += sizeof(TlsRenegoInfo);
         //Fix the length of the extension
         extension->length = htons(n);

         //Compute the length, in bytes, of the RenegotiationInfo extension
         n += sizeof(TlsExtension);
      }
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format PSK identity hint
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the PSK identity hint
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatPskIdentityHint(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n;
   TlsPskIdentityHint *pskIdentityHint;

   //Point to the PSK identity hint
   pskIdentityHint = (TlsPskIdentityHint *) p;

   //Initialize length field
   n = 0;

#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //Any PSK identity hint defined?
   if(context->pskIdentityHint != NULL)
   {
      //Determine the length of the PSK identity hint
      n = strlen(context->pskIdentityHint);
      //Copy PSK identity hint
      memcpy(pskIdentityHint->value, context->pskIdentityHint, n);
   }
#endif

   //The PSK identity hint is preceded by a 2-byte length field
   pskIdentityHint->length = htons(n);

   //Total number of bytes that have been written
   *written = sizeof(TlsPskIdentityHint) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format server's key exchange parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the PSK identity hint
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatServerKeyParams(TlsContext *context,
   uint8_t *p, size_t *written)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Total number of bytes that have been written
   *written = 0;

#if (TLS_DH_ANON_SUPPORT == ENABLED || TLS_DHE_RSA_SUPPORT == ENABLED || \
   TLS_DHE_DSS_SUPPORT == ENABLED || TLS_DHE_PSK_SUPPORT == ENABLED)
   //Diffie-Hellman key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK)
   {
      size_t n;

      //Generate an ephemeral key pair
      error = dhGenerateKeyPair(&context->dhContext,
         context->prngAlgo, context->prngContext);

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
         TRACE_DEBUG_MPI("    ", &context->dhContext.ya);

         //Encode the prime modulus to an opaque vector
         error = tlsWriteMpi(&context->dhContext.params.p, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Total number of bytes that have been written
         *written += n;

         //Encode the generator to an opaque vector
         error = tlsWriteMpi(&context->dhContext.params.g, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Total number of bytes that have been written
         *written += n;

         //Encode the server's public value to an opaque vector
         error = tlsWriteMpi(&context->dhContext.ya, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Adjust the length of the key exchange parameters
         *written += n;
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
      const EcCurveInfo *curveInfo;

      //Retrieve the elliptic curve to be used
      curveInfo = tlsGetCurveInfo(context->namedCurve);

      //Make sure the elliptic curve is supported
      if(curveInfo != NULL)
      {
         //Load EC domain parameters
         error = ecLoadDomainParameters(&context->ecdhContext.params,
            curveInfo);

         //Check status code
         if(!error)
         {
            //Generate an ephemeral key pair
            error = ecdhGenerateKeyPair(&context->ecdhContext,
               context->prngAlgo, context->prngContext);
         }

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_DEBUG("  Server public key X:\r\n");
            TRACE_DEBUG_MPI("    ", &context->ecdhContext.qa.x);
            TRACE_DEBUG("  Server public key Y:\r\n");
            TRACE_DEBUG_MPI("    ", &context->ecdhContext.qa.y);

            //Set the type of the elliptic curve domain parameters
            *p = TLS_EC_CURVE_TYPE_NAMED_CURVE;

            //Advance data pointer
            p += sizeof(uint8_t);
            //Total number of bytes that have been written
            *written += sizeof(uint8_t);

            //Write elliptic curve identifier
            STORE16BE(context->namedCurve, p);

            //Advance data pointer
            p += sizeof(uint16_t);
            //Total number of bytes that have been written
            *written += sizeof(uint16_t);

            //Write server's public key
            error = tlsWriteEcPoint(&context->ecdhContext.params,
               &context->ecdhContext.qa, p, &n);
         }

         //Check status code
         if(!error)
         {
            //Advance data pointer
            p +=n;
            //Total number of bytes that have been written
            *written += n;
         }
      }
      else
      {
         //The specified elliptic curve is not supported
         error = ERROR_FAILURE;
      }
   }
   else
#endif
   //Any other exchange method?
   {
      //It is not legal to send the ServerKeyExchange message when a key
      //exchange method other than DHE_DSS, DHE_RSA, DH_anon, ECDHE_RSA,
      //ECDHE_ECDSA or ECDH_anon is selected
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Generate signature over the server's key exchange parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the PSK identity hint
 * @param[in] params Pointer to the server's key exchange parameters
 * @param[in] paramsLen Length of the server's key exchange parameters
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsGenerateServerKeySignature(TlsContext *context,
   uint8_t *p, const uint8_t *params, size_t paramsLen, size_t *written)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Total number of bytes that have been written
   *written = 0;

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //SSL 3.0, TLS 1.0 or TLS 1.1 currently selected?
   if(context->version <= TLS_VERSION_1_1)
   {
      TlsDigitalSignature *signature;

      //Point to the digitally-signed element
      signature = (TlsDigitalSignature *) p;

#if (TLS_DHE_RSA_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED)
      //Check whether DHE_RSA or ECDHE_RSA key exchange method is currently used
      if(context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA)
      {
         Md5Context *md5Context;
         Sha1Context *sha1Context;
         RsaPrivateKey privateKey;

         //Initialize RSA private key
         rsaInitPrivateKey(&privateKey);

         //Allocate a memory buffer to hold the MD5 context
         md5Context = tlsAllocMem(sizeof(Md5Context));

         //Successful memory allocation?
         if(md5Context != NULL)
         {
            //Compute MD5(ClientHello.random + ServerHello.random + ServerDhParams)
            md5Init(md5Context);
            md5Update(md5Context, context->random, 64);
            md5Update(md5Context, params, paramsLen);
            md5Final(md5Context, context->serverVerifyData);

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
               sha1Final(sha1Context, context->serverVerifyData + MD5_DIGEST_SIZE);

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
            //Decode the PEM structure that holds the RSA private key
            error = pemImportRsaPrivateKey(context->cert->privateKey,
               context->cert->privateKeyLen, &privateKey);
         }

         //Check status code
         if(!error)
         {
            //Sign the key exchange parameters using RSA
            error = tlsGenerateRsaSignature(&privateKey,
               context->serverVerifyData, signature->value, written);
         }

         //Release previously allocated resources
         rsaFreePrivateKey(&privateKey);
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
            sha1Final(sha1Context, context->serverVerifyData);

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
            //Sign the key exchange parameters using DSA
            error = tlsGenerateDsaSignature(context, context->serverVerifyData,
               SHA1_DIGEST_SIZE, signature->value, written);
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
            sha1Final(sha1Context, context->serverVerifyData);

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
            //Sign the key exchange parameters using ECDSA
            error = tlsGenerateEcdsaSignature(context, context->serverVerifyData,
               SHA1_DIGEST_SIZE, signature->value, written);
         }
      }
      else
#endif
      //Invalid signature algorithm?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }

      //Fix the length of the digitally-signed element
      signature->length = htons(*written);
      //Adjust the length of the signature
      *written += sizeof(TlsDigitalSignature);
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

      //Retrieve the hash algorithm used for signing
      hashAlgo = tlsGetHashAlgo(context->signHashAlgo);

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
            if(context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
               context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA)
            {
               RsaPrivateKey privateKey;

               //Initialize RSA private key
               rsaInitPrivateKey(&privateKey);

               //Set the relevant signature algorithm
               signature->algorithm.signature = TLS_SIGN_ALGO_RSA;
               signature->algorithm.hash = context->signHashAlgo;

               //Decode the PEM structure that holds the RSA private key
               error = pemImportRsaPrivateKey(context->cert->privateKey,
                  context->cert->privateKeyLen, &privateKey);

               //Check status code
               if(!error)
               {
                  //Use the signature algorithm defined in PKCS #1 v1.5
                  error = rsassaPkcs1v15Sign(&privateKey, hashAlgo,
                     hashContext->digest, signature->value, written);
               }

               //Release previously allocated resources
               rsaFreePrivateKey(&privateKey);
            }
            else
#endif
#if (TLS_DHE_DSS_SUPPORT == ENABLED)
            //Check whether DHE_DSS key exchange method is currently used
            if(context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS)
            {
               //Set the relevant signature algorithm
               signature->algorithm.signature = TLS_SIGN_ALGO_DSA;
               signature->algorithm.hash = context->signHashAlgo;

               //Sign the key exchange parameters using DSA
               error = tlsGenerateDsaSignature(context, hashContext->digest,
                  hashAlgo->digestSize, signature->value, written);
            }
            else
#endif
#if (TLS_ECDHE_ECDSA_SUPPORT == ENABLED)
            //Check whether ECDHE_ECDSA key exchange method is currently used
            if(context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
            {
               //Set the relevant signature algorithm
               signature->algorithm.signature = TLS_SIGN_ALGO_ECDSA;
               signature->algorithm.hash = context->signHashAlgo;

               //Sign the key exchange parameters using ECDSA
               error = tlsGenerateEcdsaSignature(context, hashContext->digest,
                  hashAlgo->digestSize, signature->value, written);
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

      //Fix the length of the digitally-signed element
      signature->length = htons(*written);
      //Adjust the length of the message
      *written += sizeof(TlsDigitalSignature2);
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
 * @brief Parse SNI extension
 * @param[in] context Pointer to the TLS context
 * @param[in] serverNameList Pointer to the SNI extension
 * @return Error code
 **/

error_t tlsParseClientSniExtension(TlsContext *context,
   const TlsServerNameList *serverNameList)
{
#if (TLS_SNI_SUPPORT == ENABLED)
   size_t i;
   size_t n;
   size_t length;
   const TlsServerName *serverName;

   //In order to provide the server name, clients may include ServerName
   //extension
   if(context->serverName != NULL)
   {
      //Release memory
      tlsFreeMem(context->serverName);
      context->serverName = NULL;
   }

   //Retrieve the length of the list
   length = ntohs(serverNameList->length);

   //Loop through the list of server names advertised by the client
   for(i = 0; i < length; i += sizeof(TlsServerName) + n)
   {
      //Point to the current server name
      serverName = (TlsServerName *) (serverNameList->value + i);

      //Malformed extension?
      if(length < (i + sizeof(TlsServerName)))
         return ERROR_DECODING_FAILED;
      if(length < (i + sizeof(TlsServerName) + ntohs(serverName->length)))
         return ERROR_DECODING_FAILED;

      //Retrieve the length of the server name
      n = ntohs(serverName->length);

      //Empty strings must not be included in the list
      if(n > 0 && n <= TLS_MAX_SERVER_NAME_LEN)
      {
         //Currently, the only server names supported are DNS hostnames
         if(serverName->type == TLS_NAME_TYPE_HOSTNAME)
         {
            //In practice, current client implementations only send one name
            if(context->serverName == NULL)
            {
               //Allocate a memory block to hold the server name
               context->serverName = tlsAllocMem(n + 1);
               //Failed to allocate memory?
               if(context->serverName == NULL)
                  return ERROR_OUT_OF_MEMORY;

               //Save server name
               memcpy(context->serverName, serverName->hostname, n);
               //Properly terminate the string with a NULL character
               context->serverName[n] = '\0';
            }
         }
      }
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse MaxFragmentLength extension
 * @param[in] context Pointer to the TLS context
 * @param[in] maxFragLen Pointer to the MaxFragmentLength extension
 * @return Error code
 **/

error_t tlsParseClientMaxFragLenExtension(TlsContext *context,
   const uint8_t *maxFragLen)
{
#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   size_t n;

   //Retrieve the value advertised by the client
   switch(*maxFragLen)
   {
   case TLS_MAX_FRAGMENT_LENGHT_512:
      n = 512;
      break;
   case TLS_MAX_FRAGMENT_LENGHT_1024:
      n = 1024;
      break;
   case TLS_MAX_FRAGMENT_LENGHT_2048:
      n = 2048;
      break;
   case TLS_MAX_FRAGMENT_LENGHT_4096:
      n = 4096;
      break;
   default:
      n = 0;
      break;
   }

   //If a server receives a maximum fragment length negotiation request for a
   //value other than the allowed values, it must abort the handshake with an
   //illegal_parameter alert
   if(n == 0)
      return ERROR_ILLEGAL_PARAMETER;

   //Once a maximum fragment length has been successfully negotiated, the
   //server must immediately begin fragmenting messages (including handshake
   //messages) to ensure that no fragment larger than the negotiated length
   //is sent
   context->maxFragLen = n;
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse EcPointFormats extension
 * @param[in] context Pointer to the TLS context
 * @param[in] ecPointFormatList Pointer to the EcPointFormats extension
 * @return Error code
 **/

error_t tlsParseClientEcPointFormatsExtension(TlsContext *context,
   const TlsEcPointFormatList *ecPointFormatList)
{
   error_t error;
   uint_t i;

   //Initialize status code
   error = ERROR_ILLEGAL_PARAMETER;

   //Loop through the list of supported EC point formats
   for(i = 0; i < ecPointFormatList->length; i++)
   {
      //If the EcPointFormats extension is sent, it must contain the value 0
      //as one of the items in the list of point formats (refer to RFC 4492,
      //section 5.1)
      if(ecPointFormatList->value[i] == TLS_EC_POINT_FORMAT_UNCOMPRESSED)
      {
         //Exit immediately
         error = NO_ERROR;
         break;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse ALPN extension
 * @param[in] context Pointer to the TLS context
 * @param[in] protocolNameList Pointer to the ALPN extension
 * @return Error code
 **/

error_t tlsParseClientAlpnExtension(TlsContext *context,
   const TlsProtocolNameList *protocolNameList)
{
#if (TLS_ALPN_SUPPORT == ENABLED)
   size_t i;
   size_t n;
   size_t length;
   const TlsProtocolName *protocolName;

   //When session resumption is used, the previous contents of this
   //extension are irrelevant
   if(context->selectedProtocol != NULL)
   {
      //Release memory
      tlsFreeMem(context->selectedProtocol);
      context->selectedProtocol = NULL;
   }

   //Retrieve the length of the list
   length = ntohs(protocolNameList->length);

   //The list must not be be empty
   if(length == 0)
      return ERROR_DECODING_FAILED;

   //Loop through the list of protocols advertised by the client
   for(i = 0; i < length; i += sizeof(TlsProtocolName) + n)
   {
      //Point to the current protocol
      protocolName = (TlsProtocolName *) (protocolNameList->value + i);

      //Malformed extension?
      if(length < (i + sizeof(TlsProtocolName)))
         return ERROR_DECODING_FAILED;
      if(length < (i + sizeof(TlsProtocolName) + protocolName->length))
         return ERROR_DECODING_FAILED;

      //Retrieve the length of the protocol name
      n = protocolName->length;

      //Empty strings must not be included in the list
      if(n == 0)
         return ERROR_DECODING_FAILED;

      //Check whether the protocol is supported by the server
      if(tlsIsAlpnProtocolSupported(context, protocolName->value, n))
      {
         //Select the current protocol
         if(context->selectedProtocol == NULL)
         {
            //Allocate a memory block to hold the protocol name
            context->selectedProtocol = tlsAllocMem(n + 1);
            //Failed to allocate memory?
            if(context->selectedProtocol == NULL)
               return ERROR_OUT_OF_MEMORY;

            //Save protocol name
            memcpy(context->selectedProtocol, protocolName->value, n);
            //Properly terminate the string with a NULL character
            context->selectedProtocol[n] = '\0';
         }
      }
   }

   //ALPN protocol selection failed?
   if(context->protocolList != NULL && context->selectedProtocol == NULL)
   {
      //Report an error if unknown ALPN protocols are disallowed
      if(!context->unknownProtocolsAllowed)
      {
         //In the event that the server supports no protocols that the
         //client advertises, then the server shall respond with a fatal
         //no_application_protocol alert
         return ERROR_NO_APPLICATION_PROTOCOL;
      }
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse PSK identity
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the PSK identity hint
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tlsParsePskIdentity(TlsContext *context,
   const uint8_t *p, size_t length, size_t *consumed)
{
   size_t n;
   TlsPskIdentity *pskIdentity;

   //Point to the PSK identity
   pskIdentity = (TlsPskIdentity *) p;

   //Malformed ClientKeyExchange message?
   if(length < sizeof(TlsPskIdentity))
      return ERROR_DECODING_FAILED;
   if(length < (sizeof(TlsPskIdentity) + ntohs(pskIdentity->length)))
      return ERROR_DECODING_FAILED;

   //Retrieve the length of the PSK identity
   n = ntohs(pskIdentity->length);

#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //Check whether the PSK identity has already been configured
   if(context->pskIdentity != NULL)
   {
      //Release memory
      tlsFreeMem(context->pskIdentity);
      context->pskIdentity = NULL;
   }

   //Valid PSK identity?
   if(n > 0)
   {
      //Allocate a memory block to hold the PSK identity
      context->pskIdentity = tlsAllocMem(n + 1);
      //Failed to allocate memory?
      if(context->pskIdentity == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Save the PSK identity
      memcpy(context->pskIdentity, pskIdentity->value, n);
      //Properly terminate the string
      context->pskIdentity[n] = '\0';
   }

   //Any registered callback?
   if(context->pskCallback != NULL)
   {
      error_t error;

      //Invoke user callback function
      if(context->pskIdentity != NULL)
         error = context->pskCallback(context, context->pskIdentity);
      else
         error = context->pskCallback(context, "");

      //Any error to report?
      if(error)
         return ERROR_UNKNOWN_IDENTITY;
   }
#endif

   //Total number of bytes that have been consumed
   *consumed = sizeof(TlsPskIdentity) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse client's key exchange parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the client's key exchange parameters
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tlsParseClientKeyParams(TlsContext *context,
   const uint8_t *p, size_t length, size_t *consumed)
{
   error_t error;

#if (TLS_RSA_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED)
   //RSA key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
   {
      size_t n;
      uint16_t version;
      RsaPrivateKey privateKey;

      //The RSA-encrypted premaster secret in a ClientKeyExchange is preceded by
      //two length bytes. SSL 3.0 implementations do not include these bytes
      if(context->version > SSL_VERSION_3_0)
      {
         //Malformed ClientKeyExchange message?
         if(length < 2)
            return ERROR_DECODING_FAILED;

         //Decode the length field
         n = LOAD16BE(p);

         //Check the length of the RSA-encrypted premaster secret
         if(n > (length - 2))
            return ERROR_DECODING_FAILED;

         //Save the length of the RSA-encrypted premaster secret
         length = n;
         //Advance the pointer over the length field
         p += 2;
         //Total number of bytes that have been consumed
         *consumed = length + 2;
      }
      else
      {
         //Total number of bytes that have been consumed
         *consumed = length;
      }

      //Initialize RSA private key
      rsaInitPrivateKey(&privateKey);

      //Decode the PEM structure that holds the RSA private key
      error = pemImportRsaPrivateKey(context->cert->privateKey,
         context->cert->privateKeyLen, &privateKey);

      //Check status code
      if(!error)
      {
         //Decrypt the premaster secret using the server private key
         error = rsaesPkcs1v15Decrypt(&privateKey, p, length,
            context->premasterSecret, TLS_PREMASTER_SECRET_SIZE,
            &context->premasterSecretLen);
      }

      //Release RSA private key
      rsaFreePrivateKey(&privateKey);

      //Retrieve the latest version supported by the client. This is used
      //to detect version roll-back attacks
      version = LOAD16BE(context->premasterSecret);

      //The best way to avoid vulnerability to the Bleichenbacher attack is to
      //treat incorrectly formatted messages in a manner indistinguishable from
      //correctly formatted RSA blocks
      if(error || context->premasterSecretLen != 48 || version != context->clientVersion)
      {
         //When it receives an incorrectly formatted RSA block, the server
         //should generate a random 48-byte value and proceed using it as
         //the premaster secret
         error = context->prngAlgo->read(context->prngContext,
            context->premasterSecret, 48);

         //Fix the length of the premaster secret
         context->premasterSecretLen = 48;
      }
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
      size_t n;

      //Convert the client's public value to a multiple precision integer
      error = tlsReadMpi(&context->dhContext.yb, p, length, &n);

      //Check status code
      if(!error)
      {
         //Total number of bytes that have been consumed
         *consumed = n;

         //Verify client's public value
         error = dhCheckPublicKey(&context->dhContext.params,
            &context->dhContext.yb);
      }

      //Check status code
      if(!error)
      {
         //Calculate the negotiated key Z
         error = dhComputeSharedSecret(&context->dhContext,
            context->premasterSecret, TLS_PREMASTER_SECRET_SIZE,
            &context->premasterSecretLen);
      }

      //Check status code
      if(!error)
      {
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

      //Decode client's public key
      error = tlsReadEcPoint(&context->ecdhContext.params,
         &context->ecdhContext.qb, p, length, &n);

      //Check status code
      if(!error)
      {
         //Total number of bytes that have been consumed
         *consumed = n;

         //Verify client's public key and make sure that it is on the same
         //elliptic curve as the server's ECDH key
         error = ecdhCheckPublicKey(&context->ecdhContext.params,
            &context->ecdhContext.qb);
      }

      //Check status code
      if(!error)
      {
         //Calculate the shared secret Z. Leading zeros found in this octet
         //string must not be truncated (see RFC 4492, section 5.10)
         error = ecdhComputeSharedSecret(&context->ecdhContext,
            context->premasterSecret, TLS_PREMASTER_SECRET_SIZE,
            &context->premasterSecretLen);
      }
   }
   else
#endif
   //Invalid key exchange method?
   {
      //The specified key exchange method is not supported
      error = ERROR_UNSUPPORTED_KEY_EXCH_METHOD;
   }

   //Return status code
   return error;
}

#endif
