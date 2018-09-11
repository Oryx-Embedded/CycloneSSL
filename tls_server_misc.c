/**
 * @file tls_server_misc.c
 * @brief Helper functions for TLS server
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
#include "tls_cipher_suites.h"
#include "tls_handshake_misc.h"
#include "tls_server.h"
#include "tls_server_misc.h"
#include "tls_common.h"
#include "tls_record.h"
#include "tls_signature.h"
#include "tls_certificate.h"
#include "tls_cache.h"
#include "tls_ffdhe.h"
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
      //Full handshake?
      if(!context->resume)
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
      else
      {
         //When resuming a session, the server must not include a ServerName
         //extension in the ServerHello (refer to RFC 6066, section 3)
         n = 0;
      }
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
            extension->value[0] = TLS_MAX_FRAGMENT_LENGTH_512;
            break;
         case 1024:
            extension->value[0] = TLS_MAX_FRAGMENT_LENGTH_1024;
            break;
         case 2048:
            extension->value[0] = TLS_MAX_FRAGMENT_LENGTH_2048;
            break;
         default:
            extension->value[0] = TLS_MAX_FRAGMENT_LENGTH_4096;
            break;
         }

         //The extension data field contains a single byte
         n = sizeof(uint8_t);
         //Fix the length of the extension
         extension->length = htons(n);

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
 * @brief Format RecordSizeLimit extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the RecordSizeLimit extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatServerRecordSizeLimitExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   //An extension type must not appear in the ServerHello unless the same
   //extension type appeared in the corresponding ClientHello
   if(context->recordSizeLimitExtReceived)
   {
      uint16_t recordSizeLimit;
      TlsExtension *extension;

      //Add the RecordSizeLimit extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_RECORD_SIZE_LIMIT);

      //An endpoint must not send a value higher than the protocol-defined
      //maximum record size (refer to RFC 8449, section 4)
      recordSizeLimit = MIN(context->rxBufferMaxLen, TLS_MAX_RECORD_LENGTH);

      //The value of RecordSizeLimit is the maximum size of record in octets
      //that the endpoint is willing to receive
      STORE16BE(recordSizeLimit, extension->value);

      //The extension data field contains a 16-bit unsigned integer
      n = sizeof(uint16_t);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the RecordSizeLimit extension
      n += sizeof(TlsExtension);
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
      uint16_t identifier;

      //Retrieve the selected cipher suite
      identifier = context->cipherSuite.identifier;

      //A server that selects an ECC cipher suite in response to a ClientHello
      //message including an EcPointFormats extension appends this extension
      //to its ServerHello message
      if(tlsGetCipherSuiteType(identifier) == TLS_CIPHER_SUITE_TYPE_ECC)
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

         //Consider the length field that precedes the list
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
         protocolName->length = (uint8_t) n;
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
 * @brief Format ClientCertType extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the ClientCertType extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientCertTypeExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //An extension type must not appear in the ServerHello unless the same
   //extension type appeared in the corresponding ClientHello
   if(context->clientCertTypeExtReceived)
   {
      TlsExtension *extension;

      //Add the ClientCertType extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_CLIENT_CERT_TYPE);

      //The ClientCertType extension in the ServerHello indicates the type
      //of certificates the client is requested to provide in a subsequent
      //certificate payload
      extension->value[0] = context->peerCertFormat;

      //The extension data field contains a single byte
      n = sizeof(uint8_t);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the ClientCertType extension
      n += sizeof(TlsExtension);
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format ServerCertType extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the ServerCertType extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatServerCertTypeExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //An extension type must not appear in the ServerHello unless the same
   //extension type appeared in the corresponding ClientHello
   if(context->serverCertTypeExtReceived)
   {
      TlsExtension *extension;

      //Add the ServerCertType extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_SERVER_CERT_TYPE);

      //With the ServerCertType extension in the ServerHello, the TLS server
      //indicates the certificate type carried in the certificate payload
      extension->value[0] = context->certFormat;

      //The extension data field contains a single byte
      n = sizeof(uint8_t);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the ServerCertType extension
      n += sizeof(TlsExtension);
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
         renegoInfo->length = (uint8_t) n;

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
 * @param[in] p Output stream where to write the server's key exchange parameters
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

#if (TLS_FFDHE_SUPPORT == ENABLED)
      //Valid FFDHE group?
      if(context->namedGroup != TLS_GROUP_NONE)
      {
         //Load FFDHE parameters
         error = tlsLoadFfdheParameters(&context->dhContext.params,
            context->namedGroup);
      }
#endif

      //Check status code
      if(!error)
      {
         //Generate an ephemeral key pair
         error = dhGenerateKeyPair(&context->dhContext, context->prngAlgo,
            context->prngContext);
      }

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
      curveInfo = tlsGetCurveInfo(context->namedGroup);

      //Make sure the elliptic curve is supported
      if(curveInfo != NULL)
      {
         //Load EC domain parameters
         error = ecLoadDomainParameters(&context->ecdhContext.params,
            curveInfo);

         //Check status code
         if(!error)
         {
#if (TLS_ECC_CALLBACK_SUPPORT == ENABLED)
            //Any registered callback?
            if(context->ecdhCallback != NULL)
            {
               //Invoke user callback function
               error = context->ecdhCallback(context);
            }
            else
#endif
            {
               //No callback function defined
               error = ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
            }

            //Check status code
            if(error == ERROR_UNSUPPORTED_ELLIPTIC_CURVE)
            {
               //Generate an ephemeral key pair
               error = ecdhGenerateKeyPair(&context->ecdhContext,
                  context->prngAlgo, context->prngContext);
            }
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
            STORE16BE(context->namedGroup, p);

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
 * @brief Sign server's key exchange parameters (SSL 3.0, TLS 1.0 and TLS 1.1)
 * @param[in] context Pointer to the TLS context
 * @param[in] signature Output stream where to write the digital signature
 * @param[in] params Pointer to the server's key exchange parameters
 * @param[in] paramsLen Length of the server's key exchange parameters
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsGenerateServerKeySignature(TlsContext *context,
   TlsDigitalSignature *signature, const uint8_t *params,
   size_t paramsLen, size_t *written)
{
   error_t error;

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //Initialize status code
   error = NO_ERROR;

   //Total number of bytes that have been written
   *written = 0;

#if (TLS_DHE_RSA_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED)
   //DHE_RSA or ECDHE_RSA key exchange method?
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
         //Compute MD5(ClientHello.random + ServerHello.random +
         //ServerKeyExchange.params)
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
            //Compute SHA(ClientHello.random + ServerHello.random +
            //ServerKeyExchange.params)
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
   //DHE_DSS key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS)
   {
      Sha1Context *sha1Context;

      //Allocate a memory buffer to hold the SHA-1 context
      sha1Context = tlsAllocMem(sizeof(Sha1Context));

      //Successful memory allocation?
      if(sha1Context != NULL)
      {
         //Compute SHA(ClientHello.random + ServerHello.random +
         //ServerKeyExchange.params)
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
   //ECDHE_ECDSA key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
   {
      //The digitally-signed element does not convey the signature algorithm
      //to use, and hence implementations need to inspect the certificate to
      //find out the signature algorithm to use
      if(context->cert->type == TLS_CERT_ECDSA_SIGN)
      {
         Sha1Context *sha1Context;

         //Allocate a memory buffer to hold the SHA-1 context
         sha1Context = tlsAllocMem(sizeof(Sha1Context));

         //Successful memory allocation?
         if(sha1Context != NULL)
         {
            //Compute SHA(ClientHello.random + ServerHello.random +
            //ServerKeyExchange.params)
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
      {
         //The signature algorithm is not supported
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }
   else
#endif
   //Invalid key exchange method?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Fix the length of the digitally-signed element
   signature->length = htons(*written);
   //Adjust the length of the signature
   *written += sizeof(TlsDigitalSignature);
#else
   //Not implemented
   error = ERROR_NOT_IMPLEMENTED;
#endif

   //Return status code
   return error;
}


/**
 * @brief Sign server's key exchange parameters (TLS 1.2)
 * @param[in] context Pointer to the TLS context
 * @param[in] signature Output stream where to write the digital signature
 * @param[in] params Pointer to the server's key exchange parameters
 * @param[in] paramsLen Length of the server's key exchange parameters
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tls12GenerateServerKeySignature(TlsContext *context,
   Tls12DigitalSignature *signature, const uint8_t *params,
   size_t paramsLen, size_t *written)
{
   error_t error;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Initialize status code
   error = NO_ERROR;

   //Total number of bytes that have been written
   *written = 0;

#if (TLS_DHE_RSA_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_DHE_DSS_SUPPORT == ENABLED || TLS_ECDHE_ECDSA_SUPPORT == ENABLED)
   //RSA, DSA or ECDSA signature algorithm?
   if(context->cert->type == TLS_CERT_RSA_SIGN ||
      context->cert->type == TLS_CERT_DSS_SIGN ||
      context->cert->type == TLS_CERT_ECDSA_SIGN)
   {
      const HashAlgo *hashAlgo;
      HashContext *hashContext;

      //Retrieve the hash algorithm used for signing
      if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256)
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
      else if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384)
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
      else if(context->signAlgo == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512)
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
      else
         hashAlgo = tlsGetHashAlgo(context->signHashAlgo);

      //Make sure the hash algorithm is supported
      if(hashAlgo != NULL)
      {
         //Allocate a memory buffer to hold the hash context
         hashContext = tlsAllocMem(hashAlgo->contextSize);

         //Successful memory allocation?
         if(hashContext != NULL)
         {
            //Compute hash(ClientHello.random + ServerHello.random +
            //ServerKeyExchange.params)
            hashAlgo->init(hashContext);
            hashAlgo->update(hashContext, context->random, 64);
            hashAlgo->update(hashContext, params, paramsLen);
            hashAlgo->final(hashContext, NULL);

#if (TLS_DHE_RSA_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED)
            //DHE_RSA or ECDHE_RSA key exchange method?
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
#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
                  //RSASSA-PKCS1-v1_5 signature scheme?
                  if(context->signAlgo == TLS_SIGN_ALGO_RSA)
                  {
                     //Set the relevant signature algorithm
                     signature->algorithm.signature = TLS_SIGN_ALGO_RSA;
                     signature->algorithm.hash = context->signHashAlgo;

                     //Generate RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
                     error = rsassaPkcs1v15Sign(&privateKey, hashAlgo,
                        hashContext->digest, signature->value, written);
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
                        hashContext->digest, signature->value, written);
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
#if (TLS_DHE_DSS_SUPPORT == ENABLED)
            //DHE_DSS key exchange method?
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
            //ECDHE_ECDSA key exchange method?
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
            //Invalid key exchange method?
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
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }
   else
#endif
#if (TLS_ED25519_SUPPORT == ENABLED || TLS_ED448_SUPPORT == ENABLED)
   //EdDSA signature algorithm?
   if(context->cert->type == TLS_CERT_ED25519_SIGN ||
      context->cert->type == TLS_CERT_ED448_SIGN)
   {
#if (TLS_ECDHE_ECDSA_SUPPORT == ENABLED)
      //ECDHE_ECDSA key exchange method?
      if(context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
      {
         uint8_t *buffer;

         //A temporary buffer is needed to concatenate ClientHello.random +
         //ServerHello.random + ServerKeyExchange.params
         buffer = tlsAllocMem(paramsLen + 64);

         //Successful memory allocation?
         if(buffer != NULL)
         {
            //Data to be verified is run through the EdDSA algorithm with no
            //hashing
            memcpy(buffer, context->random, 64);
            memcpy(buffer + 64, params, paramsLen);

            //Set the relevant signature algorithm
            if(context->cert->type == TLS_CERT_ED25519_SIGN)
            {
               signature->algorithm.signature = TLS_SIGN_ALGO_ED25519;
               signature->algorithm.hash = TLS_HASH_ALGO_INTRINSIC;
            }
            else
            {
               signature->algorithm.signature = TLS_SIGN_ALGO_ED448;
               signature->algorithm.hash = TLS_HASH_ALGO_INTRINSIC;
            }

            //Sign the key exchange parameters using EdDSA
            error = tlsGenerateEddsaSignature(context, buffer, paramsLen + 64,
               signature->value, written);

            //Release previously allocated memory
            tlsFreeMem(buffer);
         }
         else
         {
            //Failed to allocate memory
            error = ERROR_OUT_OF_MEMORY;
         }
      }
      else
#endif
      //Invalid key exchange method?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
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
   //Adjust the length of the message
   *written += sizeof(Tls12DigitalSignature);
#else
   //Not implemented
   error = ERROR_NOT_IMPLEMENTED;
#endif

   //Return status code
   return error;
}


/**
 * @brief Check whether the ClientHello includes any SCSV cipher suites
 * @param[in] context Pointer to the TLS context
 * @param[in] cipherSuites List of cipher suites offered by the client
 * @return Error code
 **/

error_t tlsCheckSignalingCipherSuiteValues(TlsContext *context,
   const TlsCipherSuites *cipherSuites)
{
   error_t error;
   uint_t i;
   uint_t n;
   uint16_t serverVersion;

   //Initialize status code
   error = NO_ERROR;

   //Get the highest version supported by the implementation (legacy version)
   serverVersion = MIN(context->versionMax, TLS_VERSION_1_2);

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Translate TLS version into DTLS version
      serverVersion = dtlsTranslateVersion(serverVersion);
   }
#endif

   //Get the number of cipher suite identifiers present in the list
   n = ntohs(cipherSuites->length) / 2;

   //Debug message
   TRACE_DEBUG("Cipher suites:\r\n");

   //Loop through the list of cipher suite identifiers
   for(i = 0; i < n; i++)
   {
      //Debug message
      TRACE_DEBUG("  0x%04" PRIX16 " (%s)\r\n", ntohs(cipherSuites->value[i]),
         tlsGetCipherSuiteName(ntohs(cipherSuites->value[i])));

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
      //TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite?
      if(ntohs(cipherSuites->value[i]) == TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
      {
         //Initial handshake?
         if(context->clientVerifyDataLen == 0)
         {
            //Set the secure_renegotiation flag to TRUE
            context->secureRenegoFlag = TRUE;
         }
         //Secure renegotiation?
         else
         {
            //When a ClientHello is received, the server must verify that it
            //does not contain the TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV. If
            //the SCSV is present, the server must abort the handshake
            error = ERROR_HANDSHAKE_FAILED;
            break;
         }
      }
      else
#endif
      //TLS_FALLBACK_SCSV signaling cipher suite?
      if(ntohs(cipherSuites->value[i]) == TLS_FALLBACK_SCSV)
      {
#if (DTLS_SUPPORT == ENABLED)
         //DTLS protocol?
         if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
         {
            //Test if the highest protocol version supported by the server is
            //higher than the version indicated by the client
            if(serverVersion < context->clientVersion)
            {
               //The server must respond with a fatal inappropriate_fallback alert
               error = ERROR_INAPPROPRIATE_FALLBACK;
               break;
            }
         }
         else
#endif
         //TLS protocol?
         {
            //Test if the highest protocol version supported by the server is
            //higher than the version indicated by the client
            if(serverVersion > context->clientVersion)
            {
               //The server must respond with a fatal inappropriate_fallback alert
               error = ERROR_INAPPROPRIATE_FALLBACK;
               break;
            }
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Version negotiation
 * @param[in] context Pointer to the TLS context
 * @param[in] clientVersion Highest version number supported by the client (legacy version)
 * @param[in] supportedVersionList Pointer to the SupportedVersions extensions
 * @return Error code
 **/

error_t tlsNegotiateVersion(TlsContext *context, uint16_t clientVersion,
   const TlsSupportedVersionList *supportedVersionList)
{
   error_t error;
   uint16_t serverVersion;

   //Get the highest version supported by the implementation
   serverVersion = context->versionMax;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //In DTLS 1.2, the client can indicate its version preferences in the
      //SupportedVersions extension
      if(supportedVersionList != NULL && context->versionMax >= TLS_VERSION_1_2)
      {
         //If the SupportedVersions extension is present in the ClientHello,
         //servers must only select a version of TLS present in that extension
         error = dtlsParseClientSupportedVersionsExtension(context,
            (DtlsSupportedVersionList *) supportedVersionList);
      }
      else
      {
         //If the SupportedVersions extension is not present, servers must
         //negotiate DTLS 1.2 or prior
         serverVersion = MIN(serverVersion, TLS_VERSION_1_2);

         //Translate TLS version into DTLS version
         serverVersion = dtlsTranslateVersion(serverVersion);

         //If a DTLS server receives a ClientHello containing a version number
         //greater than the highest version supported by the server, it must
         //reply according to the highest version supported by the server
         serverVersion = MAX(serverVersion, clientVersion);

         //Set the DTLS version to be used
         error = dtlsSelectVersion(context, serverVersion);
      }
   }
   else
#endif
   //TLS protocol?
   {
      //In TLS 1.2, the client can indicate its version preferences in the
      //SupportedVersions extension
      if(supportedVersionList != NULL && context->versionMax >= TLS_VERSION_1_2)
      {
         //If the SupportedVersions extension is present in the ClientHello,
         //servers must only select a version of TLS present in that extension
         error = tlsParseClientSupportedVersionsExtension(context,
            supportedVersionList);
      }
      else
      {
         //If the SupportedVersions extension is not present, servers must
         //negotiate TLS 1.2 or prior
         serverVersion = MIN(serverVersion, TLS_VERSION_1_2);

         //If a TLS server receives a ClientHello containing a version number
         //greater than the highest version supported by the server, it must
         //reply according to the highest version supported by the server
         serverVersion = MIN(serverVersion, clientVersion);

         //Set the TLS version to be used
         error = tlsSelectVersion(context, serverVersion);
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Cipher suite negotiation
 * @param[in] context Pointer to the TLS context
 * @param[in] cipherSuites List of cipher suites offered by the client
 * @param[in] extensions ClientHello extensions offered by the client
 * @return Error code
 **/

error_t tlsNegotiateCipherSuite(TlsContext *context,
   const TlsCipherSuites *cipherSuites, const TlsHelloExtensions *extensions)
{
   error_t error;
   uint_t i;
   uint_t j;
   uint_t n;

   //Initialize status code
   error = ERROR_HANDSHAKE_FAILED;

   //Get the total number of cipher suites offered by the client
   n = ntohs(cipherSuites->length) / 2;

   //Any preferred cipher suites?
   if(context->numCipherSuites > 0)
   {
      //Loop through the list of allowed cipher suites (most preferred first)
      for(i = 0; i < context->numCipherSuites && error; i++)
      {
         //Loop through the list of cipher suites offered by the client
         for(j = 0; j < n && error; j++)
         {
            //Acceptable cipher suite?
            if(context->cipherSuites[i] == ntohs(cipherSuites->value[j]))
            {
               //Select current cipher suite
               error = tlsSelectCipherSuite(context, context->cipherSuites[i]);

               //If the list contains cipher suites the server does not recognize,
               //support, or wish to use, the server must ignore those cipher suites,
               //and process the remaining ones as usual
               if(!error)
               {
                  //Select cipher suite parameters
                  error = tlsSelectCipherSuiteParams(context, extensions);
               }
            }
         }
      }
   }
   else
   {
      //The cipher suite list contains the combinations of cryptographic
      //algorithms supported by the client in order of the client's preference
      for(j = 0; j < n && error; j++)
      {
         //Check whether the current cipher suite is supported
         error = tlsSelectCipherSuite(context, ntohs(cipherSuites->value[j]));

         //If the list contains cipher suites the server does not recognize,
         //support, or wish to use, the server must ignore those cipher suites,
         //and process the remaining ones as usual
         if(!error)
         {
            //Select cipher suite parameters
            error = tlsSelectCipherSuiteParams(context, extensions);
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Select cipher suite parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] extensions ClientHello extensions offered by the client
 * @return Error code
 **/

error_t tlsSelectCipherSuiteParams(TlsContext *context,
   const TlsHelloExtensions *extensions)
{
   error_t error;
   uint_t i;
   uint8_t certType;
   bool_t acceptable;

   //ECC cipher suite?
   if(context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //One of the proposed ECC cipher suites must be negotiated only if the
      //server can successfully complete the handshake while using the curves
      //and point formats supported by the client
      error = tlsSelectNamedCurve(context, extensions->supportedGroupList);
   }
#if (TLS_FFDHE_SUPPORT == ENABLED)
   //FFDHE cipher suite?
   else if(context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK)
   {
      //If none of the client-proposed FFDHE groups are known and acceptable
      //to the server, then the server must not select an FFDHE cipher suite
      error = tlsSelectFfdheGroup(context, extensions->supportedGroupList);
   }
#endif
   else
   {
      //Successful processing
      error = NO_ERROR;
   }

   //Check status code
   if(!error)
   {
      //The server requires a valid certificate whenever the agreed-upon key
      //exchange method uses certificates for authentication
      if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
      {
         //RSA, DHE_RSA, ECDHE_RSA and RSA_PSK key exchange methods require
         //a RSA certificate
         certType = TLS_CERT_RSA_SIGN;
      }
      else if(context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS)
      {
         //DHE_DSS key exchange method requires a DSA certificate
         certType = TLS_CERT_DSS_SIGN;
      }
      else if(context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
      {
         //ECDHE_ECDSA key exchange method requires an ECDSA certificate
         certType = TLS_CERT_ECDSA_SIGN;
      }
      else
      {
         //DH_anon and ECDH_anon key exchange methods do not require any
         //certificate
         certType = TLS_CERT_NONE;
      }

      //Check whether a certificate is required
      if(certType != TLS_CERT_NONE)
      {
         //Do not accept the specified cipher suite unless a suitable
         //certificate has been previously loaded by the user
         error = ERROR_NO_CERTIFICATE;

         //Loop through the list of available certificates
         for(i = 0; i < context->numCerts; i++)
         {
            //Check whether the current certificate is acceptable
            acceptable = tlsIsCertificateAcceptable(&context->certs[i],
               &certType, 1, extensions->signAlgoList,
               extensions->supportedGroupList, NULL);

            //The certificate must be appropriate for the negotiated cipher
            //suite and any negotiated extensions
            if(acceptable)
            {
               //The hash algorithm to be used when generating signatures must
               //be one of those present in the SignatureAlgorithms extension
               error = tlsSelectSignHashAlgo(context, &context->certs[i],
                  extensions->signAlgoList);

               //If all the requirements were met, the certificate can be used
               //in conjunction with the selected cipher suite
               if(!error)
               {
                  context->cert = &context->certs[i];
                  break;
               }
            }
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse the list of compression methods supported by the client
 * @param[in] context Pointer to the TLS context
 * @param[in] compressMethods List of compression methods
 * @return Error code
 **/

error_t tlsParseCompressMethods(TlsContext *context,
   const TlsCompressMethods *compressMethods)
{
   error_t error;
   uint_t i;

   //Initialize status code
   error = ERROR_ILLEGAL_PARAMETER;

   //The list of the compression methods supported by the client is sorted by
   //client preference
   for(i = 0; i < compressMethods->length && error; i++)
   {
      //Check whether the current compression algorithm is supported
      error = tlsSelectCompressMethod(context, compressMethods->value[i]);
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SupportedVersions extension
 * @param[in] context Pointer to the TLS context
 * @param[in] supportedVersionList Pointer to the SupportedVersions extension
 * @return Error code
 **/

error_t tlsParseClientSupportedVersionsExtension(TlsContext *context,
   const TlsSupportedVersionList *supportedVersionList)
{
   error_t error;
   uint_t i;
   uint_t j;
   uint_t n;

   //Supported TLS versions
   const uint16_t supportedVersions[] =
   {
      TLS_VERSION_1_2,
      TLS_VERSION_1_1,
      TLS_VERSION_1_0,
      SSL_VERSION_3_0
   };

   //Initialize status code
   error = ERROR_VERSION_NOT_SUPPORTED;

   //Retrieve the number of items in the list
   n = supportedVersionList->length / sizeof(uint16_t);

   //Loop through the list of TLS versions supported by the server
   for(i = 0; i < arraysize(supportedVersions) && error; i++)
   {
      //The extension contains a list of TLS versions supported by the client
      for(j = 0; j < n && error; j++)
      {
         //Servers must only select a version of TLS present in that extension
         //and must ignore any unknown versions
         if(ntohs(supportedVersionList->value[j]) == supportedVersions[i])
         {
            //Set the TLS version to be used
            error = tlsSelectVersion(context, supportedVersions[i]);
         }
      }
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
   //SNI extension found?
   if(serverNameList != NULL)
   {
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
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   //MaxFragmentLength extension found?
   if(maxFragLen != NULL)
   {
      size_t n;

      //Retrieve the value advertised by the client
      switch(*maxFragLen)
      {
      case TLS_MAX_FRAGMENT_LENGTH_512:
         n = 512;
         break;
      case TLS_MAX_FRAGMENT_LENGTH_1024:
         n = 1024;
         break;
      case TLS_MAX_FRAGMENT_LENGTH_2048:
         n = 2048;
         break;
      case TLS_MAX_FRAGMENT_LENGTH_4096:
         n = 4096;
         break;
      default:
         n = 0;
         break;
      }

      //Acceptable value?
      if(n > 0)
      {
         //Once a maximum fragment length has been successfully negotiated,
         //the server must immediately begin fragmenting messages (including
         //handshake messages) to ensure that no fragment larger than the
         //negotiated length is sent
         context->maxFragLen = n;
      }
      else
      {
         //If a server receives a maximum fragment length negotiation request
         //for a value other than the allowed values, it must abort the handshake
         //with an illegal_parameter alert
         error = ERROR_ILLEGAL_PARAMETER;
      }

      //The ClientHello includes a MaxFragmentLength extension
      context->maxFragLenExtReceived = TRUE;
   }
   else
   {
      //The ClientHello does not contain any MaxFragmentLength extension
      context->maxFragLenExtReceived = FALSE;
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Parse RecordSizeLimit extension
 * @param[in] context Pointer to the TLS context
 * @param[in] recordSizeLimit Pointer to the RecordSizeLimit extension
 * @return Error code
 **/

error_t tlsParseClientRecordSizeLimitExtension(TlsContext *context,
   const uint8_t *recordSizeLimit)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   //RecordSizeLimit extension found?
   if(recordSizeLimit != NULL)
   {
      uint16_t n;

      //The value of RecordSizeLimit is the maximum size of record in octets
      //that the peer is willing to receive
      n = LOAD16BE(recordSizeLimit);

      //Endpoints must not send a RecordSizeLimit extension with a value
      //smaller than 64
      if(n < 64)
      {
         //An endpoint must treat receipt of a smaller value as a fatal error
         //and generate an illegal_parameter alert
         error = ERROR_ILLEGAL_PARAMETER;
      }
      else
      {
         //The peer can include any limit up to the protocol-defined limit for
         //maximum record size. Even if a larger value is provided by a peer, an
         //endpoint must not send records larger than the protocol-defined limit
         context->recordSizeLimit = MIN(n, TLS_MAX_RECORD_LENGTH);
      }

      //The ClientHello includes a RecordSizeLimit extension
      context->recordSizeLimitExtReceived = TRUE;
   }
   else
   {
      //The ClientHello does not contain any RecordSizeLimit extension
      context->recordSizeLimitExtReceived = FALSE;
   }
#endif

   //Return status code
   return error;
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

   //Initialize status code
   error = NO_ERROR;

#if (TLS_ECDH_ANON_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //EcPointFormats extension found?
   if(ecPointFormatList != NULL)
   {
      uint_t i;

      //Loop through the list of supported EC point formats
      for(i = 0; i < ecPointFormatList->length; i++)
      {
         //Uncompressed point format?
         if(ecPointFormatList->value[i] == TLS_EC_POINT_FORMAT_UNCOMPRESSED)
         {
            break;
         }
      }

      //The uncompressed point format must be supported by any TLS application
      //that supports this extension (refer to RFC 4492, section 5.1)
      if(i >= ecPointFormatList->length)
      {
         //Report an error
         error = ERROR_ILLEGAL_PARAMETER;
      }

      //The ClientHello includes a EcPointFormats extension
      context->ecPointFormatsExtReceived = TRUE;
   }
   else
   {
      //If no SupportedPointsFormat extension is sent, the uncompressed format
      //has to be used
      context->ecPointFormatsExtReceived = FALSE;
   }
#endif

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
   //ALPN extension found?
   if(protocolNameList != NULL)
   {
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
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ClientCertType extension
 * @param[in] context Pointer to the TLS context
 * @param[in] clientCertTypeList Pointer to the ClientCertType extension
 * @return Error code
 **/

error_t tlsParseClientCertTypeListExtension(TlsContext *context,
   const TlsCertTypeList *clientCertTypeList)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //ClientCertType extension found?
   if(clientCertTypeList != NULL)
   {
      //If the server does not send any CertificateRequest message, then the
      //ClientCertType extension in the ServerHello must be omitted
      if(context->clientAuthMode != TLS_CLIENT_AUTH_NONE)
      {
         uint_t i;

         //The ClientCertType extension carries a list of supported certificate
         //types, sorted by client preference
         for(i = 0; i < clientCertTypeList->length; i++)
         {
            //Check certificate type
            if(clientCertTypeList->value[i] == TLS_CERT_FORMAT_X509)
            {
               //Select X.509 certificate format
               context->peerCertFormat = TLS_CERT_FORMAT_X509;
               //Exit immediately
               break;
            }
            else if(clientCertTypeList->value[i] == TLS_CERT_FORMAT_RAW_PUBLIC_KEY)
            {
               //Ensure the server is able to process raw public keys
               if(context->rpkVerifyCallback != NULL)
               {
                  //Select raw public key format
                  context->peerCertFormat = TLS_CERT_FORMAT_RAW_PUBLIC_KEY;
                  //Exit immediately
                  break;
               }
            }
            else
            {
               //Unsupported certificate type
            }
         }

         //If the server does not have any certificate type in common with the
         //client, then the server terminates the session with a fatal alert
         if(i >= clientCertTypeList->length)
         {
            //Report an error
            error = ERROR_UNSUPPORTED_CERTIFICATE;
         }

         //The ClientHello includes a ClientCertType extension
         context->clientCertTypeExtReceived = TRUE;
      }
   }
   else
   {
      //The ClientHello does not contain any ClientCertType extension
      context->clientCertTypeExtReceived = FALSE;
      //Select default certificate format
      context->peerCertFormat = TLS_CERT_FORMAT_X509;
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Parse ServerCertType extension
 * @param[in] context Pointer to the TLS context
 * @param[in] serverCertTypeList Pointer to the ServerCertType extension
 * @return Error code
 **/

error_t tlsParseServerCertTypeListExtension(TlsContext *context,
   const TlsCertTypeList *serverCertTypeList)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //ServerCertType extension found?
   if(serverCertTypeList != NULL)
   {
      uint_t i;

      //The ServerCertType extension carries a list of supported certificate
      //types, sorted by client preference
      for(i = 0; i < serverCertTypeList->length; i++)
      {
         //Check certificate type
         if(serverCertTypeList->value[i] == TLS_CERT_FORMAT_X509 ||
            serverCertTypeList->value[i] == TLS_CERT_FORMAT_RAW_PUBLIC_KEY)
         {
            //The certificate type is selected from one of the values provided
            //by the client
            context->certFormat = (TlsCertificateFormat) serverCertTypeList->value[i];

            //We are done
            break;
         }
      }

      //If the server does not have any certificate type in common with the
      //client, then the server terminates the session with a fatal alert
      if(i >= serverCertTypeList->length)
      {
         //Report an error
         error = ERROR_UNSUPPORTED_CERTIFICATE;
      }

      //The ClientHello includes a ServerCertType extension
      context->serverCertTypeExtReceived = TRUE;
   }
   else
   {
      //The ClientHello does not contain any ServerCertType extension
      context->serverCertTypeExtReceived = FALSE;
      //Select default certificate format
      context->certFormat = TLS_CERT_FORMAT_X509;
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Parse ExtendedMasterSecret extension
 * @param[in] context Pointer to the TLS context
 * @param[in] extendedMasterSecret Pointer to the ExtendedMasterSecret extension
 * @return Error code
 **/

error_t tlsParseClientEmsExtension(TlsContext *context,
   const uint8_t *extendedMasterSecret)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //ExtendedMasterSecret extension found?
   if(extendedMasterSecret != NULL)
   {
      //SSL 3.0 currently selected?
      if(context->version == SSL_VERSION_3_0)
      {
         //If the client chooses to support SSL 3.0, the resulting session
         //must use the legacy master secret computation
         context->extendedMasterSecretExtReceived = FALSE;
      }
      else
      {
         //Use the extended master secret computation
         context->extendedMasterSecretExtReceived = TRUE;
      }
   }
   else
   {
      //Abbreviated handshake?
      if(context->resume)
      {
         //If the original session used the ExtendedMasterSecret extension but
         //the new ClientHello does not contain it, the server must abort the
         //abbreviated handshake
         if(context->extendedMasterSecretExtReceived)
         {
            //Report an error
            error = ERROR_HANDSHAKE_FAILED;
         }
      }

      //If the client and server choose to continue a full handshake without
      //the extension, they must use the standard master secret derivation
      //for the new session
      context->extendedMasterSecretExtReceived = FALSE;
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Parse RenegotiationInfo extension
 * @param[in] context Pointer to the TLS context
 * @param[in] renegoInfo Pointer to the RenegotiationInfo extension
 * @return Error code
 **/

error_t tlsParseClientRenegoInfoExtension(TlsContext *context,
   const TlsRenegoInfo *renegoInfo)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //RenegotiationInfo extension found?
   if(renegoInfo != NULL)
   {
      //Initial handshake?
      if(context->clientVerifyDataLen == 0)
      {
         //Set the secure_renegotiation flag to TRUE
         context->secureRenegoFlag = TRUE;

         //The server must then verify that the length of the
         //renegotiated_connection field is zero
         if(renegoInfo->length != 0)
         {
            //If it is not, the server must abort the handshake
            error = ERROR_HANDSHAKE_FAILED;
         }
      }
      //Secure renegotiation?
      else
      {
         //Check the length of the renegotiated_connection field
         if(renegoInfo->length != context->clientVerifyDataLen)
         {
            //The server must abort the handshake
            error = ERROR_HANDSHAKE_FAILED;
         }
         else
         {
            //Verify that the value of the renegotiated_connection field
            //is equal to the saved client_verify_data value
            if(memcmp(renegoInfo->value, context->clientVerifyData,
               context->clientVerifyDataLen))
            {
               //If it is not, the server must abort the handshake
               error = ERROR_HANDSHAKE_FAILED;
            }
         }
      }
   }
   else
   {
      //Secure renegotiation?
      if(context->clientVerifyDataLen != 0 || context->serverVerifyDataLen != 0)
      {
         //The server must verify that the renegotiation_info extension is
         //present. If it is not, the server must abort the handshake
         error = ERROR_HANDSHAKE_FAILED;
      }
   }
#endif

   //Return status code
   return error;
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
#if (TLS_ECC_CALLBACK_SUPPORT == ENABLED)
         //Any registered callback?
         if(context->ecdhCallback != NULL)
         {
            //Invoke user callback function
            error = context->ecdhCallback(context);
         }
         else
#endif
         {
            //No callback function defined
            error = ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
         }

         //Check status code
         if(error == ERROR_UNSUPPORTED_ELLIPTIC_CURVE)
         {
            //Calculate the shared secret Z. Leading zeros found in this octet
            //string must not be truncated (see RFC 4492, section 5.10)
            error = ecdhComputeSharedSecret(&context->ecdhContext,
               context->premasterSecret, TLS_PREMASTER_SECRET_SIZE,
               &context->premasterSecretLen);
         }
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
