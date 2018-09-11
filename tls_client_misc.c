/**
 * @file tls_client_misc.c
 * @brief Helper functions for TLS client
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
#include "tls_client.h"
#include "tls_client_misc.h"
#include "tls_common.h"
#include "tls_record.h"
#include "tls_signature.h"
#include "tls_cache.h"
#include "tls_ffdhe.h"
#include "tls_misc.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED && TLS_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Format the list of cipher suites supported by the client
 * @param[in] context Pointer to the TLS context
 * @param[out] cipherSuiteTypes Types of cipher suites proposed by the client
 * @param[in] p Output stream where to write the list of cipher suites
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatCipherSuites(TlsContext *context,
   uint_t *cipherSuiteTypes, uint8_t *p, size_t *written)
{
   uint_t i;
   uint_t k;
   uint_t n;
   TlsCipherSuites *cipherSuites;
   const TlsCipherSuiteInfo *cipherSuite;

   //Types of cipher suites proposed by the client
   *cipherSuiteTypes = TLS_CIPHER_SUITE_TYPE_UNKNOWN;

   //Point to the list of cryptographic algorithms supported by the client
   cipherSuites = (TlsCipherSuites *) p;
   //Number of cipher suites in the array
   n = 0;

   //Debug message
   TRACE_DEBUG("Cipher suites:\r\n");

   //Any preferred cipher suites?
   if(context->numCipherSuites > 0)
   {
      //Loop through the list of preferred cipher suites
      for(i = 0; i < context->numCipherSuites; i++)
      {
         //Make sure the specified cipher suite is supported
         if(tlsIsCipherSuiteSupported(context->cipherSuites[i],
            context->versionMax, context->transportProtocol))
         {
            //Copy cipher suite identifier
            cipherSuites->value[n++] = htons(context->cipherSuites[i]);

            //Debug message
            TRACE_DEBUG("  0x%04" PRIX16 " (%s)\r\n", context->cipherSuites[i],
               tlsGetCipherSuiteName(context->cipherSuites[i]));

            //Check whether the identifier matches an ECC/FFDHE cipher suite
            *cipherSuiteTypes |= tlsGetCipherSuiteType(context->cipherSuites[i]);
         }
      }
   }
   else
   {
      //Determine the number of supported cipher suites
      k = tlsGetNumSupportedCipherSuites();

      //Loop through the list of supported cipher suites
      for(i = 0; i < k; i++)
      {
         //Point to the current cipher suite
         cipherSuite = &tlsSupportedCipherSuites[i];

         //TLS 1.2 cipher suites must not be negotiated in older versions of TLS
         if(context->versionMax == TLS_VERSION_1_2 ||
            cipherSuite->prfHashAlgo == NULL)
         {
            //The only stream cipher described in TLS 1.2 is RC4, which cannot
            //be randomly accessed. RC4 must not be used with DTLS
            if(context->transportProtocol != TLS_TRANSPORT_PROTOCOL_DATAGRAM ||
               cipherSuite->cipherMode != CIPHER_MODE_STREAM)
            {
               //Copy cipher suite identifier
               cipherSuites->value[n++] = htons(cipherSuite->identifier);

               //Debug message
               TRACE_DEBUG("  0x%04" PRIX16 " (%s)\r\n", cipherSuite->identifier,
                  cipherSuite->name);

               //Check whether the identifier matches an ECC/FFDHE cipher suite
               *cipherSuiteTypes |= tlsGetCipherSuiteType(cipherSuite->identifier);
            }
         }
      }
   }

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //Check whether secure renegotiation is enabled
   if(context->secureRenegoEnabled)
   {
      //Initial handshake?
      if(context->clientVerifyDataLen == 0)
      {
         //The client includes the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling
         //cipher suite value in its ClientHello
         cipherSuites->value[n++] = HTONS(TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
      }
   }
#endif

#if (TLS_FALLBACK_SCSV_SUPPORT == ENABLED)
   //Check whether support for FALLBACK_SCSV is enabled
   if(context->fallbackScsvEnabled)
   {
      //The TLS_FALLBACK_SCSV cipher suite value is meant for use by clients
      //that repeat a connection attempt with a downgraded protocol
      if(context->versionMax != TLS_MAX_VERSION)
      {
         //The client should put TLS_FALLBACK_SCSV after all cipher suites
         //that it actually intends to negotiate
         cipherSuites->value[n++] = HTONS(TLS_FALLBACK_SCSV);
      }
   }
#endif

   //Length of the array, in bytes
   cipherSuites->length = htons(n * 2);

   //Total number of bytes that have been written
   *written = sizeof(TlsCipherSuites) + n * 2;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format the list of compression methods supported by the client
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the list of compression methods
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatCompressMethods(TlsContext *context,
   uint8_t *p, size_t *written)
{
   TlsCompressMethods *compressMethods;

   //List of compression algorithms supported by the client
   compressMethods = (TlsCompressMethods *) p;

   //The CRIME exploit takes advantage of TLS compression, so conservative
   //implementations do not enable compression at the TLS level
   compressMethods->length = 1;
   compressMethods->value[0] = TLS_COMPRESSION_METHOD_NULL;

   //Total number of bytes that have been written
   *written = sizeof(TlsCompressMethods) + compressMethods->length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SupportedVersions extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the SupportedVersions extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientSupportedVersionsExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

   //In TLS 1.2, the client can indicate its version preferences in the
   //SupportedVersions extension, in preference to the legacy_version field
   //of the ClientHello
   if(context->versionMax >= TLS_VERSION_1_2)
   {
      TlsExtension *extension;
      TlsSupportedVersionList *supportedVersionList;

      //Add the SupportedVersions extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_SUPPORTED_VERSIONS);

      //Point to the extension data field
      supportedVersionList = (TlsSupportedVersionList *) extension->value;

      //The extension contains a list of supported versions in preference
      //order, with the most preferred version first
      n = 0;

#if (DTLS_SUPPORT == ENABLED)
      //DTLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
      {
         //Check whether DTLS 1.2 is supported
         if(context->versionMax >= TLS_VERSION_1_2 && context->versionMin <= TLS_VERSION_1_2)
            supportedVersionList->value[n++] = HTONS(DTLS_VERSION_1_2);

         //Check whether DTLS 1.0 is supported
         if(context->versionMax >= TLS_VERSION_1_1 && context->versionMin <= TLS_VERSION_1_1)
            supportedVersionList->value[n++] = HTONS(DTLS_VERSION_1_0);
      }
      else
#endif
      //TLS protocol?
      {
         //Check whether TLS 1.2 is supported
         if(context->versionMax >= TLS_VERSION_1_2 && context->versionMin <= TLS_VERSION_1_2)
            supportedVersionList->value[n++] = HTONS(TLS_VERSION_1_2);

         //Check whether TLS 1.1 is supported
         if(context->versionMax >= TLS_VERSION_1_1 && context->versionMin <= TLS_VERSION_1_1)
            supportedVersionList->value[n++] = HTONS(TLS_VERSION_1_1);

         //Check whether TLS 1.0 is supported
         if(context->versionMax >= TLS_VERSION_1_0 && context->versionMin <= TLS_VERSION_1_0)
            supportedVersionList->value[n++] = HTONS(TLS_VERSION_1_0);

         //Check whether SSL 3.0 is supported
         if(context->versionMax >= SSL_VERSION_3_0 && context->versionMin <= SSL_VERSION_3_0)
            supportedVersionList->value[n++] = HTONS(SSL_VERSION_3_0);
      }

      //Compute the length, in bytes, of the list
      n *= sizeof(uint16_t);
      //Fix the length of the list
      supportedVersionList->length = (uint8_t) n;

      //Consider the length field that precedes the list
      n += sizeof(TlsSupportedVersionList);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the SupportedVersions extension
      n += sizeof(TlsExtension);
   }

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SNI extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the ServerName extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientSniExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_SNI_SUPPORT == ENABLED)
   //In order to provide the server name, clients may include a ServerName
   //extension
   if(context->serverName != NULL)
   {
      TlsExtension *extension;
      TlsServerNameList *serverNameList;
      TlsServerName *serverName;

      //Determine the length of the server name
      n = strlen(context->serverName);

      //Add SNI (Server Name Indication) extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_SERVER_NAME);

      //Point to the list of server names
      serverNameList = (TlsServerNameList *) extension->value;

      //Point to the server name
      serverName = (TlsServerName *) serverNameList->value;
      //Fill in the type and the length fields
      serverName->type = TLS_NAME_TYPE_HOSTNAME;
      serverName->length = htons(n);
      //Copy server name
      memcpy(serverName->hostname, context->serverName, n);

      //Compute the length, in byte, of the structure
      n += sizeof(TlsServerName);
      //Fix the length of the list
      serverNameList->length = htons(n);

      //Consider the 2-byte length field that precedes the list
      n += sizeof(TlsServerNameList);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the ServerName extension
      n += sizeof(TlsExtension);
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

error_t tlsFormatClientMaxFragLenExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   //In order to negotiate smaller maximum fragment lengths, clients may
   //include a MaxFragmentLength extension
   if(context->maxFragLen == 512 || context->maxFragLen == 1024 ||
      context->maxFragLen == 2048 || context->maxFragLen == 4096)
   {
      TlsExtension *extension;

      //Add the MaxFragmentLength extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_MAX_FRAGMENT_LENGTH);

      //Set the maximum fragment length
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

error_t tlsFormatClientRecordSizeLimitExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
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
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SupportedGroups extension
 * @param[in] context Pointer to the TLS context
 * @param[in] cipherSuiteTypes Types of cipher suites proposed by the client
 * @param[in] p Output stream where to write the SupportedGroups extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatSupportedGroupsExtension(TlsContext *context,
   uint_t cipherSuiteTypes, uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_ECDH_ANON_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED || \
   TLS_FFDHE_SUPPORT == ENABLED)
   TlsExtension *extension;
   TlsSupportedGroupList *supportedGroupList;

   //Add the SupportedGroups extension
   extension = (TlsExtension *) p;
   //Type of the extension
   extension->type = HTONS(TLS_EXT_SUPPORTED_GROUPS);

   //Point to the list of supported groups
   supportedGroupList = (TlsSupportedGroupList *) extension->value;
   //The groups are ordered according to client's preferences
   n = 0;

#if (TLS_ECDH_ANON_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //Any ECC cipher suite proposed by the client?
   if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_ECC) != 0)
   {
      //Curve25519 elliptic curve supported?
      if(tlsGetCurveInfo(TLS_GROUP_ECDH_X25519) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_ECDH_X25519);

      //Curve448 elliptic curve supported?
      if(tlsGetCurveInfo(TLS_GROUP_ECDH_X448) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_ECDH_X448);

      //secp160k1 elliptic curve supported?
      if(tlsGetCurveInfo(TLS_GROUP_SECP160K1) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_SECP160K1);

      //secp160r1 elliptic curve supported?
      if(tlsGetCurveInfo(TLS_GROUP_SECP160R1) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_SECP160R1);

      //secp160r2 elliptic curve supported?
      if(tlsGetCurveInfo(TLS_GROUP_SECP160R2) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_SECP160R2);

      //secp192k1 elliptic curve supported?
      if(tlsGetCurveInfo(TLS_GROUP_SECP192K1) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_SECP192K1);

      //secp192r1 elliptic curve supported?
      if(tlsGetCurveInfo(TLS_GROUP_SECP192R1) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_SECP192R1);

      //secp224k1 elliptic curve supported?
      if(tlsGetCurveInfo(TLS_GROUP_SECP224K1) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_SECP224K1);

      //secp224r1 elliptic curve supported?
      if(tlsGetCurveInfo(TLS_GROUP_SECP224R1) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_SECP224R1);

      //secp256k1 elliptic curve supported?
      if(tlsGetCurveInfo(TLS_GROUP_SECP256K1) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_SECP256K1);

      //secp256r1 elliptic curve supported?
      if(tlsGetCurveInfo(TLS_GROUP_SECP256R1) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_SECP256R1);

      //secp384r1 elliptic curve supported?
      if(tlsGetCurveInfo(TLS_GROUP_SECP384R1) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_SECP384R1);

      //secp521r1 elliptic curve supported?
      if(tlsGetCurveInfo(TLS_GROUP_SECP521R1) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_SECP521R1);

      //brainpoolP256r1 elliptic curve supported?
      if(tlsGetCurveInfo(TLS_GROUP_BRAINPOOLP256R1) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_BRAINPOOLP256R1);

      //brainpoolP384r1 elliptic curve supported?
      if(tlsGetCurveInfo(TLS_GROUP_BRAINPOOLP384R1) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_BRAINPOOLP384R1);

      //brainpoolP512r1 elliptic curve supported?
      if(tlsGetCurveInfo(TLS_GROUP_BRAINPOOLP512R1) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_BRAINPOOLP512R1);
   }
#endif

#if (TLS_FFDHE_SUPPORT == ENABLED)
   //Any FFDHE cipher suite proposed by the client?
   if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_FFDHE) != 0)
   {
      //ffdhe2048 group supported?
      if(tlsGetFfdheGroup(TLS_GROUP_FFDHE2048) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_FFDHE2048);

      //ffdhe3072 group supported?
      if(tlsGetFfdheGroup(TLS_GROUP_FFDHE3072) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_FFDHE3072);

      //ffdhe4096 group supported?
      if(tlsGetFfdheGroup(TLS_GROUP_FFDHE4096) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_FFDHE4096);

      //ffdhe6144 group supported?
      if(tlsGetFfdheGroup(TLS_GROUP_FFDHE6144) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_FFDHE6144);

      //ffdhe8192 group supported?
      if(tlsGetFfdheGroup(TLS_GROUP_FFDHE8192) != NULL)
         supportedGroupList->value[n++] = HTONS(TLS_GROUP_FFDHE8192);
   }
#endif

   //If the client supports and wants ECDHE and FFDHE key exchanges, it must
   //use a single SupportedGroups extension to include all supported groups
   //(both ECDHE and FFDHE groups)
   if(n != 0)
   {
      //Compute the length, in bytes, of the list
      n *= 2;
      //Fix the length of the list
      supportedGroupList->length = htons(n);

      //Consider the 2-byte length field that precedes the list
      n += sizeof(TlsSupportedGroupList);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the SupportedGroups extension
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
 * @param[in] cipherSuiteTypes Types of cipher suites proposed by the client
 * @param[in] p Output stream where to write the EcPointFormats extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientEcPointFormatsExtension(TlsContext *context,
   uint_t cipherSuiteTypes, uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_ECDH_ANON_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //A client that proposes ECC cipher suites in its ClientHello message
   //should send the EcPointFormats extension
   if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_ECC) != 0)
   {
      TlsExtension *extension;
      TlsEcPointFormatList *ecPointFormatList;

      //Add the EcPointFormats extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_EC_POINT_FORMATS);

      //Point to the list of supported EC point formats
      ecPointFormatList = (TlsEcPointFormatList *) extension->value;
      //Items in the list are ordered according to client's preferences
      n = 0;

      //The client can parse only the uncompressed point format...
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

error_t tlsFormatClientAlpnExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_ALPN_SUPPORT == ENABLED)
   //The ALPN extension contains the list of protocols advertised by the
   //client, in descending order of preference
   if(context->protocolList != NULL)
   {
      uint_t i;
      uint_t j;
      TlsExtension *extension;
      TlsProtocolName *protocolName;
      TlsProtocolNameList *protocolNameList;

      //Add ALPN (Application-Layer Protocol Negotiation) extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_ALPN);

      //Point to the list of protocol names
      protocolNameList = (TlsProtocolNameList *) extension->value;

      //Move back to the beginning of the list
      i = 0;
      j = 0;
      n = 0;

      //Parse the list of supported protocols
      do
      {
         //Delimiter character found?
         if(context->protocolList[i] == ',' || context->protocolList[i] == '\0')
         {
            //Discard empty tokens
            if((i - j) > 0)
            {
               //Point to the protocol name
               protocolName = (TlsProtocolName *) (protocolNameList->value + n);

               //Fill in the length field
               protocolName->length = i - j;
               //Copy protocol name
               memcpy(protocolName->value, context->protocolList + j, i - j);

               //Adjust the length of the list
               n += sizeof(TlsProtocolName) + i - j;
            }

            //Move to the next token
            j = i + 1;
         }

         //Loop until the NULL character is reached
      } while(context->protocolList[i++] != '\0');

      //Fix the length of the list
      protocolNameList->length = htons(n);

      //Consider the 2-byte length field that precedes the list
      n += sizeof(TlsProtocolNameList);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the ALPN extension
      n += sizeof(TlsExtension);
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

error_t tlsFormatClientCertTypeListExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   TlsExtension *extension;
   TlsCertTypeList *clientCertTypeList;

   //Add the ClientCertType extension
   extension = (TlsExtension *) p;
   //Type of the extension
   extension->type = HTONS(TLS_EXT_CLIENT_CERT_TYPE);

   //The ClientCertType extension in the ClientHello indicates the certificate
   //types the client is able to provide to the server, when requested using a
   //CertificateRequest message
   clientCertTypeList = (TlsCertTypeList *) extension->value;

   //The ClientCertType extension carries a list of supported certificate
   //types, sorted by client preference
   n = 0;

   //Raw public key type
   clientCertTypeList->value[n++] = TLS_CERT_FORMAT_RAW_PUBLIC_KEY;
   //X.509 certificate type
   clientCertTypeList->value[n++] = TLS_CERT_FORMAT_X509;

   //Fix the length of the list
   clientCertTypeList->length = (uint8_t) n;

   //Consider the length field that precedes the list
   n += sizeof(TlsCertTypeList);
   //Fix the length of the extension
   extension->length = htons(n);

   //Compute the length, in bytes, of the ClientCertType extension
   n += sizeof(TlsExtension);
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

error_t tlsFormatServerCertTypeListExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //Ensure the client is able to process raw public keys
   if(context->rpkVerifyCallback != NULL)
   {
      TlsExtension *extension;
      TlsCertTypeList *serverCertTypeList;

      //Add the ServerCertType extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_SERVER_CERT_TYPE);

      //The ServerCertType extension in the ClientHello indicates the types of
      //certificates the client is able to process when provided by the server
      //in a subsequent certificate payload
      serverCertTypeList = (TlsCertTypeList *) extension->value;

      //The ServerCertType extension carries a list of supported certificate
      //types, sorted by client preference
      n = 0;

      //Raw public key type
      serverCertTypeList->value[n++] = TLS_CERT_FORMAT_RAW_PUBLIC_KEY;
      //X.509 certificate type
      serverCertTypeList->value[n++] = TLS_CERT_FORMAT_X509;

      //Fix the length of the list
      serverCertTypeList->length = (uint8_t) n;

      //Consider the length field that precedes the list
      n += sizeof(TlsCertTypeList);
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

error_t tlsFormatClientEmsExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //If the client chooses to support SSL 3.0, the resulting session must
   //use the legacy master secret computation
   if(context->versionMax >= TLS_VERSION_1_0)
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

error_t tlsFormatClientRenegoInfoExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //Check whether secure renegotiation is enabled
   if(context->secureRenegoEnabled)
   {
      //During secure renegotiation, the client must include the RenegotiationInfo
      //extension containing the saved client_verify_data
      if(context->secureRenegoFlag)
      {
         TlsExtension *extension;
         TlsRenegoInfo *renegoInfo;

         //Determine the length of the verify data
         n = context->clientVerifyDataLen;

         //Add the RenegotiationInfo extension
         extension = (TlsExtension *) p;
         //Type of the extension
         extension->type = HTONS(TLS_EXT_RENEGOTIATION_INFO);

         //Point to the renegotiated_connection field
         renegoInfo = (TlsRenegoInfo *) extension->value;
         //Set the length of the verify data
         renegoInfo->length = (uint8_t) n;

         //Copy the verify data from the Finished message sent by the client
         //on the immediately previous handshake
         memcpy(renegoInfo->value, context->clientVerifyData, n);

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
 * @brief Format PSK identity
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the PSK identity hint
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatPskIdentity(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n;
   TlsPskIdentity *pskIdentity;

   //Point to the PSK identity
   pskIdentity = (TlsPskIdentity *) p;

   //Initialize length field
   n = 0;

#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //Any registered callback?
   if(context->pskCallback != NULL)
   {
      error_t error;

      //Invoke user callback function
      if(context->pskIdentityHint != NULL)
         error = context->pskCallback(context, context->pskIdentityHint);
      else
         error = context->pskCallback(context, "");

      //Any error to report?
      if(error)
         return ERROR_UNKNOWN_IDENTITY;
   }

   //Any PSK identity defined?
   if(context->pskIdentity != NULL)
   {
      //Determine the length of the PSK identity
      n = strlen(context->pskIdentity);
      //Copy PSK identity
      memcpy(pskIdentity->value, context->pskIdentity, n);
   }
#endif

   //The PSK identity is preceded by a 2-byte length field
   pskIdentity->length = htons(n);

   //Total number of bytes that have been written
   *written = sizeof(TlsPskIdentity) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format client's key exchange parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the client's key exchange parameters
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientKeyParams(TlsContext *context,
   uint8_t *p, size_t *written)
{
#if (TLS_RSA_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED)
   //RSA key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
   {
      error_t error;
      size_t n;

      //Sanity check
      if(TLS_PREMASTER_SECRET_SIZE < 48)
         return ERROR_BUFFER_OVERFLOW;

      //If RSA is being used for key agreement and authentication, the
      //client generates a 48-byte premaster secret
      context->premasterSecretLen = 48;

      //The first 2 bytes code the latest version supported by the client
      STORE16BE(context->clientVersion, context->premasterSecret);

      //The last 46 bytes contain securely-generated random bytes
      error = context->prngAlgo->read(context->prngContext,
         context->premasterSecret + 2, 46);
      //Any error to report?
      if(error)
         return error;

      //The RSA-encrypted premaster secret in a ClientKeyExchange is preceded by
      //two length bytes. SSL 3.0 implementations do not include these bytes
      if(context->version > SSL_VERSION_3_0)
      {
         //Encrypt the premaster secret using the server public key
         error = rsaesPkcs1v15Encrypt(context->prngAlgo, context->prngContext,
            &context->peerRsaPublicKey, context->premasterSecret, 48, p + 2, &n);
         //RSA encryption failed?
         if(error)
            return error;

         //Write the length field
         STORE16BE(n, p);

         //Length of the resulting octet string
         n += 2;
      }
      else
      {
         //Encrypt the premaster secret using the server public key
         error = rsaesPkcs1v15Encrypt(context->prngAlgo, context->prngContext,
            &context->peerRsaPublicKey, context->premasterSecret, 48, p, &n);
         //RSA encryption failed?
         if(error)
            return error;
      }

      //Total number of bytes that have been written
      *written = n;
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
      error_t error;
      size_t n;

      //Generate an ephemeral key pair
      error = dhGenerateKeyPair(&context->dhContext,
         context->prngAlgo, context->prngContext);
      //Any error to report?
      if(error)
         return error;

      //Encode the client's public value to an opaque vector
      error = tlsWriteMpi(&context->dhContext.ya, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Total number of bytes that have been written
      *written = n;

      //Calculate the negotiated key Z
      error = dhComputeSharedSecret(&context->dhContext,
         context->premasterSecret, TLS_PREMASTER_SECRET_SIZE,
         &context->premasterSecretLen);
      //Any error to report?
      if(error)
         return error;

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
      error_t error;
      size_t n;

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
         //Any error to report?
         if(error)
            return error;

         //Calculate the negotiated key Z
         error = ecdhComputeSharedSecret(&context->ecdhContext,
            context->premasterSecret, TLS_PREMASTER_SECRET_SIZE,
            &context->premasterSecretLen);
         //Any error to report?
         if(error)
            return error;
      }
      else if(error != NO_ERROR)
      {
         //Report an error
         return error;
      }

      //Encode the client's public key to an opaque vector
      error = tlsWriteEcPoint(&context->ecdhContext.params,
         &context->ecdhContext.qa, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Total number of bytes that have been written
      *written = n;
   }
   else
#endif
   //Invalid key exchange method?
   {
      //The specified key exchange method is not supported
      return ERROR_UNSUPPORTED_KEY_EXCH_METHOD;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SNI extension
 * @param[in] context Pointer to the TLS context
 * @param[in] serverNameList Pointer to the ServerName extension
 * @return Error code
 **/

error_t tlsParseServerSniExtension(TlsContext *context,
   const TlsServerNameList *serverNameList)
{
   //If a client receives an extension type in the ServerHello that it did
   //not request in the associated ClientHello, it must abort the handshake
   //with an unsupported_extension fatal alert
   if(context->serverName == NULL)
      return ERROR_UNSUPPORTED_EXTENSION;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse MaxFragmentLength extension
 * @param[in] context Pointer to the TLS context
 * @param[in] maxFragLen Pointer to the MaxFragmentLength extension
 * @return Error code
 **/

error_t tlsParseServerMaxFragLenExtension(TlsContext *context,
   const uint8_t *maxFragLen)
{
#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   size_t n;

   //Retrieve the value advertised by the server
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

   //If a client receives a maximum fragment length negotiation response that
   //differs from the length it requested, it must also abort the handshake
   //with an illegal_parameter alert
   if(n != context->maxFragLen)
      return ERROR_ILLEGAL_PARAMETER;
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse RecordSizeLimit extension
 * @param[in] context Pointer to the TLS context
 * @param[in] recordSizeLimit Pointer to the RecordSizeLimit extension
 * @return Error code
 **/

error_t tlsParseServerRecordSizeLimitExtension(TlsContext *context,
   const uint8_t *recordSizeLimit)
{
#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   uint16_t n;

   //The value of RecordSizeLimit is the maximum size of record in octets
   //that the peer is willing to receive
   n = LOAD16BE(recordSizeLimit);

   //An endpoint must treat receipt of a value smaller than 64 as a fatal
   //error and generate an illegal_parameter alert
   if(n < 64)
      return ERROR_ILLEGAL_PARAMETER;

   //The peer can include any limit up to the protocol-defined limit for
   //maximum record size. Even if a larger value is provided by a peer, an
   //endpoint must not send records larger than the protocol-defined limit
   context->recordSizeLimit = MIN(n, TLS_MAX_RECORD_LENGTH);
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

error_t tlsParseServerEcPointFormatsExtension(TlsContext *context,
   const TlsEcPointFormatList *ecPointFormatList)
{
   uint_t i;

   //Loop through the list of supported EC point formats
   for(i = 0; i < ecPointFormatList->length; i++)
   {
      //If the EcPointFormats extension is sent, it must contain the value 0
      //as one of the items in the list of point formats (refer to RFC 4492,
      //section 5.2)
      if(ecPointFormatList->value[i] == TLS_EC_POINT_FORMAT_UNCOMPRESSED)
      {
         //Exit immediately
         return NO_ERROR;
      }
   }

   //The point format is not supported
   return ERROR_ILLEGAL_PARAMETER;
}


/**
 * @brief Parse ALPN extension
 * @param[in] context Pointer to the TLS context
 * @param[in] protocolNameList Pointer to the ALPN extension
 * @return Error code
 **/

error_t tlsParseServerAlpnExtension(TlsContext *context,
   const TlsProtocolNameList *protocolNameList)
{
#if (TLS_ALPN_SUPPORT == ENABLED)
   size_t length;
   const TlsProtocolName *protocolName;

   //If a client receives an extension type in the ServerHello that it did
   //not request in the associated ClientHello, it must abort the handshake
   //with an unsupported_extension fatal alert
   if(context->protocolList == NULL)
      return ERROR_UNSUPPORTED_EXTENSION;

   //Retrieve the length of the list
   length = ntohs(protocolNameList->length);

   //The list must not be be empty
   if(length == 0)
      return ERROR_DECODING_FAILED;

   //Point to the selected protocol
   protocolName = (TlsProtocolName *) protocolNameList->value;

   //The list must contain exactly one protocol name
   if(length < sizeof(TlsProtocolName))
      return ERROR_DECODING_FAILED;
   if(length != (sizeof(TlsProtocolName) + protocolName->length))
      return ERROR_DECODING_FAILED;

   //Retrieve the length of the protocol name
   length -= sizeof(TlsProtocolName);

   //Empty strings must not be included in the list
   if(length == 0)
      return ERROR_DECODING_FAILED;

   //Check whether the protocol is supported by the client
   if(!tlsIsAlpnProtocolSupported(context, protocolName->value, length))
   {
      //Report an error if unknown ALPN protocols are disallowed
      if(!context->unknownProtocolsAllowed)
         return ERROR_ILLEGAL_PARAMETER;
   }

   //Sanity check
   if(context->selectedProtocol != NULL)
   {
      //Release memory
      tlsFreeMem(context->selectedProtocol);
      context->selectedProtocol = NULL;
   }

   //Allocate a memory block to hold the protocol name
   context->selectedProtocol = tlsAllocMem(length + 1);
   //Failed to allocate memory?
   if(context->selectedProtocol == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Save protocol name
   memcpy(context->selectedProtocol, protocolName->value, length);
   //Properly terminate the string with a NULL character
   context->selectedProtocol[length] = '\0';
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ClientCertType extension
 * @param[in] context Pointer to the TLS context
 * @param[in] clientCertType Pointer to the ClientCertType extension
 * @return Error code
 **/

error_t tlsParseClientCertTypeExtension(TlsContext *context,
   const uint8_t *clientCertType)
{
#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //The value conveyed in the extension must be selected from one of the
   //values provided in the ClientCertType extension sent in the ClientHello
   if(*clientCertType != TLS_CERT_FORMAT_X509 &&
      *clientCertType != TLS_CERT_FORMAT_RAW_PUBLIC_KEY)
   {
      return ERROR_ILLEGAL_PARAMETER;
   }

   //The ClientCertType extension in the ServerHello indicates the type
   //of certificates the client is requested to provide in a subsequent
   //certificate payload
   context->certFormat = (TlsCertificateFormat) *clientCertType;
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ServerCertType extension
 * @param[in] context Pointer to the TLS context
 * @param[in] serverCertType Pointer to the ServerCertType extension
 * @return Error code
 **/

error_t tlsParseServerCertTypeExtension(TlsContext *context,
   const uint8_t *serverCertType)
{
#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //If a client receives an extension type in the ServerHello that it did
   //not request in the associated ClientHello, it must abort the handshake
   //with an unsupported_extension fatal alert
   if(context->rpkVerifyCallback == NULL)
      return ERROR_UNSUPPORTED_EXTENSION;

   //The value conveyed in the extension must be selected from one of the
   //values provided in the ServerCertType extension sent in the ClientHello
   if(*serverCertType != TLS_CERT_FORMAT_X509 &&
      *serverCertType != TLS_CERT_FORMAT_RAW_PUBLIC_KEY)
   {
      return ERROR_ILLEGAL_PARAMETER;
   }

   //With the ServerCertType extension in the ServerHello, the TLS server
   //indicates the certificate type carried in the certificate payload
   context->peerCertFormat = (TlsCertificateFormat) *serverCertType;
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse PSK identity hint
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the PSK identity hint
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tlsParsePskIdentityHint(TlsContext *context,
   const uint8_t *p, size_t length, size_t *consumed)
{
   size_t n;
   TlsPskIdentityHint *pskIdentityHint;

   //Point to the PSK identity hint
   pskIdentityHint = (TlsPskIdentityHint *) p;

   //Malformed ServerKeyExchange message?
   if(length < sizeof(TlsPskIdentityHint))
      return ERROR_DECODING_FAILED;
   if(length < (sizeof(TlsPskIdentityHint) + ntohs(pskIdentityHint->length)))
      return ERROR_DECODING_FAILED;

   //Retrieve the length of the PSK identity hint
   n = ntohs(pskIdentityHint->length);

#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //Check whether the PSK identity hint has already been configured
   if(context->pskIdentityHint != NULL)
   {
      //Release memory
      tlsFreeMem(context->pskIdentityHint);
      context->pskIdentityHint = NULL;
   }

   //The PSK identity hint is optional
   if(n > 0)
   {
      //Allocate a memory block to hold the PSK identity hint
      context->pskIdentityHint = tlsAllocMem(n + 1);
      //Failed to allocate memory?
      if(context->pskIdentityHint == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Save the PSK identity hint
      memcpy(context->pskIdentityHint, pskIdentityHint->value, n);
      //Properly terminate the string
      context->pskIdentityHint[n] = '\0';
   }
#endif

   //Total number of bytes that have been consumed
   *consumed = sizeof(TlsPskIdentityHint) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse server's key exchange parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the server's key exchange parameters
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tlsParseServerKeyParams(TlsContext *context,
   const uint8_t *p, size_t length, size_t *consumed)
{
   error_t error;
   const uint8_t *params;

   //Initialize status code
   error = NO_ERROR;

   //Point to the server's key exchange parameters
   params = p;

#if (TLS_DH_ANON_SUPPORT == ENABLED || TLS_DHE_RSA_SUPPORT == ENABLED || \
   TLS_DHE_DSS_SUPPORT == ENABLED || TLS_DHE_PSK_SUPPORT == ENABLED)
   //Diffie-Hellman key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK)
   {
      uint_t k;
      size_t n;

      //Convert the prime modulus to a multiple precision integer
      error = tlsReadMpi(&context->dhContext.params.p, p, length, &n);

      //Check status code
      if(!error)
      {
         //Get the length of the prime modulus, in bits
         k = mpiGetBitLength(&context->dhContext.params.p);

         //Make sure the prime modulus is acceptable
         if(k < TLS_MIN_DH_MODULUS_SIZE || k > TLS_MAX_DH_MODULUS_SIZE)
            error = ERROR_ILLEGAL_PARAMETER;
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Remaining bytes to process
         length -= n;

         //Convert the generator to a multiple precision integer
         error = tlsReadMpi(&context->dhContext.params.g, p, length, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Remaining bytes to process
         length -= n;

         //Convert the server's public value to a multiple precision integer
         error = tlsReadMpi(&context->dhContext.yb, p, length, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Remaining bytes to process
         length -= n;

         //Verify peer's public value
         error = dhCheckPublicKey(&context->dhContext.params,
            &context->dhContext.yb);
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
         TRACE_DEBUG_MPI("    ", &context->dhContext.yb);
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
      uint8_t curveType;
      uint16_t namedCurve;
      const EcCurveInfo *curveInfo;

      //Initialize curve parameters
      curveInfo = NULL;

      //Malformed ServerKeyExchange message?
      if(length < sizeof(curveType))
         error = ERROR_DECODING_FAILED;

      //Check status code
      if(!error)
      {
         //Retrieve the type of the elliptic curve domain parameters
         curveType = *p;

         //Advance data pointer
         p += sizeof(curveType);
         //Remaining bytes to process
         length -= sizeof(curveType);

         //Only named curves are supported
         if(curveType != TLS_EC_CURVE_TYPE_NAMED_CURVE)
            error = ERROR_ILLEGAL_PARAMETER;
      }

      //Check status code
      if(!error)
      {
         //Malformed ServerKeyExchange message?
         if(length < sizeof(namedCurve))
            error = ERROR_DECODING_FAILED;
      }

      //Check status code
      if(!error)
      {
         //Get elliptic curve identifier
         namedCurve = LOAD16BE(p);

         //Advance data pointer
         p += sizeof(namedCurve);
         //Remaining bytes to process
         length -= sizeof(namedCurve);

         //Retrieve the corresponding EC domain parameters
         curveInfo = tlsGetCurveInfo(namedCurve);

         //Make sure the elliptic curve is supported
         if(curveInfo == NULL)
            error = ERROR_ILLEGAL_PARAMETER;
      }

      //Check status code
      if(!error)
      {
         //Load EC domain parameters
         error = ecLoadDomainParameters(&context->ecdhContext.params,
            curveInfo);
      }

      //Check status code
      if(!error)
      {
         //Read server's public key
         error = tlsReadEcPoint(&context->ecdhContext.params,
            &context->ecdhContext.qb, p, length, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         p += n;
         //Remaining bytes to process
         length -= n;

         //Verify peer's public key
         error = ecdhCheckPublicKey(&context->ecdhContext.params, &context->ecdhContext.qb);
      }

      //Check status code
      if(!error)
      {
         //Debug message
         TRACE_DEBUG("  Server public key X:\r\n");
         TRACE_DEBUG_MPI("    ", &context->ecdhContext.qb.x);
         TRACE_DEBUG("  Server public key Y:\r\n");
         TRACE_DEBUG_MPI("    ", &context->ecdhContext.qb.y);
      }
   }
   else
#endif
   //Invalid key exchange method?
   {
      //It is not legal to send the ServerKeyExchange message when a key
      //exchange method other than DHE_DSS, DHE_RSA, DH_anon, ECDHE_RSA,
      //ECDHE_ECDSA or ECDH_anon is selected
      error = ERROR_UNEXPECTED_MESSAGE;
   }

   //Total number of bytes that have been consumed
   *consumed = p - params;

   //Return status code
   return error;
}


/**
 * @brief Verify server's key exchange parameters signature (SSL 3.0, TLS 1.0 and TLS 1.1)
 * @param[in] context Pointer to the TLS context
 * @param[in] signature Pointer to the digital signature
 * @param[in] length Number of bytes available in the input stream
 * @param[in] params Pointer to the server's key exchange parameters
 * @param[in] paramsLen Length of the server's key exchange parameters
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tlsVerifyServerKeySignature(TlsContext *context,
   const TlsDigitalSignature *signature, size_t length,
   const uint8_t *params, size_t paramsLen, size_t *consumed)
{
   error_t error;

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //Initialize status code
   error = NO_ERROR;

   //Check the length of the digitally-signed element
   if(length < sizeof(TlsDigitalSignature))
      return ERROR_DECODING_FAILED;
   if(length < (sizeof(TlsDigitalSignature) + ntohs(signature->length)))
      return ERROR_DECODING_FAILED;

#if (TLS_DHE_RSA_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED)
   //DHE_RSA or ECDHE_RSA key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA)
   {
      Md5Context *md5Context;
      Sha1Context *sha1Context;

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
         //RSA signature verification
         error = tlsVerifyRsaSignature(&context->peerRsaPublicKey,
            context->serverVerifyData, signature->value, ntohs(signature->length));
      }
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
         //DSA signature verification
         error = tlsVerifyDsaSignature(context, context->serverVerifyData,
            SHA1_DIGEST_SIZE, signature->value, ntohs(signature->length));
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
      if(context->peerEcParams.type == EC_CURVE_TYPE_SECP_K1 ||
         context->peerEcParams.type == EC_CURVE_TYPE_SECP_R1 ||
         context->peerEcParams.type == EC_CURVE_TYPE_SECP_R2 ||
         context->peerEcParams.type == EC_CURVE_TYPE_BRAINPOOLP_R1)
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

         //Check status code
         if(!error)
         {
            //ECDSA signature verification
            error = tlsVerifyEcdsaSignature(context, context->serverVerifyData,
               SHA1_DIGEST_SIZE, signature->value, ntohs(signature->length));
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

   //Total number of bytes that have been consumed
   *consumed = sizeof(TlsDigitalSignature) + ntohs(signature->length);
#else
   //Not implemented
   error = ERROR_NOT_IMPLEMENTED;
#endif

   //Return status code
   return error;
}


/**
 * @brief Verify server's key exchange parameters signature (TLS 1.2)
 * @param[in] context Pointer to the TLS context
 * @param[in] signature Pointer to the digital signature
 * @param[in] length Number of bytes available in the input stream
 * @param[in] params Pointer to the server's key exchange parameters
 * @param[in] paramsLen Length of the server's key exchange parameters
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t tls12VerifyServerKeySignature(TlsContext *context,
   const Tls12DigitalSignature *signature, size_t length,
   const uint8_t *params, size_t paramsLen, size_t *consumed)
{
   error_t error;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Initialize status code
   error = NO_ERROR;

   //Check the length of the digitally-signed element
   if(length < sizeof(Tls12DigitalSignature))
      return ERROR_DECODING_FAILED;
   if(length < (sizeof(Tls12DigitalSignature) + ntohs(signature->length)))
      return ERROR_DECODING_FAILED;

#if (TLS_DHE_RSA_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_DHE_DSS_SUPPORT == ENABLED || TLS_ECDHE_ECDSA_SUPPORT == ENABLED)
   //RSA, DSA or ECDSA signature algorithm?
   if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA ||
      signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256 ||
      signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384 ||
      signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512 ||
      signature->algorithm.signature == TLS_SIGN_ALGO_DSA ||
      signature->algorithm.signature == TLS_SIGN_ALGO_ECDSA)
   {
      const HashAlgo *hashAlgo;
      HashContext *hashContext;

      //Retrieve the hash algorithm used for signing
      if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256)
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA256);
      else if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384)
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA384);
      else if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512)
         hashAlgo = tlsGetHashAlgo(TLS_HASH_ALGO_SHA512);
      else
         hashAlgo = tlsGetHashAlgo(signature->algorithm.hash);

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
#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
               //RSASSA-PKCS1-v1_5 signature scheme?
               if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA)
               {
                  //Verify RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
                  error = rsassaPkcs1v15Verify(&context->peerRsaPublicKey, hashAlgo,
                     hashContext->digest, signature->value, ntohs(signature->length));
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
                     hashAlgo->digestSize, hashContext->digest, signature->value,
                     ntohs(signature->length));
               }
               else
#endif
               //Invalid signature scheme?
               {
                  //Report an error
                  error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
               }
            }
            else
#endif
#if (TLS_DHE_DSS_SUPPORT == ENABLED)
            //DHE_DSS key exchange method?
            if(context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS &&
               signature->algorithm.signature == TLS_SIGN_ALGO_DSA)
            {
               //DSA signature verification
               error = tlsVerifyDsaSignature(context, hashContext->digest,
                  hashAlgo->digestSize, signature->value, ntohs(signature->length));
            }
            else
#endif
#if (TLS_ECDHE_ECDSA_SUPPORT == ENABLED)
            //ECDHE_ECDSA key exchange method?
            if(context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA &&
               signature->algorithm.signature == TLS_SIGN_ALGO_ECDSA)
            {
               //ECDSA signature verification
               error = tlsVerifyEcdsaSignature(context, hashContext->digest,
                  hashAlgo->digestSize, signature->value, ntohs(signature->length));
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
         error = ERROR_INVALID_SIGNATURE;
      }
   }
   else
#endif
#if (TLS_ED25519_SUPPORT == ENABLED || TLS_ED448_SUPPORT == ENABLED)
   //EdDSA signature algorithm?
   if(signature->algorithm.signature == TLS_SIGN_ALGO_ED25519 ||
      signature->algorithm.signature == TLS_SIGN_ALGO_ED448)
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

            //EdDSA signature verification
            error = tlsVerifyEddsaSignature(context, buffer, paramsLen + 64,
               signature->value, ntohs(signature->length));

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

   //Total number of bytes that have been consumed
   *consumed = sizeof(Tls12DigitalSignature) + ntohs(signature->length);
#else
   //Not implemented
   error = ERROR_NOT_IMPLEMENTED;
#endif

   //Return status code
   return error;
}

#endif
