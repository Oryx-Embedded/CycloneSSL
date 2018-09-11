/**
 * @file tls_client.c
 * @brief Handshake message processing (TLS client)
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
 * @section Description
 *
 * The TLS protocol provides communications security over the Internet. The
 * protocol allows client/server applications to communicate in a way that
 * is designed to prevent eavesdropping, tampering, or message forgery
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
#include "tls_handshake_hash.h"
#include "tls_handshake_misc.h"
#include "tls_client.h"
#include "tls_client_misc.h"
#include "tls_common.h"
#include "tls_record.h"
#include "tls_signature.h"
#include "tls_certificate.h"
#include "tls_key_material.h"
#include "tls_misc.h"
#include "dtls_record.h"
#include "dtls_misc.h"
#include "certificate/pem_import.h"
#include "date_time.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED && TLS_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Send ClientHello message
 *
 * When a client first connects to a server, it is required to send
 * the ClientHello as its first message. The client can also send a
 * ClientHello in response to a HelloRequest or on its own initiative
 * in order to renegotiate the security parameters in an existing
 * connection
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendClientHello(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsClientHello *message;

   //Point to the buffer where to format the message
   message = (TlsClientHello *) (context->txBuffer + context->txBufferLen);

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //When sending the first ClientHello, the client does not have a cookie yet
      if(context->cookieLen == 0)
      {
         //Generate the client random value using a cryptographically-safe
         //pseudorandom number generator
         error = tlsGenerateRandomValue(context, &context->clientRandom);
      }
      else
      {
         //When responding to a HelloVerifyRequest, the client must use the
         //same random value as it did in the original ClientHello
         error = NO_ERROR;
      }
   }
   else
#endif
   //TLS protocol?
   {
      //Generate the client random value using a cryptographically-safe
      //pseudorandom number generator
      error = tlsGenerateRandomValue(context, &context->clientRandom);
   }

   //Check status code
   if(!error)
   {
      //Format ClientHello message
      error = tlsFormatClientHello(context, message, &length);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending ClientHello message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsSendHandshakeMessage(context, message, length,
         TLS_TYPE_CLIENT_HELLO);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Prepare to receive ServerHello message...
      context->state = TLS_STATE_SERVER_HELLO;
   }

   //Return status code
   return error;
}


/**
 * @brief Send ClientKeyExchange message
 *
 * This message is always sent by the client. It must immediately
 * follow the client Certificate message, if it is sent. Otherwise,
 * it must be the first message sent by the client after it receives
 * the ServerHelloDone message
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendClientKeyExchange(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsClientKeyExchange *message;

   //Point to the buffer where to format the message
   message = (TlsClientKeyExchange *) (context->txBuffer + context->txBufferLen);

   //Format ClientKeyExchange message
   error = tlsFormatClientKeyExchange(context, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending ClientKeyExchange message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsSendHandshakeMessage(context, message, length,
         TLS_TYPE_CLIENT_KEY_EXCHANGE);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Derive session keys from the premaster secret
      error = tlsGenerateSessionKeys(context);

      //Key material successfully generated?
      if(!error)
      {
         //Prepare to send CertificateVerify message...
         context->state = TLS_STATE_CLIENT_CERTIFICATE_VERIFY;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Format ClientHello message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the ClientHello message
 * @param[out] length Length of the resulting ClientHello message
 * @return Error code
 **/

error_t tlsFormatClientHello(TlsContext *context,
   TlsClientHello *message, size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *p;
   uint_t cipherSuiteTypes;
   TlsExtensionList *extensionList;

   //Get the highest version supported by the implementation
   context->clientVersion = context->versionMax;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Translate TLS version into DTLS version
      context->clientVersion = dtlsTranslateVersion(context->clientVersion);
   }
#endif

   //Version of the protocol being employed by the client
   message->clientVersion = htons(context->clientVersion);

   //Client random value
   message->random = context->clientRandom;

   //Point to the session ID
   p = message->sessionId;
   //Length of the handshake message
   *length = sizeof(TlsClientHello);

#if (TLS_SESSION_RESUME_SUPPORT == ENABLED)
   //The SessionID value identifies a session the client wishes
   //to reuse for this connection
   message->sessionIdLen = (uint8_t) context->sessionIdLen;
   memcpy(message->sessionId, context->sessionId, context->sessionIdLen);
#else
   //Session resumption is not supported
   message->sessionIdLen = 0;
#endif

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //Secure renegotiation?
   if(context->secureRenegoEnabled && context->secureRenegoFlag)
   {
      //Do not offer a session ID when renegotiating
      message->sessionIdLen = 0;
   }
#endif

   //Point to the next field
   p += message->sessionIdLen;
   //Adjust the length of the message
   *length += message->sessionIdLen;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Format Cookie field
      error = dtlsFormatCookie(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += n;
      //Adjust the length of the message
      *length += n;
   }
#endif

   //Format the list of cipher suites supported by the client
   error = tlsFormatCipherSuites(context, &cipherSuiteTypes, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;

   //Format the list of compression methods supported by the client
   error = tlsFormatCompressMethods(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;

   //Clients may request extended functionality from servers by sending
   //data in the extensions field
   extensionList = (TlsExtensionList *) p;
   //Total length of the extension list
   extensionList->length = 0;

   //Point to the first extension of the list
   p += sizeof(TlsExtensionList);

   //In TLS 1.2, the client can indicate its version preferences in the
   //SupportedVersions extension
   error = tlsFormatClientSupportedVersionsExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;

#if (TLS_SNI_SUPPORT == ENABLED)
   //In order to provide the server name, clients may include a ServerName
   //extension
   error = tlsFormatClientSniExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;
#endif

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   //In order to negotiate smaller maximum fragment lengths, clients may
   //include a MaxFragmentLength extension
   error = tlsFormatClientMaxFragLenExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;
#endif

#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   //The value of RecordSizeLimit is the maximum size of record in octets
   //that the endpoint is willing to receive
   error = tlsFormatClientRecordSizeLimitExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;
#endif

   //A client that proposes ECC/FFDHE cipher suites in its ClientHello message
   //should send the SupportedGroups extension
   error = tlsFormatSupportedGroupsExtension(context, cipherSuiteTypes, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;

   //A client that proposes ECC cipher suites in its ClientHello message
   //should send the EcPointFormats extension
   error = tlsFormatClientEcPointFormatsExtension(context, cipherSuiteTypes,
      p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;

   //Include the SignatureAlgorithms extension only if TLS 1.2 is supported
   error = tlsFormatSignatureAlgorithmsExtension(context, cipherSuiteTypes,
      p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;

#if (TLS_ALPN_SUPPORT == ENABLED)
   //The ALPN extension contains the list of protocols advertised by the
   //client, in descending order of preference
   error = tlsFormatClientAlpnExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;
#endif

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //In order to indicate the support of raw public keys, clients include the
   //ClientCertType extension in an extended ClientHello message
   error = tlsFormatClientCertTypeListExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;

   //In order to indicate the support of raw public keys, clients include the
   //ServerCertType extension in an extended ClientHello message
   error = tlsFormatServerCertTypeListExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;
#endif

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //In all handshakes, a client implementing RFC 7627 must send the
   //ExtendedMasterSecret extension in its ClientHello
   error = tlsFormatClientEmsExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;
#endif

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //If the connection's secure_renegotiation flag is set to TRUE, the client
   //must include a RenegotiationInfo extension in its ClientHello message
   error = tlsFormatClientRenegoInfoExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;
#endif

   //Any extensions included in the ClientHello message?
   if(extensionList->length > 0)
   {
      //Convert the length of the extension list to network byte order
      extensionList->length = htons(extensionList->length);
      //Adjust the length of the message
      *length += sizeof(TlsExtensionList);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format ClientKeyExchange message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the ClientKeyExchange message
 * @param[out] length Length of the resulting ClientKeyExchange message
 * @return Error code
 **/

error_t tlsFormatClientKeyExchange(TlsContext *context,
   TlsClientKeyExchange *message, size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *p;

   //Point to the beginning of the handshake message
   p = message;
   //Length of the handshake message
   *length = 0;

#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //PSK key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //The client indicates which key to use by including a PSK identity
      //in the ClientKeyExchange message
      error = tlsFormatPskIdentity(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += n;
      //Adjust the length of the message
      *length += n;
   }
#endif

   //RSA, Diffie-Hellman or ECDH key exchange method?
   if(context->keyExchMethod != TLS_KEY_EXCH_PSK)
   {
      //Format client's key exchange parameters
      error = tlsFormatClientKeyParams(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += n;
      //Adjust the length of the message
      *length += n;
   }

#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //PSK key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //Invalid pre-shared key?
      if(context->pskLen == 0)
         return ERROR_INVALID_KEY_LENGTH;

      //Generate premaster secret
      error = tlsGeneratePskPremasterSecret(context);
      //Any error to report?
      if(error)
         return error;
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse HelloRequest message
 *
 * HelloRequest is a simple notification that the client should begin the
 * negotiation process anew. In response, the client should send a ClientHello
 * message when convenient
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming HelloRequest message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseHelloRequest(TlsContext *context,
   const TlsHelloRequest *message, size_t length)
{
   error_t error;

   //Debug message
   TRACE_INFO("HelloRequest message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check TLS version
   if(context->version > TLS_VERSION_1_2)
      return ERROR_UNEXPECTED_MESSAGE;

   //The HelloRequest message does not contain any data
   if(length != 0)
      return ERROR_DECODING_FAILED;

   //Check current state
   if(context->state == TLS_STATE_APPLICATION_DATA)
   {
#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
      //Check whether the secure_renegociation flag is set
      if(context->secureRenegoEnabled && context->secureRenegoFlag)
      {
         //HelloRequest is a simple notification that the client should begin
         //the negotiation process anew
         context->state = TLS_STATE_CLIENT_HELLO;

         //Continue processing
         error = NO_ERROR;
      }
      else
#endif
      {
         //If the connection's secure_renegotiation flag is set to FALSE, it
         //is recommended that clients refuse this renegotiation request (refer
         //to RFC 5746, section 4.2)
         error = tlsSendAlert(context, TLS_ALERT_LEVEL_FATAL,
            TLS_ALERT_NO_RENEGOTIATION);
      }
   }
   else
   {
      //The HelloRequest message can be sent at any time but it should be
      //ignored by the client if it arrives in the middle of a handshake
      error = NO_ERROR;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse ServerHello message
 *
 * The server will send this message in response to a ClientHello
 * message when it was able to find an acceptable set of algorithms.
 * If it cannot find such a match, it will respond with a handshake
 * failure alert
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming ServerHello message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseServerHello(TlsContext *context,
   const TlsServerHello *message, size_t length)
{
   error_t error;
   const uint8_t *p;
   TlsCipherSuite cipherSuite;
   TlsCompressMethod compressMethod;
   TlsHelloExtensions extensions;

   //Debug message
   TRACE_INFO("ServerHello message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check current state
   if(context->state != TLS_STATE_SERVER_HELLO)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check the length of the ServerHello message
   if(length < sizeof(TlsServerHello))
      return ERROR_DECODING_FAILED;

   //Point to the session ID
   p = message->sessionId;
   //Remaining bytes to process
   length -= sizeof(TlsServerHello);

   //Check the length of the session ID
   if(message->sessionIdLen > length)
      return ERROR_DECODING_FAILED;
   if(message->sessionIdLen > 32)
      return ERROR_DECODING_FAILED;

   //Point to the next field
   p += message->sessionIdLen;
   //Remaining bytes to process
   length -= message->sessionIdLen;

   //Malformed ServerHello message?
   if(length < sizeof(TlsCipherSuite))
      return ERROR_DECODING_FAILED;

   //Get the negotiated cipher suite
   cipherSuite = LOAD16BE(p);
   //Point to the next field
   p += sizeof(TlsCipherSuite);
   //Remaining bytes to process
   length -= sizeof(TlsCipherSuite);

   //Malformed ServerHello message?
   if(length < sizeof(TlsCompressMethod))
      return ERROR_DECODING_FAILED;

   //Get the negotiated compression method
   compressMethod = *p;
   //Point to the next field
   p += sizeof(TlsCompressMethod);
   //Remaining bytes to process
   length -= sizeof(TlsCompressMethod);

   //Parse the list of extensions offered by the server
   error = tlsParseHelloExtensions(TLS_TYPE_SERVER_HELLO, p, length,
      &extensions);
   //Any error to report?
   if(error)
      return error;

   //Server version
   TRACE_INFO("  serverVersion = 0x%04" PRIX16 " (%s)\r\n",
      ntohs(message->serverVersion),
      tlsGetVersionName(ntohs(message->serverVersion)));

   //Server random value
   TRACE_INFO("  random\r\n");
   TRACE_INFO_ARRAY("    ", &message->random, sizeof(TlsRandom));

   //Session identifier
   TRACE_INFO("  sessionId\r\n");
   TRACE_INFO_ARRAY("    ", message->sessionId, message->sessionIdLen);

   //Cipher suite identifier
   TRACE_INFO("  cipherSuite = 0x%04" PRIX16 " (%s)\r\n",
      cipherSuite, tlsGetCipherSuiteName(cipherSuite));

   //Compression method
   TRACE_INFO("  compressMethod = 0x%02" PRIX8 "\r\n", compressMethod);

#if (TLS_SESSION_RESUME_SUPPORT == ENABLED)
   //Check whether the session ID matches the value that was supplied by the client
   if(message->sessionIdLen > 0 &&
      message->sessionIdLen == context->sessionIdLen &&
      !memcmp(message->sessionId, context->sessionId, context->sessionIdLen))
   {
      //For resumed sessions, the selected cipher suite and compression
      //method shall be the same as the session being resumed
      if(cipherSuite != context->cipherSuite.identifier ||
         compressMethod != context->compressMethod)
      {
         //The session ID is no more valid
         context->sessionIdLen = 0;
         //When renegotiating, if the server tries to use another
         //version or compression method than previously, abort
         return ERROR_HANDSHAKE_FAILED;
      }

      //Perform abbreviated handshake
      context->resume = TRUE;
   }
   else
#endif
   {
      //Perform a full handshake
      context->resume = FALSE;
   }

   //Save server random value
   context->serverRandom = message->random;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Set the DTLS version to be used
      error = dtlsSelectVersion(context, ntohs(message->serverVersion));
   }
   else
#endif
   //TLS protocol?
   {
      //Set the TLS version to be used
      error = tlsSelectVersion(context, ntohs(message->serverVersion));
   }

   //Specified TLS/DTLS version not supported?
   if(error)
      return error;

   //Set cipher suite
   error = tlsSelectCipherSuite(context, cipherSuite);
   //Specified cipher suite not supported?
   if(error)
      return error;

   //Set compression method
   error = tlsSelectCompressMethod(context, compressMethod);
   //Specified compression method not supported?
   if(error)
      return error;

   //Initialize handshake message hashing
   error = tlsInitHandshakeHash(context);
   //Any error to report?
   if(error)
      return error;

   //Save session identifier
   memcpy(context->sessionId, message->sessionId, message->sessionIdLen);
   context->sessionIdLen = message->sessionIdLen;

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //Initial handshake?
   if(context->clientVerifyDataLen == 0)
   {
      //RenegotiationInfo extension found?
      if(extensions.renegoInfo != NULL)
      {
         //If the extension is present, set the secure_renegotiation flag to TRUE
         context->secureRenegoFlag = TRUE;

         //Verify that the length of the renegotiated_connection field is zero
         if(extensions.renegoInfo->length != 0)
         {
            //If it is not, the client must abort the handshake by sending a
            //fatal handshake failure alert
            return ERROR_HANDSHAKE_FAILED;
         }
      }
      else
      {
         //If the extension is not present, the server does not support secure
         //renegotiation
         context->secureRenegoFlag = FALSE;
      }
   }
   //Secure renegotiation?
   else
   {
      //RenegotiationInfo extension found?
      if(extensions.renegoInfo != NULL)
      {
         //Check the length of the renegotiated_connection field
         if(extensions.renegoInfo->length != (context->clientVerifyDataLen +
            context->serverVerifyDataLen))
         {
            //The client must abort the handshake
            return ERROR_HANDSHAKE_FAILED;
         }

         //The client must verify that the first half of the field is equal to
         //the saved client_verify_data value
         if(memcmp(extensions.renegoInfo->value, context->clientVerifyData,
            context->clientVerifyDataLen))
         {
            //If it is not, the client must abort the handshake
            return ERROR_HANDSHAKE_FAILED;
         }

         //The client must verify that the the second half of the field is
         //equal to the saved server_verify_data value
         if(memcmp(extensions.renegoInfo->value + context->clientVerifyDataLen,
            context->serverVerifyData, context->serverVerifyDataLen))
         {
            //If it is not, the client must abort the handshake
            return ERROR_HANDSHAKE_FAILED;
         }

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
         //ExtendedMasterSecret extension found?
         if(extensions.extendedMasterSecret != NULL)
         {
            //If the initial handshake did not use the ExtendedMasterSecret
            //extension but the new ServerHello contains the extension, the
            //client must abort the handshake
            if(!context->extendedMasterSecretExtReceived)
               return ERROR_HANDSHAKE_FAILED;
         }
         else
         {
            //If the initial handshake used the ExtendedMasterSecret extension
            //but the new ServerHello does not contain the extension, the
            //client must abort the handshake
            if(context->extendedMasterSecretExtReceived)
               return ERROR_HANDSHAKE_FAILED;
         }
#endif
      }
      else
      {
         //If the RenegotiationInfo extension is not present, the client
         //must abort the handshake
         return ERROR_HANDSHAKE_FAILED;
      }
   }
#endif

#if (TLS_SNI_SUPPORT == ENABLED)
   //ServerName extension found?
   if(extensions.serverNameList != NULL)
   {
      //When the server includes a ServerName extension, the data field of
      //this extension may be empty
      error = tlsParseServerSniExtension(context, extensions.serverNameList);
      //Any error to report?
      if(error)
         return error;
   }
#endif

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED && TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   //A client must treat receipt of both MaxFragmentLength and RecordSizeLimit
   //extensions as a fatal error, and it should generate an illegal_parameter
   //alert (refer to RFC 8449, section 5)
   if(extensions.maxFragLen != NULL && extensions.recordSizeLimit != NULL)
      return ERROR_ILLEGAL_PARAMETER;
#endif

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   //MaxFragmentLength extension found?
   if(extensions.maxFragLen != NULL)
   {
      //Servers that receive an ClientHello containing a MaxFragmentLength
      //extension may accept the requested maximum fragment length by including
      //an extension of type MaxFragmentLength in the ServerHello
      error = tlsParseServerMaxFragLenExtension(context, extensions.maxFragLen);
      //Any error to report?
      if(error)
         return error;
   }
#endif

#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   //RecordSizeLimit extension found?
   if(extensions.recordSizeLimit != NULL)
   {
      //The value of RecordSizeLimit is the maximum size of record in octets
      //that the peer is willing to receive
      error = tlsParseServerRecordSizeLimitExtension(context,
         extensions.recordSizeLimit);
      //Any error to report?
      if(error)
         return error;
   }
#endif

   //EcPointFormats extension found?
   if(extensions.ecPointFormatList != NULL)
   {
      //A server that selects an ECC cipher suite in response to a ClientHello
      //message including an EcPointFormats extension appends this extension
      //to its ServerHello message
      error = tlsParseServerEcPointFormatsExtension(context,
         extensions.ecPointFormatList);
      //Any error to report?
      if(error)
         return error;
   }

#if (TLS_ALPN_SUPPORT == ENABLED)
   //ALPN extension found?
   if(extensions.protocolNameList != NULL)
   {
      //Parse ALPN extension
      error = tlsParseServerAlpnExtension(context, extensions.protocolNameList);
      //Any error to report?
      if(error)
         return error;
   }
#endif

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //ClientCertType extension found?
   if(extensions.clientCertType != NULL)
   {
      //Parse ClientCertType extension
      error = tlsParseClientCertTypeExtension(context, extensions.clientCertType);
      //Any error to report?
      if(error)
         return error;
   }

   //ServerCertType extension found?
   if(extensions.serverCertType != NULL)
   {
      //Parse ServerCertType extension
      error = tlsParseServerCertTypeExtension(context, extensions.serverCertType);
      //Any error to report?
      if(error)
         return error;
   }
#endif

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //ExtendedMasterSecret extension found?
   if(extensions.extendedMasterSecret != NULL)
   {
      //The countermeasure described in RFC 7627 cannot be used with SSL 3.0
      if(context->version == SSL_VERSION_3_0)
         return ERROR_UNSUPPORTED_EXTENSION;

      //Abbreviated handshake?
      if(context->resume)
      {
         //If the original session did not use the ExtendedMasterSecret
         //extension but the new ServerHello contains the extension, the
         //client must abort the handshake
         if(!context->extendedMasterSecretExtReceived)
            return ERROR_HANDSHAKE_FAILED;
      }

      //A valid ExtendedMasterSecret extension has been received
      context->extendedMasterSecretExtReceived = TRUE;
   }
   else
   {
      //Abbreviated handshake?
      if(context->resume)
      {
         //If the original session used the ExtendedMasterSecret extension
         //but the new ServerHello does not contain the extension, the client
         //must abort the handshake
         if(context->extendedMasterSecretExtReceived)
            return ERROR_HANDSHAKE_FAILED;
      }

      //The ServerHello does not contain any ExtendedMasterSecret extension
      context->extendedMasterSecretExtReceived = FALSE;
   }
#endif

#if (TLS_SESSION_RESUME_SUPPORT == ENABLED)
   //Use abbreviated handshake?
   if(context->resume)
   {
      //Derive session keys from the master secret
      error = tlsGenerateSessionKeys(context);
      //Unable to generate key material?
      if(error)
         return error;

      //At this point, both client and server must send ChangeCipherSpec
      //messages and proceed directly to Finished messages
      context->state = TLS_STATE_SERVER_CHANGE_CIPHER_SPEC;
   }
   else
#endif
   {
      //Perform a full handshake
      if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
         context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
      {
         //The Certificate message is omitted from the server's response
         context->state = TLS_STATE_SERVER_KEY_EXCHANGE;
      }
      else
      {
         //The server is required to send a Certificate message
         context->state = TLS_STATE_SERVER_CERTIFICATE;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ServerKeyExchange message
 *
 * The ServerKeyExchange message is sent by the server only when the
 * server Certificate message does not contain enough data to allow
 * the client to exchange a premaster secret
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming ServerKeyExchange message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseServerKeyExchange(TlsContext *context,
   const TlsServerKeyExchange *message, size_t length)
{
   error_t error;
   size_t n;
   size_t paramsLen;
   const uint8_t *p;
   const uint8_t *params;

   //Debug message
   TRACE_INFO("ServerKeyExchange message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check TLS version
   if(context->version > TLS_VERSION_1_2)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check current state
   if(context->state != TLS_STATE_SERVER_KEY_EXCHANGE)
      return ERROR_UNEXPECTED_MESSAGE;

   //Initialize server's key exchange parameters
   params = NULL;
   //Point to the beginning of the handshake message
   p = message;

#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //PSK key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //To help the client in selecting which identity to use, the server
      //can provide a PSK identity hint in the ServerKeyExchange message
      error = tlsParsePskIdentityHint(context, p, length, &n);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += n;
      //Remaining bytes to process
      length -= n;
   }
#endif

   //Diffie-Hellman or ECDH key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //Point to the server's key exchange parameters
      params = p;

      //Parse server's key exchange parameters
      error = tlsParseServerKeyParams(context, p, length, &paramsLen);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += paramsLen;
      //Remaining bytes to process
      length -= paramsLen;
   }

   //For non-anonymous Diffie-Hellman and ECDH key exchanges, the signature
   //over the server's key exchange parameters shall be verified
   if(context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
   {
#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
      //SSL 3.0, TLS 1.0 or TLS 1.1 currently selected?
      if(context->version <= TLS_VERSION_1_1)
      {
         //Signature verification
         error = tlsVerifyServerKeySignature(context,
            (TlsDigitalSignature *) p, length, params, paramsLen, &n);
      }
      else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //TLS 1.2 currently selected?
      if(context->version == TLS_VERSION_1_2)
      {
         //Signature verification
         error = tls12VerifyServerKeySignature(context,
            (Tls12DigitalSignature *) p, length, params, paramsLen, &n);
      }
      else
#endif
      {
         //Report an error
         error = ERROR_INVALID_VERSION;
      }

      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += n;
      //Remaining bytes to process
      length -= n;
   }

   //If the amount of data in the message does not precisely match the format
   //of the ServerKeyExchange message, then send a fatal alert
   if(length != 0)
      return ERROR_DECODING_FAILED;

   //Anomynous server?
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //An anonymous server cannot request client authentication
      context->state = TLS_STATE_SERVER_HELLO_DONE;
   }
   else
   {
      //A non-anonymous server can optionally request a certificate from
      //the client, if appropriate for the selected cipher suite
      context->state = TLS_STATE_CERTIFICATE_REQUEST;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse CertificateRequest message
 *
 * A server can optionally request a certificate from the client, if
 * appropriate for the selected cipher suite. This message will
 * immediately follow the ServerKeyExchange message
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming CertificateRequest message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseCertificateRequest(TlsContext *context,
   const TlsCertificateRequest *message, size_t length)
{
   uint_t i;
   uint_t j;
   size_t n;
   uint8_t *p;
   bool_t acceptable;
   TlsSignHashAlgos *supportedSignAlgos;
   TlsCertAuthorities *certAuthorities;

   //Debug message
   TRACE_INFO("CertificateRequest message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check the length of the ServerKeyExchange message
   if(length < sizeof(TlsCertificateRequest))
      return ERROR_DECODING_FAILED;

   //Check key exchange method
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //It is a fatal handshake failure alert for an anonymous
      //server to request client authentication
      return ERROR_HANDSHAKE_FAILED;
   }
   else if(context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
   {
      //If no PSK identity hint is provided by the server, the
      //ServerKeyExchange message is omitted...
      if(context->state != TLS_STATE_SERVER_KEY_EXCHANGE &&
         context->state != TLS_STATE_CERTIFICATE_REQUEST)
      {
         //Handshake failure
         return ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else
   {
      //Check current state
      if(context->state != TLS_STATE_CERTIFICATE_REQUEST)
         return ERROR_UNEXPECTED_MESSAGE;
   }

   //The server requests a certificate from the client, so that
   //the connection can be mutually authenticated
   context->clientCertRequested = TRUE;

   //Point to the beginning of the message
   p = (uint8_t *) message;
   //Remaining bytes to process
   length -= sizeof(TlsCertificateRequest);

   //Retrieve the size of the list of supported certificate types
   n = message->certificateTypesLen;
   //Make sure the length field is valid
   if(n > length)
      return ERROR_DECODING_FAILED;

   //Point to the next field
   p += sizeof(TlsCertificateRequest) + n;
   //Remaining bytes to process
   length -= n;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      //Malformed CertificateRequest message?
      if(length < sizeof(TlsSignHashAlgos))
         return ERROR_DECODING_FAILED;

      //Point to the list of the hash/signature algorithm pairs that
      //the server is able to verify
      supportedSignAlgos = (TlsSignHashAlgos *) p;
      //Remaining bytes to process
      length -= sizeof(TlsSignHashAlgos);

      //Get the size of the list
      n = ntohs(supportedSignAlgos->length);
      //Make sure the length field is valid
      if(n > length)
         return ERROR_DECODING_FAILED;

      //Point to the next field
      p += sizeof(TlsSignHashAlgos) + n;
      //Remaining bytes to process
      length -= n;
   }
   //SSL 3.0, TLS 1.0 or TLS 1.1 currently selected?
   else
#endif
   {
      //Implementations prior to TLS 1.2 do not include a
      //list of supported hash/signature algorithm pairs
      supportedSignAlgos = NULL;
   }

   //Malformed CertificateRequest message?
   if(length < sizeof(TlsCertAuthorities))
      return ERROR_DECODING_FAILED;

   //Point to the list of the distinguished names of acceptable
   //certificate authorities
   certAuthorities = (TlsCertAuthorities *) p;
   //Remaining bytes to process
   length -= sizeof(TlsCertAuthorities);

   //Get the size of the list
   n = ntohs(certAuthorities->length);
   //Make sure the length field is valid
   if(n != length)
      return ERROR_DECODING_FAILED;

   //No suitable certificate has been found for the moment
   context->cert = NULL;

   //Select the most appropriate certificate (2-pass process)
   for(i = 0, acceptable = FALSE; i < 2 && !acceptable; i++)
   {
      //Loop through the list of available certificates
      for(j = 0; j < context->numCerts && !acceptable; j++)
      {
         //Check whether the current certificate is suitable
         acceptable = tlsIsCertificateAcceptable(&context->certs[j],
            message->certificateTypes, message->certificateTypesLen,
            NULL, NULL, certAuthorities);

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
         //TLS 1.2 requires additional examinations
         if(acceptable && context->version == TLS_VERSION_1_2)
         {
            //The hash and signature algorithms used in the signature of the
            //CertificateVerify message must be one of those present in the
            //SupportedSignatureAlgorithms field
            if(tlsSelectSignHashAlgo(context, &context->certs[j],
               supportedSignAlgos))
            {
               acceptable = FALSE;
            }
         }
#endif
         //If all the requirements were met, the certificate can be used
         if(acceptable)
         {
            context->cert = &context->certs[j];
         }
      }

      //The second pass relaxes the constraints
      certAuthorities = NULL;
   }

   //Prepare to receive ServerHelloDone message...
   context->state = TLS_STATE_SERVER_HELLO_DONE;
   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ServerHelloDone message
 *
 * The ServerHelloDone message is sent by the server to indicate the
 * end of the ServerHello and associated messages. After sending this
 * message, the server will wait for a client response
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming ServerHelloDone message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseServerHelloDone(TlsContext *context,
   const TlsServerHelloDone *message, size_t length)
{
   //Debug message
   TRACE_INFO("ServerHelloDone message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check TLS version
   if(context->version > TLS_VERSION_1_2)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check key exchange method
   if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
   {
      //The server may omit the CertificateRequest message and go
      //directly to the ServerHelloDone message
      if(context->state != TLS_STATE_CERTIFICATE_REQUEST &&
         context->state != TLS_STATE_SERVER_HELLO_DONE)
      {
         //Handshake failure
         return ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else if(context->keyExchMethod == TLS_KEY_EXCH_PSK)
   {
      //If no PSK identity hint is provided by the server, the
      //ServerKeyExchange message is omitted
      if(context->state != TLS_STATE_SERVER_KEY_EXCHANGE &&
         context->state != TLS_STATE_SERVER_HELLO_DONE)
      {
         //Handshake failure
         return ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else if(context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
   {
      //The server may omit the ServerKeyExchange message and/or
      //the CertificateRequest message
      if(context->state != TLS_STATE_SERVER_KEY_EXCHANGE &&
         context->state != TLS_STATE_CERTIFICATE_REQUEST &&
         context->state != TLS_STATE_SERVER_HELLO_DONE)
      {
         //Handshake failure
         return ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else
   {
      //Check current state
      if(context->state != TLS_STATE_SERVER_HELLO_DONE)
         return ERROR_UNEXPECTED_MESSAGE;
   }

   //The ServerHelloDone message does not contain any data
   if(length != 0)
      return ERROR_DECODING_FAILED;

   //Prepare to send client Certificate message...
   context->state = TLS_STATE_CLIENT_CERTIFICATE;
   //Successful processing
   return NO_ERROR;
}

#endif
