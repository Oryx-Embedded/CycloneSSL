/**
 * @file tls_server.c
 * @brief Handshake message processing (TLS server)
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
 * @section Description
 *
 * The TLS protocol provides communications security over the Internet. The
 * protocol allows client/server applications to communicate in a way that
 * is designed to prevent eavesdropping, tampering, or message forgery
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 1.7.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include <string.h>
#include "tls.h"
#include "tls_cipher_suites.h"
#include "tls_server.h"
#include "tls_server_misc.h"
#include "tls_common.h"
#include "tls_record.h"
#include "tls_cache.h"
#include "tls_misc.h"
#include "x509.h"
#include "pem.h"
#include "date_time.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED && TLS_SERVER_SUPPORT == ENABLED)


/**
 * @brief TLS server handshake
 *
 * TLS handshake protocol is responsible for the authentication
 * and key exchange necessary to establish a secure session
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsServerHandshake(TlsContext *context)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Wait for the handshake to complete
   do
   {
      //Flush send buffer
      if(context->state != TLS_STATE_CLOSED)
         error = tlsWriteProtocolData(context, NULL, 0, TLS_TYPE_NONE);

      //Check status code
      if(!error)
      {
         //Check whether the handshake is complete
         if(context->state == TLS_STATE_APPLICATION_DATA)
         {
            //At this is point, the handshake is complete and the server
            //starts to exchange application-layer data
            break;
         }

         //The TLS handshake is implemented as a state machine
         //representing the current location in the protocol
         switch(context->state)
         {
         //Default state?
         case TLS_STATE_INIT:
            //The client initiates the TLS handshake by sending a ClientHello
            //message to the server
            context->state = TLS_STATE_CLIENT_HELLO;
            break;
         //Sending ServerHello message?
         case TLS_STATE_SERVER_HELLO:
            //The server will send this message in response to a ClientHello
            //message when it was able to find an acceptable set of algorithms
            error = tlsSendServerHello(context);
            break;
         //Sending Certificate message?
         case TLS_STATE_SERVER_CERTIFICATE:
            //The server must send a Certificate message whenever the agreed-
            //upon key exchange method uses certificates for authentication. This
            //message will always immediately follow the ServerHello message
            error = tlsSendCertificate(context);
            break;
         //Sending ServerKeyExchange message?
         case TLS_STATE_SERVER_KEY_EXCHANGE:
            //The ServerKeyExchange message is sent by the server only when the
            //server Certificate message (if sent) does not contain enough data
            //to allow the client to exchange a premaster secret
            error = tlsSendServerKeyExchange(context);
            break;
         //Sending Certificate message?
         case TLS_STATE_CERTIFICATE_REQUEST:
            //A non-anonymous server can optionally request a certificate from the
            //client, if appropriate for the selected cipher suite. This message,
            //if sent, will immediately follow the ServerKeyExchange message
            error = tlsSendCertificateRequest(context);
            break;
         //Sending ServerHelloDone message?
         case TLS_STATE_SERVER_HELLO_DONE:
            //The ServerHelloDone message is sent by the server to indicate the
            //end of the ServerHello and associated messages
            error = tlsSendServerHelloDone(context);
            break;
         //Sending ChangeCipherSpec message?
         case TLS_STATE_SERVER_CHANGE_CIPHER_SPEC:
            //The ChangeCipherSpec message is sent by the server and to notify the
            //client that subsequent records will be protected under the newly
            //negotiated CipherSpec and keys
            error = tlsSendChangeCipherSpec(context);
            break;
         //Sending Finished message?
         case TLS_STATE_SERVER_FINISHED:
            //A Finished message is always sent immediately after a changeCipherSpec
            //message to verify that the key exchange and authentication processes
            //were successful
            error = tlsSendFinished(context);
            break;
         //Waiting for a message from the client?
         case TLS_STATE_CLIENT_HELLO:
         case TLS_STATE_CLIENT_CERTIFICATE:
         case TLS_STATE_CLIENT_KEY_EXCHANGE:
         case TLS_STATE_CERTIFICATE_VERIFY:
         case TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC:
         case TLS_STATE_CLIENT_FINISHED:
            //Parse incoming handshake message
            error = tlsParseClientMessage(context);
            break;
         //Sending Alert message?
         case TLS_STATE_CLOSING:
            //Mark the TLS connection as closed
            context->state = TLS_STATE_CLOSED;
            break;
         //TLS connection closed?
         case TLS_STATE_CLOSED:
            //Debug message
            TRACE_WARNING("TLS handshake failure!\r\n");
            //Report an error
            error = ERROR_HANDSHAKE_FAILED;
            break;
         //Invalid state?
         default:
            //Report an error
            error = ERROR_UNEXPECTED_STATE;
            break;
         }
      }

      //Abort TLS handshake if an error was encountered
   } while(!error);

   //Successful TLS handshake?
   if(!error)
   {
      //Save current session in the session cache for further reuse
      tlsSaveToCache(context);
   }
   else
   {
      //Send an alert message to the client, if applicable
      tlsProcessError(context, error);
   }

   //Return status code
   return error;
}


/**
 * @brief Parse incoming handshake message
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsParseClientMessage(TlsContext *context)
{
   error_t error;
   size_t length;
   void *message;
   TlsContentType contentType;

   //A message can be fragmented across several records...
   error = tlsReadProtocolData(context, &message, &length, &contentType);

   //Check status code
   if(!error)
   {
      //Handshake message received?
      if(contentType == TLS_TYPE_HANDSHAKE)
      {
         //Check handshake message type
         switch(((TlsHandshake *) message)->msgType)
         {
         //ClientHello message received?
         case TLS_TYPE_CLIENT_HELLO:
            //When a client first connects to a server, it is required to send
            //the ClientHello as its first message
            error = tlsParseClientHello(context, message, length);
            break;
         //Certificate message received?
         case TLS_TYPE_CERTIFICATE:
            //This is the first message the client can send after receiving a
            //ServerHelloDone message. This message is only sent if the server
            //requests a certificate
            error = tlsParseCertificate(context, message, length);
            break;
         //ClientKeyExchange message received?
         case TLS_TYPE_CLIENT_KEY_EXCHANGE:
            //This message is always sent by the client. It must immediately
            //follow the client certificate message, if it is sent. Otherwise,
            //it must be the first message sent by the client after it receives
            //the ServerHelloDone message
            error = tlsParseClientKeyExchange(context, message, length);
            break;
         //CertificateVerify message received?
         case TLS_TYPE_CERTIFICATE_VERIFY:
            //This message is used to provide explicit verification of a client
            //certificate. This message is only sent following a client certificate
            //that has signing capability. When sent, it must immediately follow
            //the clientKeyExchange message
            error = tlsParseCertificateVerify(context, message, length);
            break;
         //Finished message received?
         case TLS_TYPE_FINISHED:
            //A Finished message is always sent immediately after a changeCipherSpec
            //message to verify that the key exchange and authentication processes
            //were successful
            error = tlsParseFinished(context, message, length);
            break;
         //Invalid handshake message received?
         default:
            //Report an error
            error = ERROR_UNEXPECTED_MESSAGE;
            break;
         }
      }
      //ChangeCipherSpec message received?
      else if(contentType == TLS_TYPE_CHANGE_CIPHER_SPEC)
      {
         //The ChangeCipherSpec message is sent by the client and to notify the
         //server that subsequent records will be protected under the newly
         //negotiated CipherSpec and keys
         error = tlsParseChangeCipherSpec(context, message, length);
      }
      //Alert message received?
      else if(contentType == TLS_TYPE_ALERT)
      {
         //Parse Alert message
         error = tlsParseAlert(context, message, length);
      }
      //Application data received?
      else
      {
         //The client cannot transmit application data
         //before the handshake is completed
         error = ERROR_UNEXPECTED_MESSAGE;
      }

      //Advance data pointer
      context->rxBufferPos += length;
      //Number of bytes still pending in the receive buffer
      context->rxBufferLen -= length;
   }

   //Return status code
   return error;
}


/**
 * @brief Send ServerHello message
 *
 * The server will send this message in response to a ClientHello
 * message when it was able to find an acceptable set of algorithms.
 * If it cannot find such a match, it will respond with a handshake
 * failure alert
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendServerHello(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsServerHello *message;

   //Point to the buffer where to format the message
   message = (TlsServerHello *) context->txBuffer;

   //Generate the server random value using a cryptographically-safe
   //pseudorandom number generator
   error = tlsGenerateRandomValue(context, &context->serverRandom);

   //Check status code
   if(!error)
   {
      //Format ServerHello message
      error = tlsFormatServerHello(context, message, &length);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending ServerHello message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsWriteProtocolData(context, message, length, TLS_TYPE_HANDSHAKE);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
#if (TLS_SESSION_RESUME_SUPPORT == ENABLED)
      //Use abbreviated handshake?
      if(context->resume)
      {
         //Derive session keys from the master secret
         error = tlsGenerateKeys(context);

         //Key material successfully generated?
         if(!error)
         {
            //At this point, both client and server must send ChangeCipherSpec
            //messages and proceed directly to Finished messages
            context->state = TLS_STATE_SERVER_CHANGE_CIPHER_SPEC;
         }
      }
      else
#endif
      {
         //Perform a full handshake
         context->state = TLS_STATE_SERVER_CERTIFICATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send ServerKeyExchange message
 *
 * The ServerKeyExchange message is sent by the server only when the
 * server Certificate message does not contain enough data to allow
 * the client to exchange a premaster secret
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendServerKeyExchange(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsServerKeyExchange *message;

   //Initialize status code
   error = NO_ERROR;

   //Point to the buffer where to format the message
   message = (TlsServerKeyExchange *) context->txBuffer;
   //Initialize length
   length = 0;

   //The ServerKeyExchange message is sent by the server only when the server
   //Certificate message (if sent) does not contain enough data to allow the
   //client to exchange a premaster secret
   if(context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //Format ServerKeyExchange message
      error = tlsFormatServerKeyExchange(context, message, &length);
   }
   else if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
   {
#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
      //If no PSK identity hint is provided by the server, the
      //ServerKeyExchange message is omitted...
      if(context->pskIdentityHint != NULL)
      {
         //Format ServerKeyExchange message
         error = tlsFormatServerKeyExchange(context, message, &length);
      }
#endif
   }

   //Check status code
   if(!error)
   {
      //Any message to send?
      if(length > 0)
      {
         //Debug message
         TRACE_INFO("Sending ServerKeyExchange message (%" PRIuSIZE " bytes)...\r\n", length);
         TRACE_DEBUG_ARRAY("  ", message, length);

         //Send handshake message
         error = tlsWriteProtocolData(context, message, length, TLS_TYPE_HANDSHAKE);
      }
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Prepare to send a CertificateRequest message...
      context->state = TLS_STATE_CERTIFICATE_REQUEST;
   }

   //Return status code
   return error;
}


/**
 * @brief Send CertificateRequest message
 *
 * A server can optionally request a certificate from the client, if
 * appropriate for the selected cipher suite. This message will
 * immediately follow the ServerKeyExchange message
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendCertificateRequest(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsCertificateRequest *message;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_DSA_SIGN_SUPPORT == ENABLED || TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   //A server can optionally request a certificate from the client
   if(context->clientAuthMode != TLS_CLIENT_AUTH_NONE)
   {
      //Non-anonymous key exchange?
      if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
         context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
      {
         //Point to the buffer where to format the message
         message = (TlsCertificateRequest *) context->txBuffer;

         //Format CertificateRequest message
         error = tlsFormatCertificateRequest(context, message, &length);

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_INFO("Sending CertificateRequest message (%" PRIuSIZE " bytes)...\r\n", length);
            TRACE_DEBUG_ARRAY("  ", message, length);

            //Send handshake message
            error = tlsWriteProtocolData(context, message, length, TLS_TYPE_HANDSHAKE);
         }
      }
   }
#endif

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Prepare to send a ServerHelloDone message...
      context->state = TLS_STATE_SERVER_HELLO_DONE;
   }

   //Return status code
   return error;
}


/**
 * @brief Send ServerHelloDone message
 *
 * The ServerHelloDone message is sent by the server to indicate the
 * end of the ServerHello and associated messages. After sending this
 * message, the server will wait for a client response
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendServerHelloDone(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsServerHelloDone *message;

   //Point to the buffer where to format the message
   message = (TlsServerHelloDone *) context->txBuffer;

   //Format ServerHelloDone message
   error = tlsFormatServerHelloDone(context, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending ServerHelloDone message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsWriteProtocolData(context, message, length, TLS_TYPE_HANDSHAKE);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //The client must send a Certificate message if the server requests it
      if(context->clientAuthMode != TLS_CLIENT_AUTH_NONE)
         context->state = TLS_STATE_CLIENT_CERTIFICATE;
      else
         context->state = TLS_STATE_CLIENT_KEY_EXCHANGE;
   }

   //Return status code
   return error;
}


/**
 * @brief Format ServerHello message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the ServerHello message
 * @param[out] length Length of the resulting ServerHello message
 * @return Error code
 **/

error_t tlsFormatServerHello(TlsContext *context,
   TlsServerHello *message, size_t *length)
{
   uint8_t *p;
   TlsExtensions *extensionList;

   //Handshake message type
   message->msgType = TLS_TYPE_SERVER_HELLO;

   //This field contains the lower of the version suggested by the client
   //in the ClientHello and the highest supported by the server
   message->serverVersion = htons(context->version);

   //Server random value
   message->random = context->serverRandom;

   //Point to the session ID
   p = message->sessionId;
   //Total length of the message
   *length = sizeof(TlsServerHello);

#if (TLS_SESSION_RESUME_SUPPORT == ENABLED)
   //The SessionID uniquely identifies the current session
   message->sessionIdLength = (uint8_t)context->sessionIdLen;
   memcpy(message->sessionId, context->sessionId, context->sessionIdLen);
#else
   //The server may return an empty session ID to indicate that the session
   //will not be cached and therefore cannot be resumed
   message->sessionIdLength = 0;
#endif

   //Debug message
   TRACE_INFO("Session ID (%" PRIu8 " bytes):\r\n", message->sessionIdLength);
   TRACE_INFO_ARRAY("  ", message->sessionId, message->sessionIdLength);

   //Advance data pointer
   p += message->sessionIdLength;
   //Adjust the length of the message
   *length += message->sessionIdLength;

   //The single cipher suite selected by the server
   STORE16BE(context->cipherSuite, p);
   //Advance data pointer
   p += sizeof(TlsCipherSuite);
   //Adjust the length of the message
   *length += sizeof(TlsCipherSuite);

   //The single compression algorithm selected by the server
   *p = context->compressionMethod;
   //Advance data pointer
   p += sizeof(TlsCompressionMethod);
   //Adjust the length of the message
   *length += sizeof(TlsCompressionMethod);

   //Only extensions offered by the client can appear in the server's list
   extensionList = (TlsExtensions *) p;
   //Total length of the extension list
   extensionList->length = 0;

   //Point to the first extension of the list
   p += sizeof(TlsExtensions);

#if (TLS_ECDH_ANON_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //A server that selects an ECC cipher suite in response to a ClientHello
   //message including an EcPointFormats extension appends this extension
   //to its ServerHello message
   if(tlsIsEccCipherSuite(context->cipherSuite) && context->ecPointFormatExtFound)
   {
      uint_t n;
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
      ecPointFormatList->length = n;

      //Consider the 2-byte length field that precedes the list
      n += sizeof(TlsEcPointFormatList);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the EcPointFormats extension
      n += sizeof(TlsExtension);
      //Fix the length of the extension list
      extensionList->length += n;

      //Point to the next field
      p += n;
      //Total length of the message
      *length += n;
   }
#endif

   //Check whether the extension list is empty
   if(extensionList->length > 0)
   {
      //Convert the length of the extension list to network byte order
      extensionList->length = htons(extensionList->length);
      //Total length of the message
      *length += sizeof(TlsExtensions);
   }

   //Fix the length field
   STORE24BE(*length - sizeof(TlsHandshake), message->length);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format ServerKeyExchange message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the ServerKeyExchange message
 * @param[out] length Length of the resulting ServerKeyExchange message
 * @return Error code
 **/

error_t tlsFormatServerKeyExchange(TlsContext *context,
   TlsServerKeyExchange *message, size_t *length)
{
   error_t error;
   size_t n;
   size_t paramsLen;
   uint8_t *p;
   uint8_t *params;

   //Handshake message type
   message->msgType = TLS_TYPE_SERVER_KEY_EXCHANGE;

   //Point to the body of the handshake message
   p = message->data;
   //Length of the handshake message
   *length = 0;

   //PSK key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //To help the client in selecting which identity to use, the server
      //can provide a PSK identity hint in the ServerKeyExchange message
      error = tlsFormatPskIdentityHint(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += n;
      //Adjust the length of the message
      *length += n;
   }

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

      //Format server's key exchange parameters
      error = tlsFormatServerKeyParams(context, p, &paramsLen);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += paramsLen;
      //Adjust the length of the message
      *length += paramsLen;
   }

   //For non-anonymous Diffie-Hellman and ECDH key exchanges, a signature
   //over the server's key exchange parameters shall be generated
   if(context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
   {
      //Sign server's key exchange parameters
      error = tlsGenerateServerKeySignature(context, p, params, paramsLen, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += n;
      //Adjust the length of the message
      *length += n;
   }

   //Fix the length field
   STORE24BE(*length, message->length);
   //Length of the complete handshake message
   *length += sizeof(TlsHandshake);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format CertificateRequest message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the CertificateRequest message
 * @param[out] length Length of the resulting CertificateRequest message
 * @return Error code
 **/

error_t tlsFormatCertificateRequest(TlsContext *context,
   TlsCertificateRequest *message, size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *p;
   const char_t *pemCert;
   size_t pemCertLength;
   uint8_t *derCert;
   size_t derCertSize;
   size_t derCertLength;
   X509CertificateInfo *certInfo;
   TlsCertAuthorities *certAuthorities;

   //Initialize status code
   error = NO_ERROR;

   //Handshake message type
   message->msgType = TLS_TYPE_CERTIFICATE_REQUEST;

   //Enumerate the types of certificate types that the client may offer
   n = 0;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
   //Accept certificates that contain a RSA public key
   message->certificateTypes[n++] = TLS_CERT_RSA_SIGN;
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
   //Accept certificates that contain a DSA public key
   message->certificateTypes[n++] = TLS_CERT_DSS_SIGN;
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   //Accept certificates that contain an ECDSA public key
   message->certificateTypes[n++] = TLS_CERT_ECDSA_SIGN;
#endif

   //Set the length of the list
   message->certificateTypesLength = (uint8_t) n;
   //Total length of the message
   *length = sizeof(TlsCertificateRequest) + n;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Check whether TLS 1.2 is currently used
   if(context->version == TLS_VERSION_1_2)
   {
      TlsSignHashAlgos *supportedSignAlgos;

      //Point to the list of the hash/signature algorithm pairs that
      //the server is able to verify
      supportedSignAlgos = PTR_OFFSET(message, *length);

      //Enumerate the hash/signature algorithm pairs in descending
      //order of preference
      n = 0;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
      //SHA-1 with RSA is always supported
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;

      //The hash algorithm used for PRF operations can also be used for signing
      if(context->prfHashAlgo == SHA256_HASH_ALGO)
      {
         //SHA-256 with RSA is supported
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
      }
#if (TLS_SHA384_SUPPORT == ENABLED)
      else if(context->prfHashAlgo == SHA384_HASH_ALGO)
      {
         //SHA-384 with RSA is supported
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA384;
      }
#endif
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
      //DSA with SHA-1 is always supported
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_DSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;

      //The hash algorithm used for PRF operations can also be used for signing
      if(context->prfHashAlgo == SHA256_HASH_ALGO)
      {
         //DSA with SHA-256 is supported
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_DSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
      }
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
      //ECDSA with SHA-1 is always supported
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;

      //The hash algorithm used for PRF operations can also be used for signing
      if(context->prfHashAlgo == SHA256_HASH_ALGO)
      {
         //ECDSA with SHA-256 is supported
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
      }
#if (TLS_SHA384_SUPPORT == ENABLED)
      else if(context->prfHashAlgo == SHA384_HASH_ALGO)
      {
         //ECDSA with SHA-384 is supported
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA384;
      }
#endif
#endif
      //Fix the length of the list
      supportedSignAlgos->length = htons(n * sizeof(TlsSignHashAlgo));
      //Total length of the message
      *length += sizeof(TlsSignHashAlgos) + n * sizeof(TlsSignHashAlgo);
   }
#endif

   //Point to the list of the distinguished names of acceptable
   //certificate authorities
   certAuthorities = PTR_OFFSET(message, *length);
   //Total length of the message
   *length += sizeof(TlsCertAuthorities);

   //Point to the first certificate authority
   p = certAuthorities->value;
   //Length of the list in bytes
   n = 0;

   //Point to the first trusted CA certificate
   pemCert = context->trustedCaList;
   //Get the total length, in bytes, of the trusted CA list
   pemCertLength = context->trustedCaListLen;

   //DER encoded certificate
   derCert = NULL;
   derCertSize = 0;
   derCertLength = 0;

   //Allocate a memory buffer to store X.509 certificate info
   certInfo = tlsAllocMem(sizeof(X509CertificateInfo));

   //Successful memory allocation?
   if(certInfo != NULL)
   {
      //Loop through the list of trusted CA certificates
      while(pemCertLength > 0)
      {
         //Decode PEM certificate
         error = pemReadCertificate(&pemCert, &pemCertLength,
            &derCert, &derCertSize, &derCertLength);

         //Any error to report?
         if(error)
         {
            //End of file detected
            error = NO_ERROR;
            break;
         }

         //Parse X.509 certificate
         error = x509ParseCertificate(derCert, derCertLength, certInfo);
         //Failed to parse the X.509 certificate?
         if(error)
            break;

         //Total length of the message
         *length += certInfo->subject.rawDataLen + 2;

         //Prevent the buffer from overflowing
         if(*length > context->txRecordMaxLen)
         {
            //Report an error
            error = ERROR_MESSAGE_TOO_LONG;
            break;
         }

         //Each distinguished name is preceded by a 2-byte length field
         STORE16BE(certInfo->subject.rawDataLen, p);
         //The distinguished name shall be DER encoded
         memcpy(p + 2, certInfo->subject.rawData, certInfo->subject.rawDataLen);

         //Advance data pointer
         p += certInfo->subject.rawDataLen + 2;
         //Adjust the length of the list
         n += certInfo->subject.rawDataLen + 2;
      }

      //Free previously allocated memory
      tlsFreeMem(derCert);
      tlsFreeMem(certInfo);

      //Fix the length of the list
      certAuthorities->length = htons(n);

      //Fix the length field
      STORE24BE(*length - sizeof(TlsHandshake), message->length);
   }
   else
   {
      //Report an error
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
}


/**
 * @brief Format ServerHelloDone message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the ServerHelloDone message
 * @param[out] length Length of the resulting ServerHelloDone message
 * @return Error code
 **/

error_t tlsFormatServerHelloDone(TlsContext *context,
   TlsServerHelloDone *message, size_t *length)
{
   //Handshake message type
   message->msgType = TLS_TYPE_SERVER_HELLO_DONE;

   //The ServerHelloDone message does not contain any data
   STORE24BE(0, message->length);

   //Length of the complete handshake message
   *length = sizeof(TlsHandshake);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ClientHello message
 *
 * When a client first connects to a server, it is required to send
 * the ClientHello as its first message. The client can also send a
 * ClientHello in response to a HelloRequest or on its own initiative
 * in order to renegotiate the security parameters in an existing
 * connection
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming ClientHello message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseClientHello(TlsContext *context, const TlsClientHello *message, size_t length)
{
   error_t error;
   size_t i;
   size_t j;
   size_t k;
   size_t n;
   bool_t acceptable;
   uint8_t certType;
   const uint8_t *p;
   const TlsCipherSuites *cipherSuites;
   const TlsCompressionMethods *compressionMethods;
   const TlsExtension *extension;
   const TlsSignHashAlgos *supportedSignAlgos;
   const TlsEllipticCurveList *curveList;

   //Debug message
   TRACE_INFO("ClientHello message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check the length of the ClientHello message
   if(length < sizeof(TlsClientHello))
      return ERROR_DECODING_FAILED;

   //Check current state
   if(context->state != TLS_STATE_CLIENT_HELLO)
      return ERROR_UNEXPECTED_MESSAGE;

   //Point to the session ID
   p = (uint8_t *) message + sizeof(TlsClientHello);
   //Remaining bytes to process
   n = length - sizeof(TlsClientHello);

   //Check the length of the session ID
   if(message->sessionIdLength > n)
      return ERROR_DECODING_FAILED;
   if(message->sessionIdLength > 32)
      return ERROR_ILLEGAL_PARAMETER;

   //Debug message
   TRACE_INFO("Session ID (%" PRIu8 " bytes):\r\n", message->sessionIdLength);
   TRACE_INFO_ARRAY("  ", message->sessionId, message->sessionIdLength);

   //Point to the next field
   p += message->sessionIdLength;
   //Remaining bytes to process
   n -= message->sessionIdLength;

   //Malformed ClientHello message?
   if(n < sizeof(TlsCipherSuites))
      return ERROR_DECODING_FAILED;

   //List of cryptographic algorithms supported by the client
   cipherSuites = (TlsCipherSuites *) p;
   //Remaining bytes to process
   n -= sizeof(TlsCipherSuites);

   //Check the length of the list
   if(ntohs(cipherSuites->length) < 2)
      return ERROR_ILLEGAL_PARAMETER;
   if(ntohs(cipherSuites->length) > n)
      return ERROR_DECODING_FAILED;

   //Get the number of cipher suite identifiers present in the list
   k = ntohs(cipherSuites->length) / 2;

   //Debug message
   TRACE_DEBUG("Cipher suites:\r\n");

   //Dump the list of cipher suites
   for(i = 0; i < k; i++)
   {
      //Debug message
      TRACE_DEBUG("  0x%04" PRIX16 " (%s)\r\n", ntohs(cipherSuites->value[i]),
         tlsGetCipherSuiteName(ntohs(cipherSuites->value[i])));
   }

   //Point to the next field
   p += sizeof(TlsCipherSuites) + ntohs(cipherSuites->length);
   //Remaining bytes to process
   n -= ntohs(cipherSuites->length);

   //Malformed ClientHello message?
   if(n < sizeof(TlsCompressionMethods))
      return ERROR_DECODING_FAILED;

   //List of compression algorithms supported by the client
   compressionMethods = (TlsCompressionMethods *) p;
   //Remaining bytes to process
   n -= sizeof(TlsCompressionMethods);

   //Check the length of the list
   if(compressionMethods->length < 1)
      return ERROR_ILLEGAL_PARAMETER;
   if(compressionMethods->length > n)
      return ERROR_DECODING_FAILED;

   //Point to the next field
   p += sizeof(TlsCompressionMethods) + compressionMethods->length;
   //Remaining bytes to process
   n -= compressionMethods->length;

   //Parse the list of extensions offered by the client
   extension = tlsGetExtension(p, n, TLS_EXT_ELLIPTIC_CURVES);

   //The EllipticCurves extension was found?
   if(extension)
   {
      //This extension allows a client to enumerate the elliptic curves it supports
      curveList = (TlsEllipticCurveList *) extension->value;

      //Check the length of the list
      if(ntohs(extension->length) < sizeof(TlsEllipticCurveList))
         return ERROR_DECODING_FAILED;
      if(ntohs(extension->length) < (sizeof(TlsEllipticCurveList) + ntohs(curveList->length)))
         return ERROR_DECODING_FAILED;
   }
   else
   {
      //The client may omit the SignatureAlgorithms extension
      curveList = NULL;
   }

   //Parse the list of extensions offered by the client
   extension = tlsGetExtension(p, n, TLS_EXT_EC_POINT_FORMATS);

   //The EcPointFormats extension was found?
   if(extension)
      context->ecPointFormatExtFound = TRUE;
   else
      context->ecPointFormatExtFound = FALSE;

   //Parse the list of extensions offered by the client
   extension = tlsGetExtension(p, n, TLS_EXT_SIGNATURE_ALGORITHMS);

   //The SignatureAlgorithms extension was found?
   if(extension)
   {
      //Point to the list of supported hash/signature algorithm pairs
      supportedSignAlgos = (TlsSignHashAlgos *) extension->value;

      //Check the length of the list
      if(ntohs(extension->length) < sizeof(TlsSignHashAlgos))
         return ERROR_DECODING_FAILED;
      if(ntohs(extension->length) < (sizeof(TlsSignHashAlgos) + ntohs(supportedSignAlgos->length)))
         return ERROR_DECODING_FAILED;
   }
   else
   {
      //The client may omit the SignatureAlgorithms extension
      supportedSignAlgos = NULL;
   }

   //Get the version the client wishes to use during this session
   context->clientVersion = ntohs(message->clientVersion);

   //If a TLS server receives a ClientHello containing a version number
   //greater than the highest version supported by the server, it must
   //reply according to the highest version supported by the server
   error = tlsSetVersion(context, MIN(context->clientVersion, TLS_MAX_VERSION));
   //The specified TLS version is not supported?
   if(error)
      return error;

   //Save client random value
   context->clientRandom = message->random;

#if (TLS_SESSION_RESUME_SUPPORT == ENABLED)
   //Check whether session caching is supported
   if(context->cache != NULL)
   {
      //If the session ID was non-empty, the server will look in
      //its session cache for a match
      TlsSession *session = tlsFindCache(context->cache,
         message->sessionId, message->sessionIdLength);

      //Check whether a matching entry has been found in the cache
      if(session != NULL)
      {
         //Restore session parameters
         tlsRestoreSession(context, session);

         //Select the relevant cipher suite
         error = tlsSetCipherSuite(context, session->cipherSuite);
         //Any error to report?
         if(error)
            return error;

         //Perform abbreviated handshake
         context->resume = TRUE;
      }
      else
      {
         //Generate a new random ID
         error = context->prngAlgo->read(context->prngContext, context->sessionId, 32);
         //Any error to report?
         if(error)
            return error;

         //Session ID is limited to 32 bytes
         context->sessionIdLen = 32;
         //Perform a full handshake
         context->resume = FALSE;
      }
   }
   else
#endif
   {
      //This session cannot be resumed
      context->sessionIdLen = 0;
      //Perform a full handshake
      context->resume = FALSE;
   }

   //Full handshake?
   if(!context->resume)
   {
      //Get the size of the cipher suite list
      k = ntohs(cipherSuites->length) / 2;

      //The cipher suite list contains the combinations of cryptographic algorithms
      //supported by the client in order of the client's preference
      for(i = 0; i < k; i++)
      {
         //Check whether the current cipher suite is supported
         error = tlsSetCipherSuite(context, ntohs(cipherSuites->value[i]));

         //Successful processing?
         if(!error)
         {
            //ECC cipher suite?
            if(context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
               context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
               context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
               context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
            {
               //One of the proposed ECC cipher suites must be negotiated only
               //if the server can successfully complete the handshake while
               //using the curves and point formats supported by the client
               error = tlsSelectNamedCurve(context, curveList);
            }
         }

         //Successful processing?
         if(!error)
         {
            //The server requires a valid certificate whenever the agreed-upon
            //key exchange method uses certificates for authentication
            if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
               context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
               context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
               context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
            {
               //RSA, DHE_RSA, ECDHE_RSA and RAS_PSK key exchange methods
               //require a RSA certificate
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
               //DH_anon and ECDH_anon key exchange methods do not require any certificate
               certType = TLS_CERT_NONE;
            }

            //Check whether a certificate is required
            if(certType != TLS_CERT_NONE)
            {
               //Do not accept the specified cipher suite unless a suitable
               //certificate has been previously loaded by the user
               error = ERROR_NO_CERTIFICATE;

               //Loop through the list of available certificates
               for(j = 0; j < context->numCerts; j++)
               {
                  //Check whether the current certificate is acceptable
                  acceptable = tlsIsCertificateAcceptable(&context->certs[j],
                     &certType, 1, supportedSignAlgos, curveList, NULL);

                  //Is the certificate suitable for the selected cipher suite?
                  if(acceptable)
                  {
                     //The hash algorithm to be used when generating signatures must be
                     //one of those present in the SignatureAlgorithms extension
                     error = tlsSelectSignHashAlgo(context,
                        context->certs[j].signAlgo, supportedSignAlgos);

                     //If all the requirements were met, the certificate can be
                     //used in conjunction with the selected cipher suite
                     if(!error)
                     {
                        context->cert = &context->certs[j];
                        break;
                     }
                  }
               }
            }
         }

         //If the list contains cipher suites the server does not recognize,
         //support, or wish to use, the server must ignore those cipher
         //suites, and process the remaining ones as usual
         if(!error)
            break;
      }

      //If no acceptable choices are presented, return a handshake failure
      //alert and close the connection
      if(error)
         return ERROR_HANDSHAKE_FAILED;

      //The list of the compression methods supported by the client
      //is sorted by client preference
      for(i = 0; i < compressionMethods->length; i++)
      {
         //Check whether the algorithm to be used for data compression is supported
         error = tlsSetCompressionMethod(context, compressionMethods->value[i]);

         //If the compression method is not supported, process the remaining ones
         if(!error)
            break;
      }

      //If no compression algorithm is acceptable, return a handshake failure
      //alert and close the connection
      if(error)
         return ERROR_HANDSHAKE_FAILED;
   }

   //Initialize handshake message hashing
   error = tlsInitHandshakeHash(context);
   //Any error to report?
   if(error)
      return error;

   //Update the hash value with the incoming handshake message
   tlsUpdateHandshakeHash(context, message, length);

   //Prepare to send ServerHello message...
   context->state = TLS_STATE_SERVER_HELLO;
   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ClientKeyExchange message
 *
 * This message is always sent by the client. It must immediately
 * follow the client Certificate message, if it is sent. Otherwise,
 * it must be the first message sent by the client after it receives
 * the ServerHelloDone message
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming ClientKeyExchange message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseClientKeyExchange(TlsContext *context, const TlsClientKeyExchange *message, size_t length)
{
   error_t error;
   size_t n;
   const uint8_t *p;

   //Debug message
   TRACE_INFO("ClientKeyExchange message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check the length of the ClientKeyExchange message
   if(length < sizeof(TlsClientKeyExchange))
      return ERROR_DECODING_FAILED;

   //Check current state
   if(context->state == TLS_STATE_CLIENT_CERTIFICATE)
   {
      //A an non-anonymous server can optionally request a certificate from the client
      if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
         context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
      {
         //If client authentication is required by the server for the handshake
         //to continue, it may respond with a fatal handshake failure alert
         if(context->clientAuthMode == TLS_CLIENT_AUTH_REQUIRED)
            return ERROR_HANDSHAKE_FAILED;
      }
   }
   else if(context->state != TLS_STATE_CLIENT_KEY_EXCHANGE)
   {
      //Send a fatal alert to the client
      return ERROR_UNEXPECTED_MESSAGE;
   }

   //Update the hash value with the incoming handshake message
   tlsUpdateHandshakeHash(context, message, length);

   //Point to the body of the handshake message
   p = message->data;
   //Remaining bytes to process
   length -= sizeof(TlsClientKeyExchange);

   //PSK key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //The PSK identity is sent in cleartext
      error = tlsParsePskIdentity(context, p, length, &n);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += n;
      //Remaining bytes to process
      length -= n;
   }

   //RSA, Diffie-Hellman or ECDH key exchange method?
   if(context->keyExchMethod != TLS_KEY_EXCH_PSK)
   {
      //Parse client's key exchange parameters
      error = tlsParseClientKeyParams(context, p, length, &n);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += n;
      //Remaining bytes to process
      length -= n;
   }

   //If the amount of data in the message does not precisely match the format
   //of the ClientKeyExchange message, then send a fatal alert
   if(length != 0)
      return ERROR_DECODING_FAILED;

   //PSK key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //Generate premaster secret
      error = tlsGeneratePskPremasterSecret(context);
      //Any error to report?
      if(error)
         return error;
   }

   //Derive session keys from the premaster secret
   error = tlsGenerateKeys(context);
   //Unable to generate key material?
   if(error)
      return error;

   //Update FSM state
   if(context->peerCertType != TLS_CERT_NONE)
      context->state = TLS_STATE_CERTIFICATE_VERIFY;
   else
      context->state = TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse CertificateVerify message
 *
 * The CertificateVerify message is used to provide explicit verification
 * of a client certificate. This message is only sent following a client
 * certificate that has signing capability
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming CertificateVerify message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseCertificateVerify(TlsContext *context, const TlsCertificateVerify *message, size_t length)
{
   error_t error;
   size_t n;

   //Debug message
   TRACE_INFO("CertificateVerify message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check the length of the CertificateVerify message
   if(length < sizeof(TlsCertificateVerify))
      return ERROR_DECODING_FAILED;

   //Check current state
   if(context->state != TLS_STATE_CERTIFICATE_VERIFY)
      return ERROR_UNEXPECTED_MESSAGE;

   //Remaining bytes to process
   n = length - sizeof(TlsCertificateVerify);

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //SSL 3.0, TLS 1.0 or TLS 1.1 currently selected?
   if(context->version <= TLS_VERSION_1_1)
   {
      //Point to the digitally-signed element
      TlsDigitalSignature *signature = (TlsDigitalSignature *) message->signature;

      //Check the length of the digitally-signed element
      if(n < sizeof(TlsDigitalSignature))
         return ERROR_DECODING_FAILED;
      if(n < (sizeof(TlsDigitalSignature) + ntohs(signature->length)))
         return ERROR_DECODING_FAILED;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
      //The client's certificate contains a valid RSA public key?
      if(context->peerCertType == TLS_CERT_RSA_SIGN)
      {
         //Digest all the handshake messages starting at ClientHello (using MD5)
         error = tlsFinalizeHandshakeHash(context, MD5_HASH_ALGO,
            context->handshakeMd5Context, "", context->verifyData);
         //Any error to report?
         if(error)
            return error;

         //Digest all the handshake messages starting at ClientHello (using SHA-1)
         error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
            context->handshakeSha1Context, "", context->verifyData + MD5_DIGEST_SIZE);
         //Any error to report?
         if(error)
            return error;

         //Verify RSA signature using client's public key
         error = tlsVerifyRsaSignature(&context->peerRsaPublicKey,
            context->verifyData, signature->value, ntohs(signature->length));
      }
      else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
      //The client's certificate contains a valid DSA public key?
      if(context->peerCertType == TLS_CERT_DSS_SIGN)
      {
         //Digest all the handshake messages starting at ClientHello
         error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
            context->handshakeSha1Context, "", context->verifyData);
         //Any error to report?
         if(error)
            return error;

         //Verify DSA signature using client's public key
         error = tlsVerifyDsaSignature(&context->peerDsaPublicKey, context->verifyData,
            SHA1_DIGEST_SIZE, signature->value, ntohs(signature->length));
      }
      else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
      //The client's certificate contains a valid ECDSA public key?
      if(context->peerCertType == TLS_CERT_ECDSA_SIGN)
      {
         //Digest all the handshake messages starting at ClientHello
         error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
            context->handshakeSha1Context, "", context->verifyData);
         //Any error to report?
         if(error)
            return error;

         //Verify ECDSA signature using client's public key
         error = tlsVerifyEcdsaSignature(&context->peerEcParams, &context->peerEcPublicKey,
            context->verifyData, SHA1_DIGEST_SIZE, signature->value, ntohs(signature->length));
      }
      else
#endif
      //Invalid signature algorithm?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      const HashAlgo *hashAlgo;

      //Point to the digitally-signed element
      TlsDigitalSignature2 *signature = (TlsDigitalSignature2 *) message->signature;

      //Check the length of the digitally-signed element
      if(n < sizeof(TlsDigitalSignature2))
         return ERROR_DECODING_FAILED;
      if(n < (sizeof(TlsDigitalSignature2) + ntohs(signature->length)))
         return ERROR_DECODING_FAILED;

      //Retrieve the hash algorithm used for signing
      hashAlgo = tlsGetHashAlgo(signature->algorithm.hash);

      //Digest all the handshake messages starting at ClientHello
      if(hashAlgo == SHA1_HASH_ALGO)
      {
         //Use SHA-1 hash algorithm
         error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
            context->handshakeSha1Context, "", context->verifyData);
      }
      else if(hashAlgo == context->prfHashAlgo)
      {
         //Use PRF hash algorithm (SHA-256 or SHA-384)
         error = tlsFinalizeHandshakeHash(context, hashAlgo,
            context->handshakeHashContext, "", context->verifyData);
      }
      else
      {
         //The specified hash algorithm is not supported
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }

      //Any error to report?
      if(error)
         return error;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
      //The client's certificate contains a valid RSA public key?
      if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA)
      {
         //Use the signature verification algorithm defined in PKCS #1 v1.5
         error = rsassaPkcs1v15Verify(&context->peerRsaPublicKey, hashAlgo,
            context->verifyData, signature->value, ntohs(signature->length));
      }
      else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
      //The client's certificate contains a valid DSA public key?
      if(signature->algorithm.signature == TLS_SIGN_ALGO_DSA)
      {
         //Verify DSA signature using client's public key
         error = tlsVerifyDsaSignature(&context->peerDsaPublicKey, context->verifyData,
            hashAlgo->digestSize, signature->value, ntohs(signature->length));
      }
      else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
      //The client's certificate contains a valid ECDSA public key?
      if(signature->algorithm.signature == TLS_SIGN_ALGO_ECDSA)
      {
         //Verify ECDSA signature using client's public key
         error = tlsVerifyEcdsaSignature(&context->peerEcParams, &context->peerEcPublicKey,
            context->verifyData, hashAlgo->digestSize, signature->value, ntohs(signature->length));
      }
      else
#endif
      //Invalid signature algorithm?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }
   else
#endif
   {
      //The negotiated TLS version is not valid
      error = ERROR_INVALID_VERSION;
   }

   //Update the hash value with the incoming handshake message
   tlsUpdateHandshakeHash(context, message, length);

   //Prepare to receive a ChangeCipherSpec message...
   context->state = TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC;
   //Return status code
   return error;
}

#endif
