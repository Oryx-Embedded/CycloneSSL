/**
 * @file tls_client.c
 * @brief Handshake message processing (TLS client)
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
#include "tls_client.h"
#include "tls_client_misc.h"
#include "tls_common.h"
#include "tls_record.h"
#include "tls_misc.h"
#include "pem.h"
#include "date_time.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED && TLS_CLIENT_SUPPORT == ENABLED)


/**
 * @brief TLS client handshake
 *
 * TLS handshake protocol is responsible for the authentication
 * and key exchange necessary to establish a secure session
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsClientHandshake(TlsContext *context)
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
            //At this is point, the handshake is complete and the client
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
         //Sending ClientHello message?
         case TLS_STATE_CLIENT_HELLO:
            //When a client first connects to a server, it is required to send
            //the ClientHello as its first message
            error = tlsSendClientHello(context);
            break;
         //Sending Certificate message?
         case TLS_STATE_CLIENT_CERTIFICATE:
            //This is the first message the client can send after receiving a
            //ServerHelloDone message. This message is only sent if the server
            //requests a certificate
            error = tlsSendCertificate(context);
            break;
         //Sending ClientKeyExchange message?
         case TLS_STATE_CLIENT_KEY_EXCHANGE:
            //This message is always sent by the client. It must immediately
            //follow the client certificate message, if it is sent. Otherwise,
            //it must be the first message sent by the client after it receives
            //the ServerHelloDone message
            error = tlsSendClientKeyExchange(context);
            break;
         //Sending CertificateVerify message?
         case TLS_STATE_CERTIFICATE_VERIFY:
            //This message is used to provide explicit verification of a client
            //certificate. This message is only sent following a client certificate
            //that has signing capability. When sent, it must immediately follow
            //the clientKeyExchange message
            error = tlsSendCertificateVerify(context);
            break;
         //Sending ChangeCipherSpec message?
         case TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC:
            //The ChangeCipherSpec message is sent by the client and to notify the
            //server that subsequent records will be protected under the newly
            //negotiated CipherSpec and keys
            error = tlsSendChangeCipherSpec(context);
            break;
         //Sending Finished message?
         case TLS_STATE_CLIENT_FINISHED:
            //A Finished message is always sent immediately after a changeCipherSpec
            //message to verify that the key exchange and authentication processes
            //were successful
            error = tlsSendFinished(context);
            break;
         //Waiting for a message from the server?
         case TLS_STATE_SERVER_HELLO:
         case TLS_STATE_SERVER_CERTIFICATE:
         case TLS_STATE_SERVER_KEY_EXCHANGE:
         case TLS_STATE_CERTIFICATE_REQUEST:
         case TLS_STATE_SERVER_HELLO_DONE:
         case TLS_STATE_SERVER_CHANGE_CIPHER_SPEC:
         case TLS_STATE_SERVER_FINISHED:
            //Parse incoming handshake message
            error = tlsParseServerMessage(context);
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

   //Any error to report?
   if(error)
   {
      //Send an alert message to the server, if applicable
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

error_t tlsParseServerMessage(TlsContext *context)
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
         //HelloRequest message received?
         case TLS_TYPE_HELLO_REQUEST:
            //The HelloRequest message can be sent at any time but it should be
            //ignored by the client if it arrives in the middle of a handshake
            error = NO_ERROR;
            break;
         //ServerHello message received?
         case TLS_TYPE_SERVER_HELLO:
            //The server will send this message in response to a ClientHello
            //message when it was able to find an acceptable set of algorithms
            error = tlsParseServerHello(context, message, length);
            break;
         //Certificate message received?
         case TLS_TYPE_CERTIFICATE:
            //The server must send a Certificate message whenever the agreed-
            //upon key exchange method uses certificates for authentication. This
            //message will always immediately follow the ServerHello message
            error = tlsParseCertificate(context, message, length);
            break;
         //ServerKeyExchange message received?
         case TLS_TYPE_SERVER_KEY_EXCHANGE:
            //The ServerKeyExchange message is sent by the server only when the
            //server Certificate message (if sent) does not contain enough data
            //to allow the client to exchange a premaster secret
            error = tlsParseServerKeyExchange(context, message, length);
            break;
         //CertificateRequest message received?
         case TLS_TYPE_CERTIFICATE_REQUEST:
            //A non-anonymous server can optionally request a certificate from the
            //client, if appropriate for the selected cipher suite. This message,
            //if sent, will immediately follow the ServerKeyExchange message
            error = tlsParseCertificateRequest(context, message, length);
            break;
         //ServerHelloDone message received?
         case TLS_TYPE_SERVER_HELLO_DONE:
            //The ServerHelloDone message is sent by the server to indicate the
            //end of the ServerHello and associated messages
            error = tlsParseServerHelloDone(context, message, length);
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
         }
      }
      //ChangeCipherSpec message received?
      else if(contentType == TLS_TYPE_CHANGE_CIPHER_SPEC)
      {
         //The ChangeCipherSpec message is sent by the server and to notify the
         //client that subsequent records will be protected under the newly
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
         //The server cannot transmit application data
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
   message = (TlsClientHello *) context->txBuffer;

   //Generate the client random value using a cryptographically-safe
   //pseudorandom number generator
   error = tlsGenerateRandomValue(context, &context->clientRandom);

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
      error = tlsWriteProtocolData(context, message, length, TLS_TYPE_HANDSHAKE);
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
   message = (TlsClientKeyExchange *) context->txBuffer;

   //Format ClientKeyExchange message
   error = tlsFormatClientKeyExchange(context, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending ClientKeyExchange message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsWriteProtocolData(context, message, length, TLS_TYPE_HANDSHAKE);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Derive session keys from the premaster secret
      error = tlsGenerateKeys(context);

      //Key material successfully generated?
      if(!error)
      {
         //Prepare to send CertificateVerify message...
         context->state = TLS_STATE_CERTIFICATE_VERIFY;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send CertificateVerify message
 *
 * The CertificateVerify message is used to provide explicit verification
 * of a client certificate. This message is only sent following a client
 * certificate that has signing capability
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendCertificateVerify(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsCertificateVerify *message;

   //Initialize status code
   error = NO_ERROR;

   //The CertificateVerify message is only sent following a client
   //certificate that has signing capability
   if(context->cert != NULL)
   {
      //Check certificate type
      if(context->cert->type == TLS_CERT_RSA_SIGN ||
         context->cert->type == TLS_CERT_DSS_SIGN ||
         context->cert->type == TLS_CERT_ECDSA_SIGN)
      {
         //Point to the buffer where to format the message
         message = (TlsCertificateVerify *) context->txBuffer;

         //Format CertificateVerify message
         error = tlsFormatCertificateVerify(context, message, &length);

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_INFO("Sending CertificateVerify message (%" PRIuSIZE " bytes)...\r\n", length);
            TRACE_DEBUG_ARRAY("  ", message, length);

            //Send handshake message
            error = tlsWriteProtocolData(context, message, length, TLS_TYPE_HANDSHAKE);
         }
      }
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Prepare to send ChangeCipherSpec message...
      context->state = TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC;
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
   uint_t i;
   uint_t n;
   uint8_t *p;
   TlsCipherSuites *cipherSuites;
   TlsCompressionMethods *compressionMethods;
   TlsExtensions *extensionList;

   //This flag tells whether any ECC cipher suite is proposed by the client
   bool_t eccCipherSuite = FALSE;

   //Handshake message type
   message->msgType = TLS_TYPE_CLIENT_HELLO;
   //Version of the protocol being employed by the client
   message->clientVersion = HTONS(TLS_MAX_VERSION);
   //Client random value
   message->random = context->clientRandom;

   //Point to the session ID
   p = message->sessionId;
   //Total length of the message
   *length = sizeof(TlsClientHello);

#if (TLS_SESSION_RESUME_SUPPORT == ENABLED)
   //The SessionID value identifies a session the client wishes
   //to reuse for this connection
   message->sessionIdLength = (uint8_t) context->sessionIdLen;
   memcpy(message->sessionId, context->sessionId, context->sessionIdLen);
#else
   //Session resumption is not supported
   message->sessionIdLength = 0;
#endif

   //Point to the next field
   p += message->sessionIdLength;
   //Adjust the length of the message
   *length += message->sessionIdLength;

   //List of cryptographic algorithms supported by the client
   cipherSuites = (TlsCipherSuites *) p;

   //Debug message
   TRACE_DEBUG("Cipher suites:\r\n");

   //User preferred cipher suite list
   if(context->numCipherSuites > 0)
   {
      //Number of cipher suites in the array
      n = 0;

      //Parse cipher suites
      for(i = 0; i < context->numCipherSuites; i++)
      {
         //Make sure the specified cipher suite is supported
         if(tlsIsCipherSuiteSupported(context->cipherSuites[i]))
         {
            //Copy cipher suite identifier
            cipherSuites->value[n++] = htons(context->cipherSuites[i]);

            //Debug message
            TRACE_DEBUG("  0x%04" PRIX16 " (%s)\r\n", context->cipherSuites[i],
               tlsGetCipherSuiteName(context->cipherSuites[i]));

            //ECC cipher suite?
            if(tlsIsEccCipherSuite(context->cipherSuites[i]))
               eccCipherSuite = TRUE;
         }
      }
   }
   //Default cipher suite list
   else
   {
      //Determine the number of supported cipher suites
      n = tlsGetNumSupportedCipherSuites();

      //Parse cipher suites
      for(i = 0; i < n; i++)
      {
         //Copy cipher suite identifier
         cipherSuites->value[i] = htons(tlsSupportedCipherSuites[i].identifier);

         //Debug message
         TRACE_DEBUG("  0x%04" PRIX16 " (%s)\r\n", tlsSupportedCipherSuites[i].identifier,
            tlsSupportedCipherSuites[i].name);

         //ECC cipher suite?
         if(tlsIsEccCipherSuite(tlsSupportedCipherSuites[i].identifier))
            eccCipherSuite = TRUE;
      }
   }

   //Length of the array, in bytes
   cipherSuites->length = htons(n * 2);
   //Point to the next field
   p += sizeof(TlsCipherSuites) + n * 2;
   //Total length of the message
   *length += sizeof(TlsCipherSuites) + n * 2;

   //List of compression algorithms supported by the client
   compressionMethods = (TlsCompressionMethods *) p;

   //The CRIME exploit takes advantage of TLS compression, so conservative
   //implementations do not enable compression at the TLS level
   compressionMethods->length = 1;
   compressionMethods->value[0] = TLS_COMPRESSION_METHOD_NULL;

   //Point to the next field
   p += sizeof(TlsCompressionMethods) + compressionMethods->length;
   //Total length of the message
   *length += sizeof(TlsCompressionMethods) + compressionMethods->length;

   //Clients may request extended functionality from servers by sending
   //data in the extensions field
   extensionList = (TlsExtensions *) p;
   //Total length of the extension list
   extensionList->length = 0;

   //Point to the first extension of the list
   p += sizeof(TlsExtensions);

#if (TLS_SNI_SUPPORT == ENABLED)
   //In order to provide the server name, clients may include a ServerName extension
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
      //Fix the length of the extension list
      extensionList->length += n;

      //Point to the next field
      p += n;
      //Total length of the message
      *length += n;
   }
#endif

#if (TLS_ALPN_SUPPORT == ENABLED)
   //The ALPN extension contains the list of protocols advertised by the
   //client, in descending order of preference
   if(context->protocolList != NULL)
   {
      uint_t j;
      TlsExtension *extension;
      TlsProtocolNameList *protocolNameList;
      TlsProtocolName *protocolName;

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
      //Fix the length of the extension list
      extensionList->length += n;

      //Point to the next field
      p += n;
      //Total length of the message
      *length += n;
   }
#endif

#if (TLS_ECDH_ANON_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //A client that proposes ECC cipher suites in its ClientHello message
   //should send the EllipticCurves extension
   if(eccCipherSuite)
   {
      TlsExtension *extension;
      TlsEllipticCurveList *ellipticCurveList;

      //Add the EllipticCurves extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_ELLIPTIC_CURVES);

      //Point to the list of supported elliptic curves
      ellipticCurveList = (TlsEllipticCurveList *) extension->value;
      //Items in the list are ordered according to client's preferences
      n = 0;

#if (TLS_SECP160K1_SUPPORT == ENABLED)
      //Support for secp160k1 elliptic curve
      ellipticCurveList->value[n++] = HTONS(TLS_EC_CURVE_SECP160K1);
#endif
#if (TLS_SECP160R1_SUPPORT == ENABLED)
      //Support for secp160r1 elliptic curve
      ellipticCurveList->value[n++] = HTONS(TLS_EC_CURVE_SECP160R1);
#endif
#if (TLS_SECP160R2_SUPPORT == ENABLED)
      //Support for secp160r2 elliptic curve
      ellipticCurveList->value[n++] = HTONS(TLS_EC_CURVE_SECP160R2);
#endif
#if (TLS_SECP192K1_SUPPORT == ENABLED)
      //Support for secp192k1 elliptic curve
      ellipticCurveList->value[n++] = HTONS(TLS_EC_CURVE_SECP192K1);
#endif
#if (TLS_SECP192R1_SUPPORT == ENABLED)
      //Support for secp192r1 elliptic curve
      ellipticCurveList->value[n++] = HTONS(TLS_EC_CURVE_SECP192R1);
#endif
#if (TLS_SECP224K1_SUPPORT == ENABLED)
      //Support for secp224k1 elliptic curve
      ellipticCurveList->value[n++] = HTONS(TLS_EC_CURVE_SECP224K1);
#endif
#if (TLS_SECP224R1_SUPPORT == ENABLED)
      //Support for secp224r1 elliptic curve
      ellipticCurveList->value[n++] = HTONS(TLS_EC_CURVE_SECP224R1);
#endif
#if (TLS_SECP256K1_SUPPORT == ENABLED)
      //Support for secp256k1 elliptic curve
      ellipticCurveList->value[n++] = HTONS(TLS_EC_CURVE_SECP256K1);
#endif
#if (TLS_SECP256R1_SUPPORT == ENABLED)
      //Support for secp256r1 elliptic curve
      ellipticCurveList->value[n++] = HTONS(TLS_EC_CURVE_SECP256R1);
#endif
#if (TLS_SECP384R1_SUPPORT == ENABLED)
      //Support for secp384r1 elliptic curve
      ellipticCurveList->value[n++] = HTONS(TLS_EC_CURVE_SECP384R1);
#endif
#if (TLS_SECP521R1_SUPPORT == ENABLED)
      //Support for secp521r1 elliptic curve
      ellipticCurveList->value[n++] = HTONS(TLS_EC_CURVE_SECP521R1);
#endif
#if (TLS_BRAINPOOLP256R1_SUPPORT == ENABLED)
      //Support for brainpoolP256r1 elliptic curve
      ellipticCurveList->value[n++] = HTONS(TLS_EC_CURVE_BRAINPOOLP256R1);
#endif
#if (TLS_BRAINPOOLP384R1_SUPPORT == ENABLED)
      //Support for brainpoolP384r1 elliptic curve
      ellipticCurveList->value[n++] = HTONS(TLS_EC_CURVE_BRAINPOOLP384R1);
#endif
#if (TLS_BRAINPOOLP512R1_SUPPORT == ENABLED)
      //Support for brainpoolP512r1 elliptic curve
      ellipticCurveList->value[n++] = HTONS(TLS_EC_CURVE_BRAINPOOLP512R1);
#endif

      //Compute the length, in bytes, of the list
      n *= 2;
      //Fix the length of the list
      ellipticCurveList->length = htons(n);

      //Consider the 2-byte length field that precedes the list
      n += sizeof(TlsEllipticCurveList);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the EllipticCurves extension
      n += sizeof(TlsExtension);
      //Fix the length of the extension list
      extensionList->length += n;

      //Point to the next field
      p += n;
      //Total length of the message
      *length += n;
   }

   //A client that proposes ECC cipher suites in its ClientHello message
   //should send the EcPointFormats extension
   if(eccCipherSuite)
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

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Include the SignatureAlgorithms extension only if TLS 1.2 is supported
   {
      TlsExtension *extension;
      TlsSignHashAlgos *supportedSignAlgos;

      //Add the SignatureAlgorithms extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_SIGNATURE_ALGORITHMS);

      //Point to the list of the hash/signature algorithm pairs that
      //the server is able to verify
      supportedSignAlgos = (TlsSignHashAlgos *) extension->value;

      //Enumerate the hash/signature algorithm pairs in descending
      //order of preference
      n = 0;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
      //MD5 with RSA is always supported
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_MD5;
      //SHA-1 with RSA is always supported
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;
#if (TLS_SHA224_SUPPORT == ENABLED)
      //SHA-224 with RSA support is optional
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA224;
#endif
      //SHA-256 with RSA is always supported
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
#if (TLS_SHA384_SUPPORT == ENABLED)
      //SHA-384 with RSA support is optional
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA384;
#endif
#if (TLS_SHA512_SUPPORT == ENABLED)
      //SHA-512 with RSA support is optional
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA512;
#endif
#endif

#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
      //DSA with SHA-1 is always supported
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_DSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;
#if (TLS_SHA224_SUPPORT == ENABLED)
      //DSA with SHA-224 support is optional
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_DSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA224;
#endif
      //DSA with SHA-256 is always supported
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_DSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
#endif

#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
      //Any ECC cipher suite proposed by the client?
      if(eccCipherSuite)
      {
         //ECDSA with SHA-1 is always supported
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;
#if (TLS_SHA224_SUPPORT == ENABLED)
         //ECDSA with SHA-224 support is optional
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA224;
#endif
         //ECDSA with SHA-256 is always supported
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
#if (TLS_SHA384_SUPPORT == ENABLED)
         //ECDSA with SHA-384 support is optional
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA384;
#endif
#if (TLS_SHA512_SUPPORT == ENABLED)
         //ECDSA with SHA-512 support is optional
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA512;
#endif
      }
#endif

      //Compute the length, in bytes, of the list
      n *= sizeof(TlsSignHashAlgo);
      //Fix the length of the list
      supportedSignAlgos->length = htons(n);

      //Consider the 2-byte length field that precedes the list
      n += sizeof(TlsSignHashAlgos);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the SignatureAlgorithms extension
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

   //Handshake message type
   message->msgType = TLS_TYPE_CLIENT_KEY_EXCHANGE;

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

   //Fix the length field
   STORE24BE(*length, message->length);
   //Length of the complete handshake message
   *length += sizeof(TlsHandshake);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format CertificateVerify message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the CertificateVerify message
 * @param[out] length Length of the resulting CertificateVerify message
 * @return Error code
 **/

error_t tlsFormatCertificateVerify(TlsContext *context,
   TlsCertificateVerify *message, size_t *length)
{
   error_t error;

   //Initialize message length
   *length = 0;

   //Handshake message type
   message->msgType = TLS_TYPE_CERTIFICATE_VERIFY;

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //SSL 3.0, TLS 1.0 or TLS 1.1 currently selected?
   if(context->version <= TLS_VERSION_1_1)
   {
      TlsDigitalSignature *signature;

      //Point to the digitally-signed element
      signature = (TlsDigitalSignature *) message->signature;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
      //The client's certificate contains a valid RSA public key?
      if(context->cert->type == TLS_CERT_RSA_SIGN)
      {
         RsaPrivateKey privateKey;

         //Initialize RSA private key
         rsaInitPrivateKey(&privateKey);

         //Digest all the handshake messages starting at ClientHello (using MD5)
         error = tlsFinalizeHandshakeHash(context, MD5_HASH_ALGO,
            context->handshakeMd5Context, "", context->verifyData);

         //Check status code
         if(!error)
         {
            //Digest all the handshake messages starting at ClientHello (using SHA-1)
            error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
               context->handshakeSha1Context, "", context->verifyData + MD5_DIGEST_SIZE);
         }

         //Check status code
         if(!error)
         {
            //Decode the PEM structure that holds the RSA private key
            error = pemReadRsaPrivateKey(context->cert->privateKey,
               context->cert->privateKeyLength, &privateKey);
         }

         //Check status code
         if(!error)
         {
            //Generate a RSA signature using the client's private key
            error = tlsGenerateRsaSignature(&privateKey,
               context->verifyData, signature->value, length);
         }

         //Release previously allocated resources
         rsaFreePrivateKey(&privateKey);
      }
      else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
      //The client's certificate contains a valid DSA public key?
      if(context->cert->type == TLS_CERT_DSS_SIGN)
      {
         DsaPrivateKey privateKey;

         //Initialize DSA private key
         dsaInitPrivateKey(&privateKey);

         //Digest all the handshake messages starting at ClientHello
         error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
            context->handshakeSha1Context, "", context->verifyData);

         //Check status code
         if(!error)
         {
            //Decode the PEM structure that holds the DSA private key
            error = pemReadDsaPrivateKey(context->cert->privateKey,
               context->cert->privateKeyLength, &privateKey);
         }

         //Check status code
         if(!error)
         {
            //Generate a DSA signature using the client's private key
            error = tlsGenerateDsaSignature(context->prngAlgo,
               context->prngContext, &privateKey, context->verifyData,
               SHA1_DIGEST_SIZE, signature->value, length);
         }

         //Release previously allocated resources
         dsaFreePrivateKey(&privateKey);
      }
      else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
      //The client's certificate contains a valid ECDSA public key?
      if(context->cert->type == TLS_CERT_ECDSA_SIGN)
      {
         EcDomainParameters params;
         Mpi privateKey;

         //Initialize EC domain parameters
         ecInitDomainParameters(&params);
         //Initialize EC private key
         mpiInit(&privateKey);

         //Digest all the handshake messages starting at ClientHello
         error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
            context->handshakeSha1Context, "", context->verifyData);

         //Check status code
         if(!error)
         {
            //Decode the PEM structure that holds the EC domain parameters
            error = pemReadEcParameters(context->cert->privateKey,
               context->cert->privateKeyLength, &params);
         }

         //Check status code
         if(!error)
         {
            //Decode the PEM structure that holds the EC private key
            error = pemReadEcPrivateKey(context->cert->privateKey,
               context->cert->privateKeyLength, &privateKey);
         }

         //Check status code
         if(!error)
         {
            //Generate an ECDSA signature using the client's private key
            error = tlsGenerateEcdsaSignature(&params, context->prngAlgo,
               context->prngContext, &privateKey, context->verifyData,
               SHA1_DIGEST_SIZE, signature->value, length);
         }

         //Release previously allocated resources
         ecFreeDomainParameters(&params);
         mpiFree(&privateKey);
      }
      else
#endif
      //Invalid signature algorithm?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }

      //Length of the signature
      signature->length = htons(*length);
      //Total length of the digitally-signed element
      *length += sizeof(TlsDigitalSignature);
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      TlsDigitalSignature2 *signature;
      const HashAlgo *hashAlgo;

      //Point to the digitally-signed element
      signature = (TlsDigitalSignature2 *) message->signature;

      //Retrieve the hash algorithm to be used for signing
      hashAlgo = tlsGetHashAlgo(context->signHashAlgo);

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

      //Handshake message hash successfully computed?
      if(!error)
      {
#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
         //The client's certificate contains a valid RSA public key?
         if(context->cert->type == TLS_CERT_RSA_SIGN)
         {
            RsaPrivateKey privateKey;

            //Initialize RSA private key
            rsaInitPrivateKey(&privateKey);

            //Set the relevant signature algorithm
            signature->algorithm.signature = TLS_SIGN_ALGO_RSA;
            signature->algorithm.hash = context->signHashAlgo;

            //Decode the PEM structure that holds the RSA private key
            error = pemReadRsaPrivateKey(context->cert->privateKey,
               context->cert->privateKeyLength, &privateKey);

            //Check status code
            if(!error)
            {
               //Use the signature algorithm defined in PKCS #1 v1.5
               error = rsassaPkcs1v15Sign(&privateKey, hashAlgo,
                  context->verifyData, signature->value, length);
            }

            //Release previously allocated resources
            rsaFreePrivateKey(&privateKey);
         }
         else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
         //The client's certificate contains a valid DSA public key?
         if(context->cert->type == TLS_CERT_DSS_SIGN)
         {
            DsaPrivateKey privateKey;

            //Initialize DSA private key
            dsaInitPrivateKey(&privateKey);

            //Set the relevant signature algorithm
            signature->algorithm.signature = TLS_SIGN_ALGO_DSA;
            signature->algorithm.hash = context->signHashAlgo;

            //Decode the PEM structure that holds the DSA private key
            error = pemReadDsaPrivateKey(context->cert->privateKey,
               context->cert->privateKeyLength, &privateKey);

            //Check status code
            if(!error)
            {
               //Generate a DSA signature using the client's private key
               error = tlsGenerateDsaSignature(context->prngAlgo,
                  context->prngContext, &privateKey, context->verifyData,
                  hashAlgo->digestSize, signature->value, length);
            }

            //Release previously allocated resources
            dsaFreePrivateKey(&privateKey);
         }
         else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
         //The client's certificate contains a valid ECDSA public key?
         if(context->cert->type == TLS_CERT_ECDSA_SIGN)
         {
            EcDomainParameters params;
            Mpi privateKey;

            //Initialize EC domain parameters
            ecInitDomainParameters(&params);
            //Initialize EC private key
            mpiInit(&privateKey);

            //Set the relevant signature algorithm
            signature->algorithm.signature = TLS_SIGN_ALGO_ECDSA;
            signature->algorithm.hash = context->signHashAlgo;

            //Decode the PEM structure that holds the EC domain parameters
            error = pemReadEcParameters(context->cert->privateKey,
               context->cert->privateKeyLength, &params);

            //Check status code
            if(!error)
            {
               //Decode the PEM structure that holds the EC private key
               error = pemReadEcPrivateKey(context->cert->privateKey,
                  context->cert->privateKeyLength, &privateKey);
            }

            //Check status code
            if(!error)
            {
               //Generate an ECDSA signature using the client's private key
               error = tlsGenerateEcdsaSignature(&params, context->prngAlgo,
                  context->prngContext, &privateKey, context->verifyData,
                  hashAlgo->digestSize, signature->value, length);
            }

            //Release previously allocated resources
            ecFreeDomainParameters(&params);
            mpiFree(&privateKey);
         }
         else
#endif
         //Invalid signature algorithm?
         {
            //Report an error
            error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
         }
      }

      //Length of the signature
      signature->length = htons(*length);
      //Length of the digitally-signed element
      *length += sizeof(TlsDigitalSignature2);
   }
   else
#endif
   {
      //The negotiated TLS version is not valid
      error = ERROR_INVALID_VERSION;
   }

   //Fix the length field
   STORE24BE(*length, message->length);
   //Length of the complete handshake message
   *length += sizeof(TlsHandshake);

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

error_t tlsParseServerHello(TlsContext *context, const TlsServerHello *message, size_t length)
{
   error_t error;
   size_t n;
   const uint8_t *p;
   TlsCipherSuite cipherSuite;
   TlsCompressionMethod compressionMethod;

   //Debug message
   TRACE_INFO("ServerHello message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check the length of the ServerHello message
   if(length < sizeof(TlsServerHello))
      return ERROR_DECODING_FAILED;

   //Check current state
   if(context->state != TLS_STATE_SERVER_HELLO)
      return ERROR_UNEXPECTED_MESSAGE;

   //Point to the session ID
   p = (uint8_t *) message + sizeof(TlsServerHello);
   //Remaining bytes to process
   n = length - sizeof(TlsServerHello);

   //Check the length of the session ID
   if(message->sessionIdLength > n)
      return ERROR_DECODING_FAILED;
   if(message->sessionIdLength > 32)
      return ERROR_ILLEGAL_PARAMETER;

   //Point to the next field
   p += message->sessionIdLength;
   //Remaining bytes to process
   n -= message->sessionIdLength;

   //Malformed ServerHello message?
   if(n < (sizeof(TlsCipherSuite) + sizeof(TlsCompressionMethod)))
      return ERROR_DECODING_FAILED;

   //Get the negotiated cipher suite
   cipherSuite = LOAD16BE(p);
   //Point to the next field
   p += sizeof(TlsCipherSuite);
   //Remaining bytes to process
   n -= sizeof(TlsCipherSuite);

   //Get the negotiated compression method
   compressionMethod = *p;
   //Point to the next field
   p += sizeof(TlsCompressionMethod);
   //Remaining bytes to process
   n -= sizeof(TlsCompressionMethod);

   //Server version
   TRACE_INFO("  serverVersion = 0x%04" PRIX16 " (%s)\r\n", ntohs(message->serverVersion),
      tlsGetVersionName(ntohs(message->serverVersion)));
   //Server random value
   TRACE_INFO("  random\r\n");
   TRACE_INFO_ARRAY("    ", &message->random, sizeof(TlsRandom));
   //Session identifier
   TRACE_INFO("  sessionId\r\n");
   TRACE_INFO_ARRAY("    ", message->sessionId, message->sessionIdLength);
   //Cipher suite identifier
   TRACE_INFO("  cipherSuite = 0x%04" PRIX16 " (%s)\r\n",
      cipherSuite, tlsGetCipherSuiteName(cipherSuite));
   //Compression method
   TRACE_INFO("  compressionMethod = 0x%02" PRIX8 "\r\n", compressionMethod);

#if (TLS_SESSION_RESUME_SUPPORT == ENABLED)
   //Check whether the session ID matches the value that was supplied by the client
   if(message->sessionIdLength > 0 && message->sessionIdLength == context->sessionIdLen &&
      !memcmp(message->sessionId, context->sessionId, context->sessionIdLen))
   {
      //For resumed sessions, the selected cipher suite and compression
      //method shall be the same as the session being resumed
      if(cipherSuite != context->cipherSuite ||
         compressionMethod != context->compressionMethod)
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

   //Save session identifier
   memcpy(context->sessionId, message->sessionId, message->sessionIdLength);
   context->sessionIdLen = message->sessionIdLength;

   //Set the TLS version to use
   error = tlsSetVersion(context, ntohs(message->serverVersion));
   //The specified TLS version is not supported?
   if(error)
      return error;

   //Set cipher suite
   error = tlsSetCipherSuite(context, cipherSuite);
   //The specified cipher suite is not supported?
   if(error)
      return error;

   //Set compression method
   error = tlsSetCompressionMethod(context, compressionMethod);
   //The specified compression method is not supported?
   if(error)
      return error;

   //Initialize handshake message hashing
   error = tlsInitHandshakeHash(context);
   //Any error to report?
   if(error)
      return error;

   //Update the hash value with the incoming handshake message
   tlsUpdateHandshakeHash(context, message, length);

#if (TLS_SESSION_RESUME_SUPPORT == ENABLED)
   //Use abbreviated handshake?
   if(context->resume)
   {
      //Derive session keys from the master secret
      error = tlsGenerateKeys(context);
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

error_t tlsParseServerKeyExchange(TlsContext *context, const TlsServerKeyExchange *message, size_t length)
{
   error_t error;
   size_t n;
   size_t paramsLen;
   const uint8_t *p;
   const uint8_t *params;

   //Debug message
   TRACE_INFO("ServerKeyExchange message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check the length of the ServerKeyExchange message
   if(length < sizeof(TlsServerKeyExchange))
      return ERROR_DECODING_FAILED;

   //Check current state
   if(context->state != TLS_STATE_SERVER_KEY_EXCHANGE)
      return ERROR_UNEXPECTED_MESSAGE;

   //Update the hash value with the incoming handshake message
   tlsUpdateHandshakeHash(context, message, length);

   //Point to the body of the handshake message
   p = message->data;
   //Remaining bytes to process
   length -= sizeof(TlsServerKeyExchange);

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

   //Non-anonymous Diffie-Hellman and ECDH key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
   {
      //For non-anonymous Diffie-Hellman and ECDH key exchanges, the signature
      //over the server's key exchange parameters shall be verified
      error = tlsVerifyServerKeySignature(context, p, length, params, paramsLen, &n);
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

error_t tlsParseCertificateRequest(TlsContext *context, const TlsCertificateRequest *message, size_t length)
{
   uint_t i;
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

   //Update the hash value with the incoming handshake message
   tlsUpdateHandshakeHash(context, message, length);

   //The server requests a certificate from the client, so that
   //the connection can be mutually authenticated
   context->clientCertRequested = TRUE;

   //Point to the beginning of the message
   p = (uint8_t *) message;
   //Remaining bytes to process
   length -= sizeof(TlsCertificateRequest);

   //Retrieve the size of the list of supported certificate types
   n = message->certificateTypesLength;
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
   if(n > length)
      return ERROR_DECODING_FAILED;

   //No suitable certificate has been found for the moment
   context->cert = NULL;

   //Loop through the list of available certificates
   for(i = 0; i < context->numCerts; i++)
   {
      //Check whether the current certificate is suitable
      acceptable = tlsIsCertificateAcceptable(&context->certs[i],
         message->certificateTypes, message->certificateTypesLength,
         supportedSignAlgos, NULL, certAuthorities);

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //TLS 1.2 requires additional examinations
      if(acceptable && context->version == TLS_VERSION_1_2)
      {
         //The hash and signature algorithms used in the signature of the CertificateVerify
         //message must be one of those present in the SupportedSignatureAlgorithms field
         if(tlsSelectSignHashAlgo(context, context->certs[i].signAlgo, supportedSignAlgos))
            acceptable = FALSE;
      }
#endif

      //If all the requirements were met, the certificate can be
      //used to authenticate the client
      if(acceptable)
      {
         context->cert = &context->certs[i];
         break;
      }
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

error_t tlsParseServerHelloDone(TlsContext *context, const TlsServerHelloDone *message, size_t length)
{
   //Debug message
   TRACE_INFO("ServerHelloDone message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check the length of the ServerHelloDone message
   if(length != sizeof(TlsServerHelloDone))
      return ERROR_DECODING_FAILED;

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

   //Update the hash value with the incoming handshake message
   tlsUpdateHandshakeHash(context, message, length);

   //Prepare to send client Certificate message...
   context->state = TLS_STATE_CLIENT_CERTIFICATE;
   //Successful processing
   return NO_ERROR;
}

#endif
