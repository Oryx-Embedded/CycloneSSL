/**
 * @file tls_handshake.c
 * @brief TLS handshake
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2019 Oryx Embedded SARL. All rights reserved.
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
 * @version 1.9.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include "tls.h"
#include "tls_cipher_suites.h"
#include "tls_handshake.h"
#include "tls_client.h"
#include "tls_server.h"
#include "tls_common.h"
#include "tls_transcript_hash.h"
#include "tls_cache.h"
#include "tls_record.h"
#include "tls_misc.h"
#include "tls13_client.h"
#include "tls13_client_misc.h"
#include "tls13_server.h"
#include "tls13_server_misc.h"
#include "tls13_common.h"
#include "tls13_key_material.h"
#include "dtls_record.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief TLS handshake initialization
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsInitHandshake(TlsContext *context)
{
   //Allocate send buffer if necessary
   if(context->txBuffer == NULL)
   {
      //Allocate TX buffer
      context->txBuffer = tlsAllocMem(context->txBufferSize);

      //Failed to allocate memory?
      if(context->txBuffer == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Clear TX buffer
      memset(context->txBuffer, 0, context->txBufferSize);
   }

   //Allocate receive buffer if necessary
   if(context->rxBuffer == NULL)
   {
      //Allocate RX buffer
      context->rxBuffer = tlsAllocMem(context->rxBufferSize);

      //Failed to allocate memory?
      if(context->rxBuffer == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Clear RX buffer
      memset(context->rxBuffer, 0, context->rxBufferSize);
   }

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS operates as a server?
   if(context->entity == TLS_CONNECTION_END_SERVER)
   {
      //A server implementation may choose to reject the early data
      context->earlyDataRejected = TRUE;
   }
#endif

   //The client initiates the TLS handshake by sending a ClientHello message
   //to the server
   context->state = TLS_STATE_CLIENT_HELLO;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Perform TLS handshake
 *
 * TLS handshake protocol is responsible for the authentication and key
 * exchange necessary to establish a secure session
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsPerformHandshake(TlsContext *context)
{
   error_t error;

   //Check whether TLS operates as a client or a server
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Perform TLS handshake with the remote server
      error = tlsPerformClientHandshake(context);
   }
   else if(context->entity == TLS_CONNECTION_END_SERVER)
   {
      //Perform TLS handshake with the remote client
      error = tlsPerformServerHandshake(context);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief TLS client handshake
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsPerformClientHandshake(TlsContext *context)
{
#if (TLS_CLIENT_SUPPORT == ENABLED)
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Wait for the handshake to complete
   while(!error)
   {
      //TLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
      {
         //Check current state
         if(context->state != TLS_STATE_INIT &&
            context->state != TLS_STATE_CLOSED)
         {
            //Flush send buffer
            error = tlsWriteProtocolData(context, NULL, 0, TLS_TYPE_NONE);
            //Any error to report?
            if(error)
               break;
         }
      }

      //Check whether the handshake is complete
      if(context->state == TLS_STATE_APPLICATION_DATA)
      {
         //At this is point, the handshake is complete and the client starts
         //to exchange application-layer data
         break;
      }

      //The TLS handshake is implemented as a state machine representing the
      //current location in the protocol
      switch(context->state)
      {
      //Initial state?
      case TLS_STATE_INIT:
         //TLS handshake initialization
         error = tlsInitHandshake(context);
         break;

      //Sending ClientHello message?
      case TLS_STATE_CLIENT_HELLO:
      case TLS_STATE_CLIENT_HELLO_2:
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

      //Sending CertificateVerify message?
      case TLS_STATE_CLIENT_CERTIFICATE_VERIFY:
         //This message is used to provide explicit verification of a client
         //certificate. This message is only sent following a client certificate
         //that has signing capability. When sent, it must immediately follow
         //the clientKeyExchange message
         error = tlsSendCertificateVerify(context);
         break;

      //Sending ChangeCipherSpec message?
      case TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC:
      case TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC_2:
         //The ChangeCipherSpec message is sent by the client and to notify the
         //server that subsequent records will be protected under the newly
         //negotiated CipherSpec and keys
         error = tlsSendChangeCipherSpec(context);
         break;

      //Sending Finished message?
      case TLS_STATE_CLIENT_FINISHED:
         //A Finished message is always sent immediately after a ChangeCipherSpec
         //message to verify that the key exchange and authentication processes
         //were successful
         error = tlsSendFinished(context);
         break;

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //Sending ClientKeyExchange message?
      case TLS_STATE_CLIENT_KEY_EXCHANGE:
         //This message is always sent by the client. It must immediately
         //follow the client certificate message, if it is sent. Otherwise,
         //it must be the first message sent by the client after it receives
         //the ServerHelloDone message
         error = tlsSendClientKeyExchange(context);
         break;
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //Sending EndOfEarlyData message?
      case TLS_STATE_END_OF_EARLY_DATA:
         //The EndOfEarlyData message indicates that all 0-RTT application
         //data messages, if any, have been transmitted and that the following
         //records are protected under handshake traffic keys
         error = tls13SendEndOfEarlyData(context);
         break;

      //Handshake traffic key generation?
      case TLS_STATE_HANDSHAKE_TRAFFIC_KEYS:
         //Compute handshake traffic keys
         error = tls13GenerateHandshakeTrafficKeys(context);
         break;

      //Server application traffic key generation?
      case TLS_STATE_SERVER_APP_TRAFFIC_KEYS:
         //Compute server application traffic keys
         error = tls13GenerateServerAppTrafficKeys(context);
         break;

      //Client application traffic key generation?
      case TLS_STATE_CLIENT_APP_TRAFFIC_KEYS:
         //Compute client application traffic keys
         error = tls13GenerateClientAppTrafficKeys(context);
         break;

      //Sending KeyUpdate message?
      case TLS_STATE_KEY_UPDATE:
         //The KeyUpdate handshake message is used to indicate that the sender
         //is updating its sending cryptographic keys
         error = tls13SendKeyUpdate(context);
         break;
#endif

      //Waiting for a message from the server?
      case TLS_STATE_SERVER_HELLO:
      case TLS_STATE_SERVER_HELLO_2:
      case TLS_STATE_SERVER_HELLO_3:
      case TLS_STATE_ENCRYPTED_EXTENSIONS:
      case TLS_STATE_SERVER_CERTIFICATE:
      case TLS_STATE_SERVER_KEY_EXCHANGE:
      case TLS_STATE_SERVER_CERTIFICATE_VERIFY:
      case TLS_STATE_CERTIFICATE_REQUEST:
      case TLS_STATE_SERVER_HELLO_DONE:
      case TLS_STATE_SERVER_CHANGE_CIPHER_SPEC:
      case TLS_STATE_SERVER_FINISHED:
         //Receive server's message
         error = tlsReceiveHandshakeMessage(context);
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

   //Any error to report?
   if(error)
   {
      //Send an alert message to the server, if applicable
      tlsProcessError(context, error);
   }

   //Return status code
   return error;
#else
   //Client mode of operation not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief TLS server handshake
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsPerformServerHandshake(TlsContext *context)
{
#if (TLS_SERVER_SUPPORT == ENABLED)
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Wait for the handshake to complete
   while(!error)
   {
      //TLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
      {
         //Check current state
         if(context->state != TLS_STATE_INIT &&
            context->state != TLS_STATE_CLOSED)
         {
            //Flush send buffer
            error = tlsWriteProtocolData(context, NULL, 0, TLS_TYPE_NONE);
            //Any error to report?
            if(error)
               break;
         }
      }

      //Check whether the handshake is complete
      if(context->state == TLS_STATE_APPLICATION_DATA)
      {
         //At this is point, the handshake is complete and the server starts
         //to exchange application-layer data
         break;
      }

      //The TLS handshake is implemented as a state machine representing the
      //current location in the protocol
      switch(context->state)
      {
      //Initial state?
      case TLS_STATE_INIT:
         //TLS handshake initialization
         error = tlsInitHandshake(context);
         break;

      //Sending ServerHello message?
      case TLS_STATE_SERVER_HELLO:
      case TLS_STATE_SERVER_HELLO_2:
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

      //Sending Certificate message?
      case TLS_STATE_CERTIFICATE_REQUEST:
         //A non-anonymous server can optionally request a certificate from the
         //client, if appropriate for the selected cipher suite. This message,
         //if sent, will immediately follow the ServerKeyExchange message
         error = tlsSendCertificateRequest(context);
         break;

      //Sending ChangeCipherSpec message?
      case TLS_STATE_SERVER_CHANGE_CIPHER_SPEC:
      case TLS_STATE_SERVER_CHANGE_CIPHER_SPEC_2:
         //The ChangeCipherSpec message is sent by the server and to notify the
         //client that subsequent records will be protected under the newly
         //negotiated CipherSpec and keys
         error = tlsSendChangeCipherSpec(context);
         break;

      //Sending Finished message?
      case TLS_STATE_SERVER_FINISHED:
         //A Finished message is always sent immediately after a ChangeCipherSpec
         //message to verify that the key exchange and authentication processes
         //were successful
         error = tlsSendFinished(context);
         break;

#if (DTLS_SUPPORT == ENABLED)
      //Sending HelloVerifyRequest message?
      case TLS_STATE_HELLO_VERIFY_REQUEST:
         //When the client sends its ClientHello message to the server, the
         //server may respond with a HelloVerifyRequest message
         error = dtlsSendHelloVerifyRequest(context);
         break;
#endif

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //Sending ServerKeyExchange message?
      case TLS_STATE_SERVER_KEY_EXCHANGE:
         //The ServerKeyExchange message is sent by the server only when the
         //server Certificate message (if sent) does not contain enough data
         //to allow the client to exchange a premaster secret
         error = tlsSendServerKeyExchange(context);
         break;

      //Sending ServerHelloDone message?
      case TLS_STATE_SERVER_HELLO_DONE:
         //The ServerHelloDone message is sent by the server to indicate the
         //end of the ServerHello and associated messages
         error = tlsSendServerHelloDone(context);
         break;
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //Sending HelloRetryRequest message?
      case TLS_STATE_HELLO_RETRY_REQUEST:
         //The server sends a HelloRetryRequest message if the ClientHello
         //message does not contain sufficient information to proceed with
         //the handshake
         error = tls13SendHelloRetryRequest(context);
         break;

      //Handshake traffic key generation?
      case TLS_STATE_HANDSHAKE_TRAFFIC_KEYS:
         //Compute handshake traffic keys
         error = tls13GenerateHandshakeTrafficKeys(context);
         break;

      //Sending EncryptedExtensions message?
      case TLS_STATE_ENCRYPTED_EXTENSIONS:
         //The server sends the EncryptedExtensions message immediately after
         //the ServerHello message. The EncryptedExtensions message contains
         //extensions that can be protected
         error = tls13SendEncryptedExtensions(context);
         break;

      //Sending CertificateVerify message?
      case TLS_STATE_SERVER_CERTIFICATE_VERIFY:
         //Servers must send this message when authenticating via a
         //certificate. When sent, this message must appear immediately
         //after the Certificate message
         error = tlsSendCertificateVerify(context);
         break;

      //Server application traffic key generation?
      case TLS_STATE_SERVER_APP_TRAFFIC_KEYS:
         //Compute server application traffic keys
         error = tls13GenerateServerAppTrafficKeys(context);
         break;

      //Client application traffic key generation?
      case TLS_STATE_CLIENT_APP_TRAFFIC_KEYS:
         //Compute client application traffic keys
         error = tls13GenerateClientAppTrafficKeys(context);
         break;

      //Sending NewSessionTicket message message?
      case TLS_STATE_NEW_SESSION_TICKET:
         //At any time after the server has received the client Finished
         //message, it may send a NewSessionTicket message
         error = tls13SendNewSessionTicket(context);
         break;

      //Sending KeyUpdate message?
      case TLS_STATE_KEY_UPDATE:
         //The KeyUpdate handshake message is used to indicate that the sender
         //is updating its sending cryptographic keys
         error = tls13SendKeyUpdate(context);
         break;
#endif

      //Waiting for a message from the client?
      case TLS_STATE_CLIENT_HELLO:
      case TLS_STATE_CLIENT_HELLO_2:
      case TLS_STATE_CLIENT_CERTIFICATE:
      case TLS_STATE_CLIENT_KEY_EXCHANGE:
      case TLS_STATE_CLIENT_CERTIFICATE_VERIFY:
      case TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC:
      case TLS_STATE_CLIENT_FINISHED:
         //Receive client's message
         error = tlsReceiveHandshakeMessage(context);
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

   //Successful TLS handshake?
   if(!error)
   {
#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
         //Save current session in the session cache for further reuse
         tlsSaveToCache(context);
      }
#endif
   }
   else
   {
      //Send an alert message to the client, if applicable
      tlsProcessError(context, error);
   }

   //Return status code
   return error;
#else
   //Server mode of operation not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Send handshake message
 * @param[in] context Pointer to the TLS context
 * @param[in] data Pointer to the handshake message
 * @param[in] length Length of the handshake message
 * @param[in] type Handshake message type
 * @return Error code
 **/

error_t tlsSendHandshakeMessage(TlsContext *context, const void *data,
   size_t length, TlsMessageType type)
{
   error_t error;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      DtlsHandshake *message;

      //Point to the handshake message header
      message = (DtlsHandshake *) data;

      //Make room for the handshake message header
      memmove(message->data, data, length);

      //Handshake message type
      message->msgType = type;
      //Number of bytes in the message
      STORE24BE(length, message->length);
      //Message sequence number
      message->msgSeq = htons(context->txMsgSeq);
      //Fragment offset
      STORE24BE(0, message->fragOffset);
      //Fragment length
      STORE24BE(length, message->fragLength);

      //Whenever a new message is generated, the message sequence
      //number is incremented by one
      context->txMsgSeq++;

      //Total length of the handshake message
      length += sizeof(DtlsHandshake);
   }
   else
#endif
   //TLS protocol?
   {
      TlsHandshake *message;

      //Point to the handshake message header
      message = (TlsHandshake *) data;

      //Make room for the handshake message header
      memmove(message->data, data, length);

      //Handshake message type
      message->msgType = type;
      //Number of bytes in the message
      STORE24BE(length, message->length);

      //Total length of the handshake message
      length += sizeof(TlsHandshake);
   }

   //The HelloRequest message must not be included in the message hashes
   //that are maintained throughout the handshake and used in the Finished
   //messages and the CertificateVerify message
   if(type != TLS_TYPE_HELLO_REQUEST)
   {
      tlsUpdateTranscriptHash(context, data, length);
   }

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Send handshake message
      error = dtlsWriteProtocolData(context, data, length, TLS_TYPE_HANDSHAKE);
   }
   else
#endif
   //TLS protocol?
   {
      //Send handshake message
      error = tlsWriteProtocolData(context, data, length, TLS_TYPE_HANDSHAKE);
   }

   //Return status code
   return error;
}


/**
 * @brief Receive peer's message
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsReceiveHandshakeMessage(TlsContext *context)
{
   error_t error;
   size_t length;
   uint8_t *data;
   TlsContentType contentType;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //A message can be fragmented across several DTLS records
      error = dtlsReadProtocolData(context, &data, &length, &contentType);
   }
   else
#endif
   //TLS protocol?
   {
      //A message can be fragmented across several TLS records
      error = tlsReadProtocolData(context, &data, &length, &contentType);
   }

   //Check status code
   if(!error)
   {
      //Advance data pointer
      context->rxBufferPos += length;
      //Number of bytes still pending in the receive buffer
      context->rxBufferLen -= length;

      //Handshake message received?
      if(contentType == TLS_TYPE_HANDSHAKE)
      {
         //Parse handshake message
         error = tlsParseHandshakeMessage(context, data, length);
      }
      //ChangeCipherSpec message received?
      else if(contentType == TLS_TYPE_CHANGE_CIPHER_SPEC)
      {
         //The ChangeCipherSpec message is sent by an endpoint to notify the
         //peer that subsequent records will be protected under the newly
         //negotiated CipherSpec and keys
         error = tlsParseChangeCipherSpec(context, (TlsChangeCipherSpec *) data,
            length);
      }
      //Alert message received?
      else if(contentType == TLS_TYPE_ALERT)
      {
         //Parse Alert message
         error = tlsParseAlert(context, (TlsAlert *) data, length);
      }
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //Application data received?
      else if(contentType == TLS_TYPE_APPLICATION_DATA)
      {
#if (TLS_SERVER_SUPPORT == ENABLED)
         //TLS operates as a server?
         if(context->entity == TLS_CONNECTION_END_SERVER)
         {
            //Process early data
            error = tls13ProcessEarlyData(context, data, length);
         }
         else
#endif
         {
            //The server cannot transmit application data before the handshake
            //is completed
            error = ERROR_UNEXPECTED_MESSAGE;
         }
      }
#endif
      //Unexpected message received?
      else
      {
         //Abort the handshake with an unexpected_message alert
         error = ERROR_UNEXPECTED_MESSAGE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse handshake message
 * @param[in] context Pointer to the TLS context
 * @param[in] message Pointer to the handshake message to parse
 * @param[in] length Length of the handshake messaged
 * @return Error code
 **/

error_t tlsParseHandshakeMessage(TlsContext *context, const uint8_t *message,
   size_t length)
{
   error_t error;
   uint8_t msgType;
   size_t n;
   const void *p;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Retrieve handshake message type
      msgType = ((DtlsHandshake *) message)->msgType;
      //Point to the handshake message
      p = message + sizeof(DtlsHandshake);
      //Calculate the length of the handshake message
      n = length - sizeof(DtlsHandshake);
   }
   else
#endif
   //TLS protocol?
   {
      //Retrieve handshake message type
      msgType = ((TlsHandshake *) message)->msgType;
      //Point to the handshake message
      p = message + sizeof(TlsHandshake);
      //Calculate the length of the handshake message
      n = length - sizeof(TlsHandshake);
   }

#if (TLS_MAX_KEY_UPDATE_MESSAGES > 0)
   //Reset the count of consecutive KeyUpdate messages
   if(msgType != TLS_TYPE_KEY_UPDATE)
      context->keyUpdateCount = 0;
#endif

#if (TLS_CLIENT_SUPPORT == ENABLED)
   //TLS operates as a client?
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Parse server's handshake message
      error = tlsParseServerHandshakeMessage(context, msgType, p, n);

      //Update the hash value with the incoming handshake message
      tlsUpdateTranscriptHash(context, message, length);
   }
   else
#endif
#if (TLS_SERVER_SUPPORT == ENABLED)
   //TLS operates as a server?
   if(context->entity == TLS_CONNECTION_END_SERVER)
   {
      //Update the hash value with the incoming handshake message
      if(msgType == TLS_TYPE_CLIENT_KEY_EXCHANGE)
      {
         tlsUpdateTranscriptHash(context, message, length);
      }

      //Parse client's handshake message
      error = tlsParseClientHandshakeMessage(context, msgType, p, n);

      //Update the hash value with the incoming handshake message
      if(msgType != TLS_TYPE_CLIENT_KEY_EXCHANGE)
      {
         tlsUpdateTranscriptHash(context, message, length);
      }
   }
   else
#endif
   //Unsupported mode of operation?
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse client's handshake message
 * @param[in] context Pointer to the TLS context
 * @param[in] msgType Handshake message type
 * @param[in] message Pointer to the handshake message to parse
 * @param[in] length Length of the handshake messaged
 * @return Error code
 **/

error_t tlsParseClientHandshakeMessage(TlsContext *context, uint8_t msgType,
   const void *message, size_t length)
{
#if (TLS_SERVER_SUPPORT == ENABLED)
   error_t error;

   //Check handshake message type
   switch(msgType)
   {
   //ClientHello message received?
   case TLS_TYPE_CLIENT_HELLO:
      //When a client first connects to a server, it is required to send the
      //ClientHello as its first message
      error = tlsParseClientHello(context, message, length);
      break;

   //Certificate message received?
   case TLS_TYPE_CERTIFICATE:
      //This is the first message the client can send after receiving a
      //ServerHelloDone message. This message is only sent if the server
      //requests a certificate
      error = tlsParseCertificate(context, message, length);
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
      //A Finished message is always sent immediately after a ChangeCipherSpec
      //message to verify that the key exchange and authentication processes
      //were successful
      error = tlsParseFinished(context, message, length);
      break;

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //ClientKeyExchange message received?
   case TLS_TYPE_CLIENT_KEY_EXCHANGE:
      //This message must immediately follow the client certificate message, if
      //it is sent. Otherwise, it must be the first message sent by the client
      //after it receives the ServerHelloDone message
      error = tlsParseClientKeyExchange(context, message, length);
      break;
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //KeyUpdate message received?
   case TLS_TYPE_KEY_UPDATE:
      //The KeyUpdate handshake message is used to indicate that the client is
      //updating its sending cryptographic keys. This message can be sent by
      //the client after it has sent a Finished message
      error = tls13ParseKeyUpdate(context, message, length);
      break;
#endif

   //Invalid handshake message received?
   default:
      //Report an error
      error = ERROR_UNEXPECTED_MESSAGE;
      break;
   }

   //Return status code
   return error;
#else
   //Server mode of operation not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse server's handshake message
 * @param[in] context Pointer to the TLS context
 * @param[in] msgType Handshake message type
 * @param[in] message Pointer to the handshake message to parse
 * @param[in] length Length of the handshake messaged
 * @return Error code
 **/

error_t tlsParseServerHandshakeMessage(TlsContext *context, uint8_t msgType,
   const void *message, size_t length)
{
#if (TLS_CLIENT_SUPPORT == ENABLED)
   error_t error;

   //Check handshake message type
   switch(msgType)
   {
   //HelloRequest message received?
   case TLS_TYPE_HELLO_REQUEST:
      //HelloRequest is a simple notification that the client should begin the
      //negotiation process anew
      error = tlsParseHelloRequest(context, message, length);
      break;

   //ServerHello message received?
   case TLS_TYPE_SERVER_HELLO:
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //For backward compatibility with middleboxes the HelloRetryRequest
      //message uses the same structure as the ServerHello, but with Random
      //field set to a special value
      if(tls13IsHelloRetryRequest(message, length))
      {
         //The server sends a HelloRetryRequest message if the ClientHello
         //message does not contain sufficient information to proceed with
         //the handshake
         error = tls13ParseHelloRetryRequest(context, message, length);
      }
      else
#endif
      {
         //The server will send this message in response to a ClientHello
         //message when it was able to find an acceptable set of algorithms
         error = tlsParseServerHello(context, message, length);
      }
      break;

   //Certificate message received?
   case TLS_TYPE_CERTIFICATE:
      //The server must send a Certificate message whenever the agreed-upon
      //key exchange method uses certificates for authentication. This message
      //will always immediately follow the ServerHello message
      error = tlsParseCertificate(context, message, length);
      break;

   //CertificateRequest message received?
   case TLS_TYPE_CERTIFICATE_REQUEST:
      //A non-anonymous server can optionally request a certificate from the
      //client, if appropriate for the selected cipher suite. This message,
      //if sent, will immediately follow the ServerKeyExchange message
      error = tlsParseCertificateRequest(context, message, length);
      break;

   //Finished message received?
   case TLS_TYPE_FINISHED:
      //A Finished message is always sent immediately after a ChangeCipherSpec
      //message to verify that the key exchange and authentication processes
      //were successful
      error = tlsParseFinished(context, message, length);
      break;

#if (DTLS_SUPPORT == ENABLED)
   //HelloVerifyRequest message received?
   case TLS_TYPE_HELLO_VERIFY_REQUEST:
      //When the client sends its ClientHello message to the server, the server
      //may respond with a HelloVerifyRequest message
      error = dtlsParseHelloVerifyRequest(context, message, length);
      break;
#endif

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //ServerKeyExchange message received?
   case TLS_TYPE_SERVER_KEY_EXCHANGE:
      //The ServerKeyExchange message is sent by the server only when the
      //server Certificate message (if sent) does not contain enough data
      //to allow the client to exchange a premaster secret
      error = tlsParseServerKeyExchange(context, message, length);
      break;

   //ServerHelloDone message received?
   case TLS_TYPE_SERVER_HELLO_DONE:
      //The ServerHelloDone message is sent by the server to indicate the end
      //of the ServerHello and associated messages
      error = tlsParseServerHelloDone(context, message, length);
      break;
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //EncryptedExtensions message received?
   case TLS_TYPE_ENCRYPTED_EXTENSIONS:
      //The server sends the EncryptedExtensions message immediately after
      //the ServerHello message. The EncryptedExtensions message contains
      //extensions that can be protected
      error = tls13ParseEncryptedExtensions(context, message, length);
      break;

   //CertificateVerify message received?
   case TLS_TYPE_CERTIFICATE_VERIFY:
      //Servers must send this message when authenticating via a certificate.
      //When sent, this message must appear immediately after the Certificate
      //message
      error = tlsParseCertificateVerify(context, message, length);
      break;

   //NewSessionTicket message received?
   case TLS_TYPE_NEW_SESSION_TICKET:
      //At any time after the server has received the client Finished message,
      //it may send a NewSessionTicket message
      error = tls13ParseNewSessionTicket(context, message, length);
      break;

   //KeyUpdate message received?
   case TLS_TYPE_KEY_UPDATE:
      //The KeyUpdate handshake message is used to indicate that the server
      //is updating its sending cryptographic keys. This message can be sent
      //by the server after it has sent a Finished message
      error = tls13ParseKeyUpdate(context, message, length);
      break;
#endif

   //Invalid handshake message received?
   default:
      //Report an error
      error = ERROR_UNEXPECTED_MESSAGE;
   }

   //Return status code
   return error;
#else
   //Client mode of operation not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
