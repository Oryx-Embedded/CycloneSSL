/**
 * @file tls_handshake.c
 * @brief TLS handshake protocol
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
#include "tls.h"
#include "tls_cipher_suites.h"
#include "tls_handshake.h"
#include "tls_handshake_hash.h"
#include "tls_client.h"
#include "tls_server.h"
#include "tls_common.h"
#include "tls_record.h"
#include "tls_cache.h"
#include "tls_misc.h"
#include "dtls_record.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Perform TLS handshake
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsHandshake(TlsContext *context)
{
   error_t error;

   //TLS operates as a client?
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Perform TLS handshake with the remote server
      error = tlsClientHandshake(context);
   }
   //TLS operates as a server?
   else if(context->entity == TLS_CONNECTION_END_SERVER)
   {
      //Perform TLS handshake with the remote client
      error = tlsServerHandshake(context);
   }
   //Unsupported mode of operation?
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
 *
 * TLS handshake protocol is responsible for the authentication
 * and key exchange necessary to establish a secure session
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsClientHandshake(TlsContext *context)
{
#if (TLS_CLIENT_SUPPORT == ENABLED)
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Wait for the handshake to complete
   do
   {
      //TLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
      {
         //Flush send buffer
         if(context->state != TLS_STATE_CLOSED)
            error = tlsWriteProtocolData(context, NULL, 0, TLS_TYPE_NONE);
      }

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
#else
   //Client mode of operation not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


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
#if (TLS_SERVER_SUPPORT == ENABLED)
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Wait for the handshake to complete
   do
   {
      //TLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
      {
         //Flush send buffer
         if(context->state != TLS_STATE_CLOSED)
            error = tlsWriteProtocolData(context, NULL, 0, TLS_TYPE_NONE);
      }

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
#if (DTLS_SUPPORT == ENABLED)
         //Sending HelloVerifyRequest message?
         case TLS_STATE_HELLO_VERIFY_REQUEST:
            //When the client sends its ClientHello message to the server, the
            //server may respond with a HelloVerifyRequest message
            error = dtlsSendHelloVerifyRequest(context);
            break;
#endif
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
#else
   //Server mode of operation not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse incoming handshake message
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsParseClientMessage(TlsContext *context)
{
#if (TLS_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   uint8_t *data;
   TlsContentType contentType;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //A message can be fragmented across several DTLS records...
      error = dtlsReadProtocolData(context, &data, &length, &contentType);
   }
   else
#endif
   //TLS protocol?
   {
      //A message can be fragmented across several TLS records...
      error = tlsReadProtocolData(context, &data, &length, &contentType);
   }

   //Check status code
   if(!error)
   {
      //Handshake message received?
      if(contentType == TLS_TYPE_HANDSHAKE)
      {
         size_t n;
         uint8_t msgType;
         void *message;

#if (DTLS_SUPPORT == ENABLED)
         //DTLS protocol?
         if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
         {
            //Retrieve handshake message type
            msgType = ((DtlsHandshake *) data)->msgType;
            //Point to the handshake message
            message = data + sizeof(DtlsHandshake);
            //Calculate the length of the handshake message
            n = length - sizeof(DtlsHandshake);
         }
         else
#endif
         //TLS protocol?
         {
            //Retrieve handshake message type
            msgType = ((TlsHandshake *) data)->msgType;
            //Point to the handshake message
            message = data + sizeof(TlsHandshake);
            //Calculate the length of the handshake message
            n = length - sizeof(TlsHandshake);
         }

         //Update the hash value with the incoming handshake message
         if(msgType == TLS_TYPE_CLIENT_KEY_EXCHANGE)
            tlsUpdateHandshakeHash(context, data, length);

         //Check handshake message type
         switch(msgType)
         {
         //ClientHello message received?
         case TLS_TYPE_CLIENT_HELLO:
            //When a client first connects to a server, it is required to send
            //the ClientHello as its first message
            error = tlsParseClientHello(context, message, n);
            break;
         //Certificate message received?
         case TLS_TYPE_CERTIFICATE:
            //This is the first message the client can send after receiving a
            //ServerHelloDone message. This message is only sent if the server
            //requests a certificate
            error = tlsParseCertificate(context, message, n);
            break;
         //ClientKeyExchange message received?
         case TLS_TYPE_CLIENT_KEY_EXCHANGE:
            //This message is always sent by the client. It must immediately
            //follow the client certificate message, if it is sent. Otherwise,
            //it must be the first message sent by the client after it receives
            //the ServerHelloDone message
            error = tlsParseClientKeyExchange(context, message, n);
            break;
         //CertificateVerify message received?
         case TLS_TYPE_CERTIFICATE_VERIFY:
            //This message is used to provide explicit verification of a client
            //certificate. This message is only sent following a client certificate
            //that has signing capability. When sent, it must immediately follow
            //the clientKeyExchange message
            error = tlsParseCertificateVerify(context, message, n);
            break;
         //Finished message received?
         case TLS_TYPE_FINISHED:
            //A Finished message is always sent immediately after a changeCipherSpec
            //message to verify that the key exchange and authentication processes
            //were successful
            error = tlsParseFinished(context, message, n);
            break;
         //Invalid handshake message received?
         default:
            //Report an error
            error = ERROR_UNEXPECTED_MESSAGE;
            break;
         }

         //Update the hash value with the incoming handshake message
         if(msgType != TLS_TYPE_CLIENT_KEY_EXCHANGE)
            tlsUpdateHandshakeHash(context, data, length);
      }
      //ChangeCipherSpec message received?
      else if(contentType == TLS_TYPE_CHANGE_CIPHER_SPEC)
      {
         //The ChangeCipherSpec message is sent by the client and to notify the
         //server that subsequent records will be protected under the newly
         //negotiated CipherSpec and keys
         error = tlsParseChangeCipherSpec(context, (TlsChangeCipherSpec *) data, length);
      }
      //Alert message received?
      else if(contentType == TLS_TYPE_ALERT)
      {
         //Parse Alert message
         error = tlsParseAlert(context, (TlsAlert *) data, length);
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
#else
   //Server mode of operation not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse incoming handshake message
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsParseServerMessage(TlsContext *context)
{
#if (TLS_CLIENT_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   uint8_t *data;
   TlsContentType contentType;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //A message can be fragmented across several records...
      error = dtlsReadProtocolData(context, &data, &length, &contentType);
   }
   else
#endif
   //TLS protocol?
   {
      //A message can be fragmented across several records...
      error = tlsReadProtocolData(context, &data, &length, &contentType);
   }

   //Check status code
   if(!error)
   {
      //Handshake message received?
      if(contentType == TLS_TYPE_HANDSHAKE)
      {
         size_t n;
         uint8_t msgType;
         void *message;

#if (DTLS_SUPPORT == ENABLED)
         //DTLS protocol?
         if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
         {
            //Retrieve handshake message type
            msgType = ((DtlsHandshake *) data)->msgType;
            //Point to the handshake message
            message = data + sizeof(DtlsHandshake);
            //Calculate the length of the handshake message
            n = length - sizeof(DtlsHandshake);
         }
         else
#endif
         //TLS protocol?
         {
            //Retrieve handshake message type
            msgType = ((TlsHandshake *) data)->msgType;
            //Point to the handshake message
            message = data + sizeof(TlsHandshake);
            //Calculate the length of the handshake message
            n = length - sizeof(TlsHandshake);
         }

         //Check handshake message type
         switch(msgType)
         {
         //HelloRequest message received?
         case TLS_TYPE_HELLO_REQUEST:
            //HelloRequest is a simple notification that the client should
            //begin the negotiation process anew
            error = tlsParseHelloRequest(context, message, n);
            break;
#if (DTLS_SUPPORT == ENABLED)
         //HelloVerifyRequest message received?
         case TLS_TYPE_HELLO_VERIFY_REQUEST:
            //When the client sends its ClientHello message to the server,
            //the server may respond with a HelloVerifyRequest message
            error = dtlsParseHelloVerifyRequest(context, message, n);
            break;
#endif
         //ServerHello message received?
         case TLS_TYPE_SERVER_HELLO:
            //The server will send this message in response to a ClientHello
            //message when it was able to find an acceptable set of algorithms
            error = tlsParseServerHello(context, message, n);
            break;
         //Certificate message received?
         case TLS_TYPE_CERTIFICATE:
            //The server must send a Certificate message whenever the agreed-
            //upon key exchange method uses certificates for authentication. This
            //message will always immediately follow the ServerHello message
            error = tlsParseCertificate(context, message, n);
            break;
         //ServerKeyExchange message received?
         case TLS_TYPE_SERVER_KEY_EXCHANGE:
            //The ServerKeyExchange message is sent by the server only when the
            //server Certificate message (if sent) does not contain enough data
            //to allow the client to exchange a premaster secret
            error = tlsParseServerKeyExchange(context, message, n);
            break;
         //CertificateRequest message received?
         case TLS_TYPE_CERTIFICATE_REQUEST:
            //A non-anonymous server can optionally request a certificate from the
            //client, if appropriate for the selected cipher suite. This message,
            //if sent, will immediately follow the ServerKeyExchange message
            error = tlsParseCertificateRequest(context, message, n);
            break;
         //ServerHelloDone message received?
         case TLS_TYPE_SERVER_HELLO_DONE:
            //The ServerHelloDone message is sent by the server to indicate the
            //end of the ServerHello and associated messages
            error = tlsParseServerHelloDone(context, message, n);
            break;
         //Finished message received?
         case TLS_TYPE_FINISHED:
            //A Finished message is always sent immediately after a changeCipherSpec
            //message to verify that the key exchange and authentication processes
            //were successful
            error = tlsParseFinished(context, message, n);
            break;
         //Invalid handshake message received?
         default:
            //Report an error
            error = ERROR_UNEXPECTED_MESSAGE;
         }

         //Update the hash value with the incoming handshake message
         tlsUpdateHandshakeHash(context, data, length);
      }
      //ChangeCipherSpec message received?
      else if(contentType == TLS_TYPE_CHANGE_CIPHER_SPEC)
      {
         //The ChangeCipherSpec message is sent by the server and to notify the
         //client that subsequent records will be protected under the newly
         //negotiated CipherSpec and keys
         error = tlsParseChangeCipherSpec(context, (TlsChangeCipherSpec *) data, length);
      }
      //Alert message received?
      else if(contentType == TLS_TYPE_ALERT)
      {
         //Parse Alert message
         error = tlsParseAlert(context, (TlsAlert *) data, length);
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
#else
   //Client mode of operation not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
