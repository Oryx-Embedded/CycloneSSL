/**
 * @file tls_common.c
 * @brief Handshake message processing (TLS client and server)
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
 * @version 1.8.2
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
#include "tls_server.h"
#include "tls_common.h"
#include "tls_record.h"
#include "tls_certificate.h"
#include "tls_cache.h"
#include "tls_misc.h"
#include "dtls_record.h"
#include "encoding/oid.h"
#include "certificate/pem_import.h"
#include "certificate/x509_cert_parse.h"
#include "certificate/x509_cert_validate.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Send Certificate message
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendCertificate(TlsContext *context)
{
   error_t error;
   size_t length;
   void *message;

   //Initialize status code
   error = NO_ERROR;

   //Point to the buffer where to format the message
   message = (void *) (context->txBuffer + context->txBufferLen);

#if (TLS_CLIENT_SUPPORT == ENABLED)
   //TLS operates as a client?
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //The client must send a Certificate message if the server requests it
      if(context->clientCertRequested)
      {
#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= SSL_VERSION_3_0)
         //No suitable certificate available?
         if(context->cert == NULL && context->version == SSL_VERSION_3_0)
         {
            //The client should send a no_certificate alert instead
            error = tlsSendAlert(context, TLS_ALERT_LEVEL_WARNING,
               TLS_ALERT_NO_CERTIFICATE);
         }
         else
#endif
         {
            //Format Certificate message
            error = tlsFormatCertificate(context, message, &length);

            //Check status code
            if(!error)
            {
               //Debug message
               TRACE_INFO("Sending Certificate message (%" PRIuSIZE " bytes)...\r\n", length);
               TRACE_DEBUG_ARRAY("  ", message, length);

               //Send handshake message
               error = tlsSendHandshakeMessage(context, message, length,
                  TLS_TYPE_CERTIFICATE);
            }
         }
      }
   }
   else
#endif
#if (TLS_SERVER_SUPPORT == ENABLED)
   //TLS operates as a server?
   if(context->entity == TLS_CONNECTION_END_SERVER)
   {
      //The server must send a Certificate message whenever the agreed-upon
      //key exchange method uses certificates for authentication
      if(context->cert != NULL)
      {
         //Format Certificate message
         error = tlsFormatCertificate(context, message, &length);

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_INFO("Sending Certificate message (%" PRIuSIZE " bytes)...\r\n", length);
            TRACE_DEBUG_ARRAY("  ", message, length);

            //Send handshake message
            error = tlsSendHandshakeMessage(context, message, length,
               TLS_TYPE_CERTIFICATE);
         }
      }
   }
   else
#endif
   //Unsupported mode of operation?
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Update FSM state
      if(context->entity == TLS_CONNECTION_END_CLIENT)
         context->state = TLS_STATE_CLIENT_KEY_EXCHANGE;
      else
         context->state = TLS_STATE_SERVER_KEY_EXCHANGE;
   }

   //Return status code
   return error;
}


/**
 * @brief Send ChangeCipherSpec message
 *
 * The change cipher spec message is sent by both the client and the
 * server to notify the receiving party that subsequent records will be
 * protected under the newly negotiated CipherSpec and keys
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendChangeCipherSpec(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsChangeCipherSpec *message;

   //Point to the buffer where to format the message
   message = (TlsChangeCipherSpec *) (context->txBuffer + context->txBufferLen);

   //Format ChangeCipherSpec message
   error = tlsFormatChangeCipherSpec(context, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending ChangeCipherSpec message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

#if (DTLS_SUPPORT == ENABLED)
      //DTLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
      {
         //Send ChangeCipherSpec message
         error = dtlsWriteProtocolData(context, (uint8_t *) message,
            length, TLS_TYPE_CHANGE_CIPHER_SPEC);
      }
      else
#endif
      //TLS protocol?
      {
         //Send ChangeCipherSpec message
         error = tlsWriteProtocolData(context, (uint8_t *) message,
            length, TLS_TYPE_CHANGE_CIPHER_SPEC);
      }
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
#if (DTLS_SUPPORT == ENABLED)
      //Release previous encryption engine first
      tlsFreeEncryptionEngine(&context->prevEncryptionEngine);

      //Save current encryption engine for later use
      context->prevEncryptionEngine = context->encryptionEngine;
      //Clear current encryption engine
      memset(&context->encryptionEngine, 0, sizeof(TlsEncryptionEngine));
#else
      //Release encryption engine first
      tlsFreeEncryptionEngine(&context->encryptionEngine);
#endif

      //Initialize encryption engine
      error = tlsInitEncryptionEngine(context, &context->encryptionEngine,
         context->entity);
   }

   //Check status code
   if(!error)
   {
      //Inform the record layer that subsequent records will be protected
      //under the newly negotiated encryption algorithm
      context->changeCipherSpecSent = TRUE;

      //Prepare to send a Finished message to the peer...
      if(context->entity == TLS_CONNECTION_END_CLIENT)
         context->state = TLS_STATE_CLIENT_FINISHED;
      else
         context->state = TLS_STATE_SERVER_FINISHED;
   }

   //Return status code
   return error;
}


/**
 * @brief Send Finished message
 *
 * A Finished message is always sent immediately after a change
 * cipher spec message to verify that the key exchange and
 * authentication processes were successful. It is essential that a
 * change cipher spec message be received between the other handshake
 * messages and the Finished message
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendFinished(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsFinished *message;

   //Point to the buffer where to format the message
   message = (TlsFinished *) (context->txBuffer + context->txBufferLen);

   //TLS operates as a client or a server?
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //The verify data is generated from all messages in this handshake
      //up to but not including the Finished message
      error = tlsComputeVerifyData(context, TLS_CONNECTION_END_CLIENT,
         context->clientVerifyData, &context->clientVerifyDataLen);
   }
   else
   {
      //The verify data is generated from all messages in this handshake
      //up to but not including the Finished message
      error = tlsComputeVerifyData(context, TLS_CONNECTION_END_SERVER,
         context->serverVerifyData, &context->serverVerifyDataLen);
   }

   //Check status code
   if(!error)
   {
      //Format Finished message
      error = tlsFormatFinished(context, message, &length);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending Finished message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsSendHandshakeMessage(context, message, length,
         TLS_TYPE_FINISHED);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //TLS operates as a client or a server?
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //Use abbreviated or full handshake?
         if(context->resume)
            context->state = TLS_STATE_APPLICATION_DATA;
         else
            context->state = TLS_STATE_SERVER_CHANGE_CIPHER_SPEC;
      }
      else
      {
         //Use abbreviated or full handshake?
         if(context->resume)
            context->state = TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC;
         else
            context->state = TLS_STATE_APPLICATION_DATA;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send Alert message
 * @param[in] context Pointer to the TLS context
 * @param[in] level Severity of the message (warning or fatal)
 * @param[in] description Description of the alert
 * @return Error code
 **/

error_t tlsSendAlert(TlsContext *context, uint8_t level, uint8_t description)
{
   error_t error;
   size_t length;
   TlsAlert *message;

   //Point to the buffer where to format the message
   message = (TlsAlert *) (context->txBuffer + context->txBufferLen);

   //Format Alert message
   error = tlsFormatAlert(context, level, description, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending Alert message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_INFO_ARRAY("  ", message, length);

#if (DTLS_SUPPORT == ENABLED)
      //DTLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
      {
         //Send Alert message
         error = dtlsWriteProtocolData(context, (uint8_t *) message,
            length, TLS_TYPE_ALERT);
      }
      else
#endif
      //TLS protocol?
      {
         //Send Alert message
         error = tlsWriteProtocolData(context, (uint8_t *) message,
            length, TLS_TYPE_ALERT);
      }
   }

   //Alert messages convey the severity of the message
   if(level == TLS_ALERT_LEVEL_WARNING)
   {
      //If an alert with a level of warning is sent, generally the
      //connection can continue normally
      if(description == TLS_ALERT_CLOSE_NOTIFY)
      {
         //Either party may initiate a close by sending a close_notify alert
         context->closeNotifySent = TRUE;

         //Update FSM state
         context->state = TLS_STATE_CLOSING;
      }
   }
   else if(level == TLS_ALERT_LEVEL_FATAL)
   {
      //Alert messages with a level of fatal result in the immediate
      //termination of the connection
      context->fatalAlertSent = TRUE;

      //Any connection terminated with a fatal alert must not be resumed
      if(context->entity == TLS_CONNECTION_END_SERVER)
         tlsRemoveFromCache(context);

      //Servers and clients must forget any session identifiers
      memset(context->sessionId, 0, 32);
      context->sessionIdLen = 0;

      //Update FSM state
      context->state = TLS_STATE_CLOSING;
   }

   //Return status code
   return error;
}


/**
 * @brief Format Certificate message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the Certificate message
 * @param[out] length Length of the resulting Certificate message
 * @return Error code
 **/

error_t tlsFormatCertificate(TlsContext *context,
   TlsCertificate *message, size_t *length)
{
   error_t error;
   size_t n;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //Check certificate type
   if(context->certFormat == TLS_CERT_FORMAT_RAW_PUBLIC_KEY)
   {
      //Format the raw public key
      error = tlsFormatRawPublicKey(context, message->certificateList, &n);
   }
   else
#endif
   {
      //Format the certificate chain
      error = tlsFormatCertificateList(context, message->certificateList, &n);
   }

   //Check status code
   if(!error)
   {
      //A 3-byte length field shall precede the certificate list
      STORE24BE(n, message->certificateListLen);
      //Length of the Certificate message
      *length = sizeof(TlsCertificate) + n;
   }

   //Return status code
   return error;
}


/**
 * @brief Format ChangeCipherSpec message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the ChangeCipherSpec message
 * @param[out] length Length of the resulting ChangeCipherSpec message
 * @return Error code
 **/

error_t tlsFormatChangeCipherSpec(TlsContext *context,
   TlsChangeCipherSpec *message, size_t *length)
{
   //The message consists of a single byte of value 1
   message->type = 1;

   //Length of the ChangeCipherSpec message
   *length = sizeof(TlsChangeCipherSpec);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format Finished message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the Finished message
 * @param[out] length Length of the resulting Finished message
 * @return Error code
 **/

error_t tlsFormatFinished(TlsContext *context,
   TlsFinished *message, size_t *length)
{
   //TLS operates as a client or a server?
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Copy the client's verify data
      memcpy(message, context->clientVerifyData, context->clientVerifyDataLen);
      //Length of the handshake message
      *length = context->clientVerifyDataLen;
   }
   else
   {
      //Copy the server's verify data
      memcpy(message, context->serverVerifyData, context->serverVerifyDataLen);
      //Length of the handshake message
      *length = context->serverVerifyDataLen;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format Alert message
 * @param[in] context Pointer to the TLS context
 * @param[in] level Severity of the message (warning or fatal)
 * @param[in] description Description of the alert
 * @param[out] message Buffer where to format the Alert message
 * @param[out] length Length of the resulting Alert message
 * @return Error code
 **/

error_t tlsFormatAlert(TlsContext *context, uint8_t level,
   uint8_t description, TlsAlert *message, size_t *length)
{
   //Severity of the message
   message->level = level;
   //Description of the alert
   message->description = description;

   //Length of the Alert message
   *length = sizeof(TlsAlert);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse Certificate message
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming Certificate message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseCertificate(TlsContext *context,
   const TlsCertificate *message, size_t length)
{
   error_t error;
   size_t n;

   //Debug message
   TRACE_INFO("Certificate message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check the length of the Certificate message
   if(length < sizeof(TlsCertificate))
      return ERROR_DECODING_FAILED;

   //TLS operates as a client or a server?
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Check current state
      if(context->state != TLS_STATE_SERVER_CERTIFICATE)
         return ERROR_UNEXPECTED_MESSAGE;
   }
   else
   {
      //Check current state
      if(context->state != TLS_STATE_CLIENT_CERTIFICATE)
         return ERROR_UNEXPECTED_MESSAGE;
   }

   //Get the size occupied by the certificate list
   n = LOAD24BE(message->certificateListLen);
   //Remaining bytes to process
   length -= sizeof(TlsCertificate);

   //Ensure that the chain of certificates is valid
   if(n != length)
      return ERROR_DECODING_FAILED;

   //Empty certificate list received by the server?
   if(context->entity == TLS_CONNECTION_END_SERVER && length == 0)
   {
      //Check whether mutual authentication is required
      if(context->clientAuthMode == TLS_CLIENT_AUTH_REQUIRED)
      {
         //If client authentication is required by the server for the handshake
         //to continue, it may respond with a fatal handshake failure alert
         error = ERROR_HANDSHAKE_FAILED;
      }
      else
      {
         //Client authentication is optional
         context->peerCertType = TLS_CERT_NONE;
         //Exit immediately
         error = NO_ERROR;
      }
   }
   else
   {
#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
      //Check certificate type
      if(context->peerCertFormat == TLS_CERT_FORMAT_RAW_PUBLIC_KEY)
      {
         //Parse the raw public key
         error = tlsParseRawPublicKey(context, message->certificateList, n);
      }
      else
#endif
      {
         //Parse the certificate chain
         error = tlsParseCertificateList(context, message->certificateList, n);
      }
   }

   //Check status code
   if(!error)
   {
      //TLS operates as a client or a server?
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //Update FSM state
         if(context->keyExchMethod == TLS_KEY_EXCH_RSA)
            context->state = TLS_STATE_CERTIFICATE_REQUEST;
         else
            context->state = TLS_STATE_SERVER_KEY_EXCHANGE;
      }
      else
      {
         //Prepare to receive ClientKeyExchange message...
         context->state = TLS_STATE_CLIENT_KEY_EXCHANGE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse ChangeCipherSpec message
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming ChangeCipherSpec message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseChangeCipherSpec(TlsContext *context,
   const TlsChangeCipherSpec *message, size_t length)
{
   error_t error;

   //Debug message
   TRACE_INFO("ChangeCipherSpec message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check the length of the ChangeCipherSpec message
   if(length != sizeof(TlsChangeCipherSpec))
      return ERROR_DECODING_FAILED;

   //The message consists of a single byte of value 1
   if(message->type != 0x01)
      return ERROR_DECODING_FAILED;

   //TLS operates as a client or a server?
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Check current state
      if(context->state != TLS_STATE_SERVER_CHANGE_CIPHER_SPEC)
         return ERROR_UNEXPECTED_MESSAGE;
   }
   else
   {
      //Check current state
      if(context->state != TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC)
         return ERROR_UNEXPECTED_MESSAGE;
   }

   //Inform the record layer that subsequent records will be protected
   //under the newly negotiated encryption algorithm
   context->changeCipherSpecReceived = TRUE;

   //Release decryption engine first
   tlsFreeEncryptionEngine(&context->decryptionEngine);

   //TLS operates as a client or a server?
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Initialize decryption engine using server write keys
      error = tlsInitEncryptionEngine(context, &context->decryptionEngine,
         TLS_CONNECTION_END_SERVER);
      //Any error to report?
      if(error)
         return error;

      //Prepare to receive a Finished message from the server
      context->state = TLS_STATE_SERVER_FINISHED;
   }
   else
   {
      //Initialize decryption engine using client write keys
      error = tlsInitEncryptionEngine(context, &context->decryptionEngine,
         TLS_CONNECTION_END_CLIENT);
      //Any error to report?
      if(error)
         return error;

      //Prepare to receive a Finished message from the client
      context->state = TLS_STATE_CLIENT_FINISHED;
   }

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Initialize sliding window
      dtlsInitReplayWindow(context);
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse Finished message
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming Finished message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseFinished(TlsContext *context,
   const TlsFinished *message, size_t length)
{
   error_t error;

   //Debug message
   TRACE_INFO("Finished message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //TLS operates as a client or a server?
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Check current state
      if(context->state != TLS_STATE_SERVER_FINISHED)
         return ERROR_UNEXPECTED_MESSAGE;

      //The verify data is generated from all messages in this handshake
      //up to but not including the Finished message
      error = tlsComputeVerifyData(context, TLS_CONNECTION_END_SERVER,
         context->serverVerifyData, &context->serverVerifyDataLen);
      //Unable to generate the verify data?
      if(error)
         return error;

      //Check the length of the Finished message
      if(length != context->serverVerifyDataLen)
         return ERROR_INVALID_SIGNATURE;

      //Check the resulting verify data
      if(memcmp(message, context->serverVerifyData, context->serverVerifyDataLen))
         return ERROR_INVALID_SIGNATURE;

      //Use abbreviated or full handshake?
      if(context->resume)
         context->state = TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC;
      else
         context->state = TLS_STATE_APPLICATION_DATA;
   }
   else
   {
      //Check current state
      if(context->state != TLS_STATE_CLIENT_FINISHED)
         return ERROR_UNEXPECTED_MESSAGE;

      //The verify data is generated from all messages in this handshake
      //up to but not including the Finished message
      error = tlsComputeVerifyData(context, TLS_CONNECTION_END_CLIENT,
         context->clientVerifyData, &context->clientVerifyDataLen);
      //Unable to generate the verify data?
      if(error)
         return error;

      //Check the length of the Finished message
      if(length != context->clientVerifyDataLen)
         return ERROR_INVALID_SIGNATURE;

      //Check the resulting verify data
      if(memcmp(message, context->clientVerifyData, context->clientVerifyDataLen))
         return ERROR_INVALID_SIGNATURE;

      //Use abbreviated or full handshake?
      if(context->resume)
         context->state = TLS_STATE_APPLICATION_DATA;
      else
         context->state = TLS_STATE_SERVER_CHANGE_CIPHER_SPEC;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse Alert message
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming Alert message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseAlert(TlsContext *context,
   const TlsAlert *message, size_t length)
{
   //Debug message
   TRACE_INFO("Alert message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_INFO_ARRAY("  ", message, length);

   //Check message length
   if(length != sizeof(TlsAlert))
      return ERROR_INVALID_LENGTH;

   //Debug message
   TRACE_DEBUG("  Level = %" PRIu8 "\r\n", message->level);
   TRACE_DEBUG("  Description = %" PRIu8 "\r\n", message->description);

   //Alert messages convey the severity of the message
   if(message->level == TLS_ALERT_LEVEL_WARNING)
   {
#if (TLS_MAX_WARNING_ALERTS > 0)
      //Increment the count of consecutive warning alerts
      context->alertCount++;

      //Do not allow too many consecutive warning alerts
      if(context->alertCount > TLS_MAX_WARNING_ALERTS)
         return ERROR_UNEXPECTED_MESSAGE;
#endif

      //Closure alert received?
      if(message->description == TLS_ALERT_CLOSE_NOTIFY)
      {
         //A closure alert has been received
         context->closeNotifyReceived = TRUE;

         //Close down the connection immediately
         if(context->state == TLS_STATE_APPLICATION_DATA)
            context->state = TLS_STATE_CLOSING;
      }
   }
   else if(message->level == TLS_ALERT_LEVEL_FATAL)
   {
      //A fatal alert message has been received
      context->fatalAlertReceived = TRUE;

      //Any connection terminated with a fatal alert must not be resumed
      if(context->entity == TLS_CONNECTION_END_SERVER)
         tlsRemoveFromCache(context);

      //Servers and clients must forget any session identifiers
      memset(context->sessionId, 0, 32);
      context->sessionIdLen = 0;

      //Alert messages with a level of fatal result in the immediate
      //termination of the connection
      context->state = TLS_STATE_CLOSED;
   }
   else
   {
      //Report an error
      return ERROR_ILLEGAL_PARAMETER;
   }

   //Successful processing
   return NO_ERROR;
}

#endif
