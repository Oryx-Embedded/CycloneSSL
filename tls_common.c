/**
 * @file tls_common.c
 * @brief Handshake message processing (TLS client and server)
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
#include "tls_handshake.h"
#include "tls_client.h"
#include "tls_server.h"
#include "tls_common.h"
#include "tls_certificate.h"
#include "tls_sign_generate.h"
#include "tls_sign_verify.h"
#include "tls_transcript_hash.h"
#include "tls_cache.h"
#include "tls_record.h"
#include "tls_misc.h"
#include "tls13_sign_generate.h"
#include "tls13_sign_verify.h"
#include "dtls_record.h"
#include "pkix/pem_import.h"
#include "pkix/x509_cert_parse.h"
#include "debug.h"

//Check TLS library configuration
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
   TlsCertificate *message;

   //Initialize status code
   error = NO_ERROR;

   //Point to the buffer where to format the message
   message = (TlsCertificate *) (context->txBuffer + context->txBufferLen);

#if (TLS_CLIENT_SUPPORT == ENABLED)
   //Client mode?
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //The client must send a Certificate message if the server requests it
      if(context->clientCertRequested)
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
#if (TLS_SERVER_SUPPORT == ENABLED)
   //Server mode?
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
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
         //Check whether TLS operates as a client or a server
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            tlsChangeState(context, TLS_STATE_CLIENT_KEY_EXCHANGE);
         }
         else
         {
            tlsChangeState(context, TLS_STATE_SERVER_KEY_EXCHANGE);
         }
      }
      else
      {
         //Check whether TLS operates as a client or a server
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            //Clients must send a CertificateVerify message whenever
            //authenticating via a certificate
            if(context->clientCertRequested)
            {
               tlsChangeState(context, TLS_STATE_CLIENT_CERTIFICATE_VERIFY);
            }
            else
            {
               tlsChangeState(context, TLS_STATE_CLIENT_FINISHED);
            }
         }
         else
         {
            //Servers must send a CertificateVerify message whenever
            //authenticating via a certificate
            tlsChangeState(context, TLS_STATE_SERVER_CERTIFICATE_VERIFY);
         }
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

   //The CertificateVerify message is only sent following a client certificate
   //that has signing capability
   if(context->cert != NULL)
   {
      //Check certificate type
      if(context->cert->type == TLS_CERT_RSA_SIGN ||
         context->cert->type == TLS_CERT_RSA_PSS_SIGN ||
         context->cert->type == TLS_CERT_DSS_SIGN ||
         context->cert->type == TLS_CERT_ECDSA_SIGN ||
         context->cert->type == TLS_CERT_SM2_SIGN ||
         context->cert->type == TLS_CERT_ED25519_SIGN ||
         context->cert->type == TLS_CERT_ED448_SIGN)
      {
         //Point to the buffer where to format the message
         message = (TlsCertificateVerify *) (context->txBuffer + context->txBufferLen);

         //Format CertificateVerify message
         error = tlsFormatCertificateVerify(context, message, &length);

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_INFO("Sending CertificateVerify message (%" PRIuSIZE " bytes)...\r\n", length);
            TRACE_DEBUG_ARRAY("  ", message, length);

            //Send handshake message
            error = tlsSendHandshakeMessage(context, message, length,
               TLS_TYPE_CERTIFICATE_VERIFY);
         }
      }
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
         //Send a ChangeCipherSpec message to the server
         tlsChangeState(context, TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC);
      }
      else
      {
         //Send a Finished message to the peer
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            tlsChangeState(context, TLS_STATE_CLIENT_FINISHED);
         }
         else
         {
            tlsChangeState(context, TLS_STATE_SERVER_FINISHED);
         }
      }
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
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
#if (DTLS_SUPPORT == ENABLED)
         //Release previous encryption engine first
         tlsFreeEncryptionEngine(&context->prevEncryptionEngine);

         //Save current encryption engine for later use
         context->prevEncryptionEngine = context->encryptionEngine;

         //Reset encryption engine
         osMemset(&context->encryptionEngine, 0, sizeof(TlsEncryptionEngine));
         context->encryptionEngine.epoch = context->prevEncryptionEngine.epoch;
#else
         //Release encryption engine first
         tlsFreeEncryptionEngine(&context->encryptionEngine);
#endif

         //Inform the record layer that subsequent records will be protected
         //under the newly negotiated encryption algorithm
         error = tlsInitEncryptionEngine(context, &context->encryptionEngine,
            context->entity, NULL);

         //Check status code
         if(!error)
         {
            //Send a Finished message to the peer
            if(context->entity == TLS_CONNECTION_END_CLIENT)
            {
               tlsChangeState(context, TLS_STATE_CLIENT_FINISHED);
            }
            else
            {
               tlsChangeState(context, TLS_STATE_SERVER_FINISHED);
            }
         }
      }
      else
      {
#if (TLS13_MIDDLEBOX_COMPAT_SUPPORT == ENABLED)
         //The middlebox compatibility mode improves the chance of successfully
         //connecting through middleboxes
         if(context->state == TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC ||
            context->state == TLS_STATE_SERVER_CHANGE_CIPHER_SPEC_2)
         {
            //The client can send its second flight
            tlsChangeState(context, TLS_STATE_CLIENT_HELLO_2);
         }
         else if(context->state == TLS_STATE_SERVER_CHANGE_CIPHER_SPEC ||
            context->state == TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC_2)
         {
            //All handshake messages after the ServerHello are now encrypted
            tlsChangeState(context, TLS_STATE_HANDSHAKE_TRAFFIC_KEYS);
         }
         else
#endif
         {
            //Middlebox compatibility mode is not implemented
            error = ERROR_UNEXPECTED_STATE;
         }
      }
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

   //Check whether TLS operates as a client or a server
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
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
         //Check whether TLS operates as a client or a server
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            //Abbreviated or full handshake?
            if(context->resume)
            {
               //The client and server can now exchange application-layer data
               tlsChangeState(context, TLS_STATE_APPLICATION_DATA);
            }
            else
            {
#if (TLS_TICKET_SUPPORT == ENABLED)
               //The server uses the SessionTicket extension to indicate to
               //the client that it will send a new session ticket using the
               //NewSessionTicket handshake message
               if(context->sessionTicketExtReceived)
               {
                  //Wait for a NewSessionTicket message from the server
                  tlsChangeState(context, TLS_STATE_NEW_SESSION_TICKET);
               }
               else
#endif
               {
                  //Wait for a ChangeCipherSpec message from the server
                  tlsChangeState(context, TLS_STATE_SERVER_CHANGE_CIPHER_SPEC);
               }
            }
         }
         else
         {
            //Abbreviated or full handshake?
            if(context->resume)
            {
               //Wait for a ChangeCipherSpec message from the client
               tlsChangeState(context, TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC);
            }
            else
            {
               //The client and server can now exchange application-layer data
               tlsChangeState(context, TLS_STATE_APPLICATION_DATA);
            }
         }
      }
      else
      {
         //Check whether TLS operates as a client or a server
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            //Compute client application traffic keys
            tlsChangeState(context, TLS_STATE_CLIENT_APP_TRAFFIC_KEYS);
         }
         else
         {
            //Compute server application traffic keys
            tlsChangeState(context, TLS_STATE_SERVER_APP_TRAFFIC_KEYS);
         }
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
         tlsChangeState(context, TLS_STATE_CLOSING);
      }
   }
   else if(level == TLS_ALERT_LEVEL_FATAL)
   {
      //Alert messages with a level of fatal result in the immediate
      //termination of the connection
      context->fatalAlertSent = TRUE;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //Any connection terminated with a fatal alert must not be resumed
      if(context->entity == TLS_CONNECTION_END_SERVER)
      {
         tlsRemoveFromCache(context);
      }
#endif

      //Servers and clients must forget any session identifiers
      osMemset(context->sessionId, 0, 32);
      context->sessionIdLen = 0;

      //Update FSM state
      tlsChangeState(context, TLS_STATE_CLOSING);
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
   uint8_t *p;
   TlsCertList *certList;

   //Point to the beginning of the handshake message
   p = message;
   //Length of the handshake message
   *length = 0;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      Tls13CertRequestContext *certRequestContext;

      //Point to the certificate request context
      certRequestContext = (Tls13CertRequestContext *) p;

      //Check whether TLS operates as a client or a server
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //The value of the certificate_request_context field from server's
         //CertificateRequest message is echoed in the Certificate message
         if(context->certRequestContextLen > 0)
         {
            //Copy certificate request context
            osMemcpy(certRequestContext->value, context->certRequestContext,
               context->certRequestContextLen);
         }

         //The context is preceded by a length field
         certRequestContext->length = (uint8_t) context->certRequestContextLen;
      }
      else
      {
         //In the case of server authentication, this field shall be zero length
         certRequestContext->length = 0;
      }

      //Point to the next field
      p += sizeof(Tls13CertRequestContext) + certRequestContext->length;
      //Adjust the length of the Certificate message
      *length += sizeof(Tls13CertRequestContext) + certRequestContext->length;
   }
#endif

   //Point to the chain of certificates
   certList = (TlsCertList *) p;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //Check certificate type
   if(context->certFormat == TLS_CERT_FORMAT_RAW_PUBLIC_KEY)
   {
      //Format the raw public key
      error = tlsFormatRawPublicKey(context, certList->value, &n);
   }
   else
#endif
   {
      //Format the certificate chain
      error = tlsFormatCertificateList(context, certList->value, &n);
   }

   //Check status code
   if(!error)
   {
      //A 3-byte length field shall precede the certificate list
      STORE24BE(n, certList->length);
      //Adjust the length of the Certificate message
      *length += sizeof(TlsCertList) + n;
   }

   //Return status code
   return error;
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

   //Length of the handshake message
   *length = 0;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //TLS 1.0 or TLS 1.1 currently selected?
   if(context->version <= TLS_VERSION_1_1)
   {
      //In TLS version prior to 1.2, the digitally-signed element combines
      //MD5 and SHA-1
      error = tlsGenerateSignature(context, message, length);
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      //In TLS 1.2, the MD5/SHA-1 combination in the digitally-signed element
      //has been replaced with a single hash. The signed element now includes
      //a field that explicitly specifies the hash algorithm used
      error = tls12GenerateSignature(context, message, length);
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      //In TLS 1.3, the signed element specifies the signature algorithm used.
      //The content that is covered under the signature is the transcript hash
      //output
      error = tls13GenerateSignature(context, message, length);
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
   //Check whether TLS operates as a client or a server
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Copy the client's verify data
      osMemcpy(message, context->clientVerifyData, context->clientVerifyDataLen);
      //Length of the handshake message
      *length = context->clientVerifyDataLen;
   }
   else
   {
      //Copy the server's verify data
      osMemcpy(message, context->serverVerifyData, context->serverVerifyDataLen);
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
 * @brief Format CertificateAuthorities extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the CertificateAuthorities extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatCertAuthoritiesExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   error_t error;
   size_t n;
   TlsExtension *extension;

   //Add the CertificateAuthorities extension
   extension = (TlsExtension *) p;
   //Type of the extension
   extension->type = HTONS(TLS_EXT_CERTIFICATE_AUTHORITIES);

   //The CertificateAuthorities extension is used to indicate the certificate
   //authorities (CAs) which an endpoint supports and which should be used by
   //the receiving endpoint to guide certificate selection
   error = tlsFormatCertAuthorities(context, extension->value, &n);

   //Check status code
   if(!error)
   {
      //The list must contains at least one distinguished name
      if(n > sizeof(TlsCertAuthorities))
      {
         //Fix the length of the extension
         extension->length = htons(n);

         //Compute the length, in bytes, of the CertificateAuthorities extension
         n += sizeof(TlsExtension);
      }
      else
      {
         //The list of distinguished names is empty
         n = 0;
      }

      //Total number of bytes that have been written
      *written = n;
   }

   //Return status code
   return error;
}


/**
 * @brief Format the list of distinguished names of acceptable CAs
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the list of distinguished names
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatCertAuthorities(TlsContext *context, uint8_t *p,
   size_t *written)
{
   error_t error;
   size_t n;
   size_t pemCertLen;
   const char_t *trustedCaList;
   size_t trustedCaListLen;
   uint8_t *derCert;
   size_t derCertLen;
   X509CertInfo *certInfo;
   TlsCertAuthorities *certAuthorities;

   //Initialize status code
   error = NO_ERROR;

   //The list contains the distinguished names of acceptable certificate
   //authorities, represented in DER-encoded format
   certAuthorities = (TlsCertAuthorities *) p;

   //Point to the first certificate authority
   p = certAuthorities->value;
   //Length of the list in bytes
   n = 0;

   //Point to the first trusted CA certificate
   trustedCaList = context->trustedCaList;
   //Get the total length, in bytes, of the trusted CA list
   trustedCaListLen = context->trustedCaListLen;

   //Allocate a memory buffer to store X.509 certificate info
   certInfo = tlsAllocMem(sizeof(X509CertInfo));

   //Successful memory allocation?
   if(certInfo != NULL)
   {
      //Loop through the list of trusted CA certificates
      while(trustedCaListLen > 0 && error == NO_ERROR)
      {
         //The first pass calculates the length of the DER-encoded certificate
         error = pemImportCertificate(trustedCaList, trustedCaListLen, NULL,
            &derCertLen, &pemCertLen);

         //Check status code
         if(!error)
         {
            //Allocate a memory buffer to hold the DER-encoded certificate
            derCert = tlsAllocMem(derCertLen);

            //Successful memory allocation?
            if(derCert != NULL)
            {
               //The second pass decodes the PEM certificate
               error = pemImportCertificate(trustedCaList, trustedCaListLen,
                  derCert, &derCertLen, NULL);

               //Check status code
               if(!error)
               {
                  //Parse X.509 certificate
                  error = x509ParseCertificate(derCert, derCertLen, certInfo);
               }

               //Valid CA certificate?
               if(!error)
               {
                  //Each distinguished name is preceded by a 2-byte length field
                  STORE16BE(certInfo->tbsCert.subject.raw.length, p);

                  //The distinguished name shall be DER-encoded
                  osMemcpy(p + 2, certInfo->tbsCert.subject.raw.value,
                     certInfo->tbsCert.subject.raw.length);

                  //Advance write pointer
                  p += certInfo->tbsCert.subject.raw.length + 2;
                  n += certInfo->tbsCert.subject.raw.length + 2;
               }
               else
               {
                  //Discard current CA certificate
                  error = NO_ERROR;
               }

               //Free previously allocated memory
               tlsFreeMem(derCert);
            }
            else
            {
               //Failed to allocate memory
               error = ERROR_OUT_OF_MEMORY;
            }

            //Advance read pointer
            trustedCaList += pemCertLen;
            trustedCaListLen -= pemCertLen;
         }
         else
         {
            //End of file detected
            trustedCaListLen = 0;
            error = NO_ERROR;
         }
      }

      //Fix the length of the list
      certAuthorities->length = htons(n);

      //Free previously allocated memory
      tlsFreeMem(certInfo);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Check status code
   if(!error)
   {
      //Total number of bytes that have been written
      *written = sizeof(TlsCertAuthorities) + n;
   }

   //Return status code
   return error;
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
   const uint8_t *p;
   const TlsCertList *certList;

   //Debug message
   TRACE_INFO("Certificate message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check whether TLS operates as a client or a server
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
         //Check current state
         if(context->state != TLS_STATE_SERVER_CERTIFICATE)
            return ERROR_UNEXPECTED_MESSAGE;
      }
      else
      {
         //The CertificateRequest message is optional
         if(context->state != TLS_STATE_CERTIFICATE_REQUEST &&
            context->state != TLS_STATE_SERVER_CERTIFICATE)
         {
            return ERROR_UNEXPECTED_MESSAGE;
         }
      }
   }
   else
   {
      //Check current state
      if(context->state != TLS_STATE_CLIENT_CERTIFICATE)
         return ERROR_UNEXPECTED_MESSAGE;
   }

   //Point to the beginning of the handshake message
   p = message;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      const Tls13CertRequestContext *certRequestContext;

      //Point to the certificate request context
      certRequestContext = (Tls13CertRequestContext *) p;

      //Malformed Certificate message?
      if(length < sizeof(Tls13CertRequestContext))
         return ERROR_DECODING_FAILED;
      if(length < (sizeof(Tls13CertRequestContext) + certRequestContext->length))
         return ERROR_DECODING_FAILED;

      //Point to the next field
      p += sizeof(Tls13CertRequestContext) + certRequestContext->length;
      //Remaining bytes to process
      length -= sizeof(Tls13CertRequestContext) + certRequestContext->length;
   }
#endif

   //Point to the chain of certificates
   certList = (TlsCertList *) p;

   //Malformed Certificate message?
   if(length < sizeof(TlsCertList))
      return ERROR_DECODING_FAILED;

   //Get the size occupied by the certificate list
   n = LOAD24BE(certList->length);
   //Remaining bytes to process
   length -= sizeof(TlsCertList);

   //Malformed Certificate message?
   if(n != length)
      return ERROR_DECODING_FAILED;

   //Non-empty certificate list?
   if(n > 0)
   {
#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
      //Check certificate type
      if(context->peerCertFormat == TLS_CERT_FORMAT_RAW_PUBLIC_KEY)
      {
         //Parse the raw public key
         error = tlsParseRawPublicKey(context, certList->value, n);
      }
      else
#endif
      {
         //Parse the certificate chain
         error = tlsParseCertificateList(context, certList->value, n);
      }
   }
   else
   {
#if (TLS_SERVER_SUPPORT == ENABLED)
      //Server mode?
      if(context->entity == TLS_CONNECTION_END_SERVER)
      {
         //Check whether client authentication is required
         if(context->clientAuthMode == TLS_CLIENT_AUTH_REQUIRED)
         {
            //Version of TLS prior to TLS 1.3?
            if(context->version <= TLS_VERSION_1_2)
            {
               //If the client does not send any certificates, the server
               //responds with a fatal handshake_failure alert (refer to
               //RFC 5246, section 7.4.6)
               error = ERROR_HANDSHAKE_FAILED;
            }
            else
            {
               //If the client does not send any certificates, the server
               //aborts the handshake with a certificate_required alert (refer
               //to RFC 8446, section 4.4.2.4)
               error = ERROR_CERTIFICATE_REQUIRED;
            }
         }
         else
         {
            //The client did not send any certificates
            context->peerCertType = TLS_CERT_NONE;
            //The server may continue the handshake without client authentication
            error = NO_ERROR;
         }
      }
      else
#endif
      //Client mode?
      {
         //The server's certificate list must always be non-empty (refer to
         //RFC 8446, section 4.4.2)
         error = ERROR_DECODING_FAILED;
      }
   }

   //Check status code
   if(!error)
   {
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
         //Check whether TLS operates as a client or a server
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            //The server does not send a ServerKeyExchange message when RSA
            //key exchange method is used
            if(context->keyExchMethod == TLS_KEY_EXCH_RSA)
            {
               tlsChangeState(context, TLS_STATE_CERTIFICATE_REQUEST);
            }
            else
            {
               tlsChangeState(context, TLS_STATE_SERVER_KEY_EXCHANGE);
            }
         }
         else
         {
            //Wait for a ClientKeyExchange message from the client
            tlsChangeState(context, TLS_STATE_CLIENT_KEY_EXCHANGE);
         }
      }
      else
      {
         //Check whether TLS operates as a client or a server
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            //The server must send a CertificateVerify message immediately
            //after the Certificate message
            tlsChangeState(context, TLS_STATE_SERVER_CERTIFICATE_VERIFY);
         }
         else
         {
            //The client must send a CertificateVerify message when the
            //Certificate message is non-empty
            if(context->peerCertType != TLS_CERT_NONE)
            {
               tlsChangeState(context, TLS_STATE_CLIENT_CERTIFICATE_VERIFY);
            }
            else
            {
               tlsChangeState(context, TLS_STATE_CLIENT_FINISHED);
            }
         }
      }
   }

   //Return status code
   return error;
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

error_t tlsParseCertificateVerify(TlsContext *context,
   const TlsCertificateVerify *message, size_t length)
{
   error_t error;

   //Debug message
   TRACE_INFO("CertificateVerify message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check whether TLS operates as a client or a server
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      //Check current state
      if(context->state != TLS_STATE_SERVER_CERTIFICATE_VERIFY)
         return ERROR_UNEXPECTED_MESSAGE;
   }
   else
   {
      //Check current state
      if(context->state != TLS_STATE_CLIENT_CERTIFICATE_VERIFY)
         return ERROR_UNEXPECTED_MESSAGE;
   }

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //TLS 1.0 or TLS 1.1 currently selected?
   if(context->version <= TLS_VERSION_1_1)
   {
      //In TLS version prior to 1.2, the digitally-signed element combines
      //MD5 and SHA-1
      error = tlsVerifySignature(context, message, length);
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      //In TLS 1.2, the MD5/SHA-1 combination in the digitally-signed element
      //has been replaced with a single hash. The signed element now includes
      //a field that explicitly specifies the hash algorithm used
      error = tls12VerifySignature(context, message, length);
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      //In TLS 1.3, the signed element specifies the signature algorithm used.
      //The content that is covered under the signature is the transcript hash
      //output
      error = tls13VerifySignature(context, message, length);
   }
   else
#endif
   //Invalid TLS version?
   {
      //Report an error
      error = ERROR_INVALID_VERSION;
   }

   //Check status code
   if(!error)
   {
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
         //Wait for a ChangeCipherSpec message from the client
         tlsChangeState(context, TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC);
      }
      else
      {
         //Wait for a Finished message from the peer
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            tlsChangeState(context, TLS_STATE_SERVER_FINISHED);
         }
         else
         {
            tlsChangeState(context, TLS_STATE_CLIENT_FINISHED);
         }
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

   //Version of TLS prior to TLS 1.3?
   if(context->version <= TLS_VERSION_1_2)
   {
      //Check whether TLS operates as a client or a server
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

      //Release decryption engine first
      tlsFreeEncryptionEngine(&context->decryptionEngine);

      //Check whether TLS operates as a client or a server
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //Initialize decryption engine using server write keys
         error = tlsInitEncryptionEngine(context, &context->decryptionEngine,
            TLS_CONNECTION_END_SERVER, NULL);
         //Any error to report?
         if(error)
            return error;

         //Wait for a Finished message from the server
         tlsChangeState(context, TLS_STATE_SERVER_FINISHED);
      }
      else
      {
         //Initialize decryption engine using client write keys
         error = tlsInitEncryptionEngine(context, &context->decryptionEngine,
            TLS_CONNECTION_END_CLIENT, NULL);
         //Any error to report?
         if(error)
            return error;

         //Wait for a Finished message from the client
         tlsChangeState(context, TLS_STATE_CLIENT_FINISHED);
      }

#if (DTLS_SUPPORT == ENABLED)
      //DTLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
      {
         //Initialize sliding window
         dtlsInitReplayWindow(context);
      }
#endif
   }
   else
   {
      //In TLS 1.3, the ChangeCipherSpec message is used only for compatibility
      //purposes and must be dropped without further processing
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //A ChangeCipherSpec message received received before the first
         //ClientHello message or after the server's Finished message must
         //be treated as an unexpected record type
         if(context->state != TLS_STATE_SERVER_HELLO &&
            context->state != TLS_STATE_SERVER_HELLO_2 &&
            context->state != TLS_STATE_ENCRYPTED_EXTENSIONS &&
            context->state != TLS_STATE_CERTIFICATE_REQUEST &&
            context->state != TLS_STATE_SERVER_CERTIFICATE &&
            context->state != TLS_STATE_SERVER_CERTIFICATE_VERIFY &&
            context->state != TLS_STATE_SERVER_FINISHED)
         {
            //Report an error
            return ERROR_UNEXPECTED_MESSAGE;
         }
      }
      else
      {
         //A ChangeCipherSpec message received received before the first
         //ClientHello message or after the client's Finished message must
         //be treated as an unexpected record type
         if(context->state != TLS_STATE_CLIENT_HELLO_2 &&
            context->state != TLS_STATE_CLIENT_CERTIFICATE &&
            context->state != TLS_STATE_CLIENT_CERTIFICATE_VERIFY &&
            context->state != TLS_STATE_CLIENT_FINISHED)
         {
            //Report an error
            return ERROR_UNEXPECTED_MESSAGE;
         }
      }

#if (TLS_MAX_CHANGE_CIPHER_SPEC_MESSAGES > 0)
      //Increment the count of consecutive ChangeCipherSpec messages
      context->changeCipherSpecCount++;

      //Do not allow too many consecutive ChangeCipherSpec messages
      if(context->changeCipherSpecCount > TLS_MAX_CHANGE_CIPHER_SPEC_MESSAGES)
         return ERROR_UNEXPECTED_MESSAGE;
#endif
   }

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

   //Check whether TLS operates as a client or a server
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
      {
#if (TLS_MAX_EMPTY_RECORDS > 0)
         return ERROR_INVALID_SIGNATURE;
#else
         return ERROR_DECODING_FAILED;
#endif
      }

      //Check the resulting verify data
      if(osMemcmp(message, context->serverVerifyData, context->serverVerifyDataLen))
         return ERROR_INVALID_SIGNATURE;
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
      {
#if (TLS_MAX_EMPTY_RECORDS > 0)
         return ERROR_INVALID_SIGNATURE;
#else
         return ERROR_DECODING_FAILED;
#endif
      }

      //Check the resulting verify data
      if(osMemcmp(message, context->clientVerifyData, context->clientVerifyDataLen))
         return ERROR_INVALID_SIGNATURE;
   }

   //Version of TLS prior to TLS 1.3?
   if(context->version <= TLS_VERSION_1_2)
   {
      //Another handshake message cannot be packed in the same record as the
      //Finished
      if(context->rxBufferLen != 0)
         return ERROR_UNEXPECTED_MESSAGE;

      //Check whether TLS operates as a client or a server
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //Abbreviated or full handshake?
         if(context->resume)
         {
            //Send a ChangeCipherSpec message to the server
            tlsChangeState(context, TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC);
         }
         else
         {
            //The client and server can now exchange application-layer data
            tlsChangeState(context, TLS_STATE_APPLICATION_DATA);
         }
      }
      else
      {
         //Abbreviated or full handshake?
         if(context->resume)
         {
            //The client and server can now exchange application-layer data
            tlsChangeState(context, TLS_STATE_APPLICATION_DATA);
         }
         else
         {
#if (TLS_TICKET_SUPPORT == ENABLED)
            //The server uses the SessionTicket extension to indicate to
            //the client that it will send a new session ticket using the
            //NewSessionTicket handshake message
            if(context->sessionTicketExtSent)
            {
               //Send a NewSessionTicket message to the client
               tlsChangeState(context, TLS_STATE_NEW_SESSION_TICKET);
            }
            else
#endif
            {
               //Send a ChangeCipherSpec message to the client
               tlsChangeState(context, TLS_STATE_SERVER_CHANGE_CIPHER_SPEC);
            }
         }
      }
   }
   else
   {
      //Check whether TLS operates as a client or a server
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //Compute server application traffic keys
         tlsChangeState(context, TLS_STATE_SERVER_APP_TRAFFIC_KEYS);
      }
      else
      {
         //Compute client application traffic keys
         tlsChangeState(context, TLS_STATE_CLIENT_APP_TRAFFIC_KEYS);
      }
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

      //Check alert type
      if(message->description == TLS_ALERT_CLOSE_NOTIFY)
      {
         //A closure alert has been received
         context->closeNotifyReceived = TRUE;

         //Close down the connection immediately
         if(context->state == TLS_STATE_APPLICATION_DATA)
         {
            tlsChangeState(context, TLS_STATE_CLOSING);
         }
      }
      else if(message->description == TLS_ALERT_USER_CANCELED)
      {
         //This alert notifies the recipient that the sender is canceling the
         //handshake for some reason unrelated to a protocol failure
      }
      else
      {
         //TLS 1.3 currently selected?
         if(context->version == TLS_VERSION_1_3)
         {
            //Unknown alert types must be treated as error alerts
            return ERROR_DECODING_FAILED;
         }
      }
   }
   else if(message->level == TLS_ALERT_LEVEL_FATAL)
   {
      //A fatal alert message has been received
      context->fatalAlertReceived = TRUE;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //Any connection terminated with a fatal alert must not be resumed
      if(context->entity == TLS_CONNECTION_END_SERVER)
      {
         tlsRemoveFromCache(context);
      }
#endif

      //Servers and clients must forget any session identifiers
      osMemset(context->sessionId, 0, 32);
      context->sessionIdLen = 0;

      //Alert messages with a level of fatal result in the immediate
      //termination of the connection
      tlsChangeState(context, TLS_STATE_CLOSED);
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
