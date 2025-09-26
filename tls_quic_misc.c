/**
 * @file tls_quic_misc.c
 * @brief QUIC helper functions
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
 * @section Description
 *
 * The TLS protocol provides communications security over the Internet. The
 * protocol allows client/server applications to communicate in a way that
 * is designed to prevent eavesdropping, tampering, or message forgery
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include "tls.h"
#include "tls_quic_misc.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_QUIC_SUPPORT == ENABLED)


/**
 * @brief Format QuicTransportParameters extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the QuicTransportParameters extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatQuicTransportParamsExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n;
   TlsExtension *extension;

   //Initialize length field
   n = 0;

   //The QuicTransportParameters extension is carried in the ClientHello and the
   //EncryptedExtensions messages during the handshake. Endpoints must send the
   //QuicTransportParameters extension (refer to RFC 9001, section 8.2)
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_QUIC)
   {
      //Add the QuicTransportParameters extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_QUIC_TRANSPORT_PARAMETERS);

      //Get the length of the local QUIC transport parameters
      n = context->localQuicTransportParamsLen;

      //The extension_data field of the QuicTransportParameters extension
      //contains a value that is defined by the version of QUIC that is in use
      osMemcpy(extension->value, context->localQuicTransportParams, n);

      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the Cookie extension
      n += sizeof(TlsExtension);
   }

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse QuicTransportParameters extension
 * @param[in] context Pointer to the TLS context
 * @param[in] selectedIdentity Pointer to the QuicTransportParameters extension
 * @return Error code
 **/

error_t tlsParseQuicTransportParamsExtension(TlsContext *context,
   const TlsExtension *quicTransportParams)
{
   size_t length;

   //QUIC transport?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_QUIC)
   {
      //Endpoints must send the QuicTransportParameters extension (refer to
      //RFC 9001, section 8.2)
      if(quicTransportParams == NULL)
         return ERROR_MISSING_EXTENSION;

      //Check whether the QUIC transport parameters have already been received
      if(context->remoteQuicTransportParams != NULL)
      {
         //Release memory
         tlsFreeMem(context->remoteQuicTransportParams);
         context->remoteQuicTransportParams = NULL;
         context->remoteQuicTransportParamsLen = 0;
      }

      //Retrieve the length of the extension_data field
      length = ntohs(quicTransportParams->length);

      //Allocate a memory block to hold the QUIC transport parameters
      context->remoteQuicTransportParams = tlsAllocMem(length);
      //Failed to allocate memory?
      if(context->remoteQuicTransportParams == NULL)
         return ERROR_OUT_OF_MEMORY;

      //The extension_data field of the QuicTransportParameters extension
      //contains a value that is defined by the version of QUIC that is in use
      osMemcpy(context->remoteQuicTransportParams, quicTransportParams->value, length);
      context->remoteQuicTransportParamsLen = length;
   }
   else
   {
      //A fatal unsupported_extension alert must be sent by an implementation
      //that supports this extension if the extension is received when the
      //transport is not QUIC (refer to RFC 9001, section 8.2)
      if(quicTransportParams != NULL)
         return ERROR_UNSUPPORTED_EXTENSION;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set encryption keys
 * @param[in] context Pointer to the TLS context
 * @param[in] level Encryption level
 * @param[in] clientKey Client's secret key
 * @param[in] serverKey Server's secret key
 * @param[in] keyLen Length of the secret keys, in bytes
 * @return Error code
 **/

error_t tlsSetQuicEncryptionKeys(TlsContext *context, TlsEncryptionLevel level,
   const uint8_t *clientKey, const uint8_t *serverKey, size_t keyLen)
{
   error_t error;
   const uint8_t *txKey;
   const uint8_t *rxKey;

   //Check whether TLS operates as a client or a server
   if(context->entity == TLS_CONNECTION_END_CLIENT)
   {
      txKey = clientKey;
      rxKey = serverKey;
   }
   else
   {
      txKey = serverKey;
      rxKey = clientKey;
   }

   //Any registered callback?
   if(context->quicCallbacks.setEncryptionKeys != NULL)
   {
      //As keys at a given encryption level become available to TLS, TLS
      //indicates to QUIC that reading or writing keys at that encryption level
      //are available (refer to RFC 9001, section 4.1.4)
      error = context->quicCallbacks.setEncryptionKeys(context, level, txKey,
         rxKey, keyLen, context->quicHandle);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Send handshake message
 * @param[in] context Pointer to the TLS context
 * @param[in] message Pointer to the handshake message
 * @param[in] length Length of the handshake message, in bytes
 * @return Error code
 **/

error_t tlsSendQuicHandshakeMessage(TlsContext *context, const uint8_t *message,
   size_t length)
{
   error_t error;
   TlsEncryptionLevel level;

   //At any time, the TLS stack at an endpoint will have a current sending
   //encryption level. TLS encryption level determines the QUIC packet type
   //and keys that are used for protecting data (refer to RFC 9001,
   //section 4.1.3)
   level = context->encryptionEngine.level;

   //Any registered callback?
   if(context->quicCallbacks.sendHandshakeMessage != NULL)
   {
      //When TLS provides handshake bytes to be sent, they are appended to the
      //handshake bytes for the current encryption level
      error = context->quicCallbacks.sendHandshakeMessage(context, level, message,
         length, context->quicHandle);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Send alert message
 * @param[in] context Pointer to the TLS context
 * @param[in] message Pointer to the alert message
 * @param[in] length Length of the alert message, in bytes
 * @return Error code
 **/

error_t tlsSendQuicAlertMessage(TlsContext *context, const TlsAlert *message,
   size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //QUIC is only able to convey an alert level of "fatal" (refer to RFC 9001,
   //section 4.8)
   if(length == sizeof(TlsAlert) && message->level == TLS_ALERT_LEVEL_FATAL)
   {
      //Any registered callback?
      if(context->quicCallbacks.sendAlertMessage != NULL)
      {
         //A TLS alert is converted into a QUIC connection error
         error = context->quicCallbacks.sendAlertMessage(context,
            message->description, context->quicHandle);
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }
   }

   //Return status code
   return error;
}

#endif
