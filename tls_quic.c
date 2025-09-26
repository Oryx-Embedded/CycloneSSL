/**
 * @file tls_quic.c
 * @brief QUIC TLS related API
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
#include "tls_quic.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_QUIC_SUPPORT == ENABLED)


/**
 * @brief Register QUIC-specific callback functions
 * @param[in] context Pointer to the TLS context
 * @param[in] quicCallbacks QUIC callback functions
 * @param[in] handle An opaque pointer passed to the callback functions
 * @return Error code
 **/

error_t tlsRegisterQuicCallbacks(TlsContext *context,
   const TlsQuicCallbacks *quicCallbacks, void *handle)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save QUIC-specific callback functions
   context->quicCallbacks = *quicCallbacks;
   //This opaque pointer will be directly passed to the callback functions
   context->quicHandle = handle;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set QUIC-specific handle
 * @param[in] context Pointer to the TLS context
 * @param[in] handle An opaque pointer passed to the callback functions
 * @return Error code
 **/

error_t tlsSetQuicHandle(TlsContext *context, void *handle)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //This opaque pointer will be directly passed to the callback functions
   context->quicHandle = handle;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set local QUIC transport parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] params Pointer to the QUIC transport parameters
 * @param[in] length Length of the QUIC transport parameters, in bytes
 * @return Error code
 **/

error_t tlsSetLocalQuicTransportParams(TlsContext *context,
   const uint8_t *params, size_t length)
{
   //Check parameters
   if(context == NULL || params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether the QUIC transport parameters have already been configured
   if(context->localQuicTransportParams != NULL)
   {
      //Release memory
      tlsFreeMem(context->localQuicTransportParams);
      context->localQuicTransportParams = NULL;
      context->localQuicTransportParamsLen = 0;
   }

   //Valid QUIC transport parameters?
   if(length > 0)
   {
      //Allocate a memory block to hold the QUIC transport parameters
      context->localQuicTransportParams = tlsAllocMem(length);
      //Failed to allocate memory?
      if(context->localQuicTransportParams == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Save the QUIC transport parameters
      osMemcpy(context->localQuicTransportParams, params, length);
      context->localQuicTransportParamsLen = length;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get remote QUIC transport parameters
 * @param[in] context Pointer to the TLS context
 * @param[out] params Pointer to the QUIC transport parameters
 * @param[out] length Length of the QUIC transport parameters, in bytes
 * @return Error code
 **/

error_t tlsGetRemoteQuicTransportParams(TlsContext *context,
   const uint8_t **params, size_t *length)
{
   //Check parameters
   if(context == NULL || params == NULL || length == NULL)
      return ERROR_INVALID_PARAMETER;

   //Return the QUIC transport parameters
   *params = context->remoteQuicTransportParams;
   *length = context->remoteQuicTransportParamsLen;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Process incoming handshake data
 * @param[in] context Pointer to the TLS context
 * @param[in] level Encryption level
 * @param[in] data Pointer to the handshake data
 * @param[in] length Length of the handshake data, in bytes
 * @return Error code
 **/

error_t tlsProcessQuicHandshakeMessage(TlsContext *context,
   TlsEncryptionLevel level, const uint8_t *data, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Empty receive buffer?
   if(context->rxBufferLen == 0)
   {
      //Rewind to the beginning of the buffer
      context->rxBufferPos = 0;
   }

   //Check current TLS receiving encryption level
   if(level == context->decryptionEngine.level)
   {
      //Check the length of the handshake data
      if((context->rxBufferLen + length) <= context->rxBufferSize)
      {
         //QUIC CRYPTO frames only carry TLS handshake messages (refer to
         //RFC 9001, section 4.1.3)
         context->rxBufferType = TLS_TYPE_HANDSHAKE;

         //The content of CRYPTO frames might either be processed incrementally by
         //TLS or buffered until complete messages or flights are available. TLS
         //is responsible for buffering handshake bytes that have arrived in order
         osMemcpy(context->rxBuffer + context->rxBufferLen, data, length);

         //Number of bytes available for reading
         context->rxBufferLen += length;
      }
      else
      {
         //Report an error
         error = ERROR_BUFFER_OVERFLOW;
      }
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_LEVEL;
   }

   //Return status code
   return error;
}

#endif
