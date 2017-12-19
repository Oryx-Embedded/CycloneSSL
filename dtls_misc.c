/**
 * @file dtls_misc.c
 * @brief DTLS (Datagram Transport Layer Security)
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
#include <string.h>
#include <ctype.h>
#include "tls.h"
#include "tls_handshake_misc.h"
#include "tls_common.h"
#include "dtls_misc.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED && DTLS_SUPPORT == ENABLED)


/**
 * @brief Set the DTLS version to be used
 * @param[in] context Pointer to the TLS context
 * @param[in] version DTLS version
 * @return Error code
 **/

error_t dtlsSelectVersion(TlsContext *context, uint16_t version)
{
   error_t error;

   //Initialize status code
   error = ERROR_VERSION_NOT_SUPPORTED;

   //Check DTLS version
   if(version == DTLS_VERSION_1_0)
   {
      //DTLS 1.0 is defined as a series of deltas from TLS 1.1
      if(context->versionMin <= TLS_VERSION_1_1 &&
         context->versionMax >= TLS_VERSION_1_1)
      {
         //Save protocol version
         context->version = TLS_VERSION_1_1;
         //The specified DTLS version is acceptable
         error = NO_ERROR;
      }
   }
   else if(version == DTLS_VERSION_1_2)
   {
      //DTLS 1.2 is defined as a series of deltas from TLS 1.2
      if(context->versionMin <= TLS_VERSION_1_2 &&
         context->versionMax >= TLS_VERSION_1_2)
      {
         //Save protocol version
         context->version = TLS_VERSION_1_2;
         //The specified DTLS version is acceptable
         error = NO_ERROR;
      }
   }

   //Check whether the DTLS version is supported
   if(!error)
   {
      //Initial handshake?
      if(context->encryptionEngine.epoch == 0)
      {
         //Save the negotiated version
         context->encryptionEngine.version = context->version;
      }
   }
   else
   {
      //Debug message
      TRACE_WARNING("DTLS version not supported!\r\n");
   }

   //Return status code
   return error;
}


/**
 * @brief Translate TLS version into DTLS version
 * @param[in] version TLS version
 * @return DTLS version
 **/

uint16_t dtlsTranslateVersion(uint16_t version)
{
   //Check current version
   if(version == TLS_VERSION_1_2)
   {
      //DTLS 1.2 is defined as a series of deltas from TLS 1.2
      version = DTLS_VERSION_1_2;
   }
   else
   {
      //DTLS 1.0 is defined as a series of deltas from TLS 1.1
      version = DTLS_VERSION_1_0;
   }

   //Return the version of the DTLS protocol
   return version;
}


/**
 * @brief Format Cookie field
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the Cookie field
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t dtlsFormatCookie(TlsContext *context,
   uint8_t *p, size_t *written)
{
   DtlsCookie *cookie;

   //Add Cookie field
   cookie = (DtlsCookie *) p;

   //Set the length of the cookie
   cookie->length = (uint8_t) context->cookieLen;
   //Copy cookie
   memcpy(cookie->value, context->cookie, context->cookieLen);

   //Total number of bytes that have been written
   *written = sizeof(DtlsCookie) + cookie->length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Send HelloVerifyRequest message
 *
 * When the client sends its ClientHello message to the server, the server may
 * respond with a HelloVerifyRequest message. This message contains a stateless
 * cookie
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t dtlsSendHelloVerifyRequest(TlsContext *context)
{
   error_t error;
   size_t length;
   DtlsHelloVerifyRequest *message;

   //Point to the buffer where to format the message
   message = (DtlsHelloVerifyRequest *) (context->txBuffer + context->txBufferLen);

   //Format HelloVerifyRequest message
   error = dtlsFormatHelloVerifyRequest(context, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending HelloVerifyRequest message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsSendHandshakeMessage(context, message, length,
         TLS_TYPE_HELLO_VERIFY_REQUEST);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //The client must retransmit the ClientHello with the cookie added
      context->state = TLS_STATE_CLIENT_HELLO;
   }

   //Return status code
   return error;
}


/**
 * @brief Format HelloVerifyRequest message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the HelloVerifyRequest message
 * @param[out] length Length of the resulting HelloVerifyRequest message
 * @return Error code
 **/

error_t dtlsFormatHelloVerifyRequest(TlsContext *context,
   DtlsHelloVerifyRequest *message, size_t *length)
{
   //In order to avoid the requirement to do version negotiation in the initial
   //handshake, DTLS 1.2 server implementations should use DTLS version 1.0
   //regardless of the version of TLS that is expected to be negotiated
   message->serverVersion = HTONS(DTLS_VERSION_1_0);

   //Set the length of the cookie
   message->cookieLength = (uint8_t) context->cookieLen;
   //Copy cookie
   memcpy(message->cookie, context->cookie, context->cookieLen);

   //Length of the handshake message
   *length = sizeof(DtlsHelloVerifyRequest) + context->cookieLen;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse HelloVerifyRequest message
 *
 * When the client sends its ClientHello message to the server,
 * the server may respond with a HelloVerifyRequest message
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming HelloVerifyRequest message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t dtlsParseHelloVerifyRequest(TlsContext *context,
   const DtlsHelloVerifyRequest *message, size_t length)
{
   //Debug message
   TRACE_INFO("HelloVerifyRequest message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Check the length of the HelloVerifyRequest message
      if(length < sizeof(DtlsHelloVerifyRequest))
         return ERROR_DECODING_FAILED;

      //Check current state
      if(context->state != TLS_STATE_SERVER_HELLO)
         return ERROR_UNEXPECTED_MESSAGE;

      //Remaining bytes to process
      length -= sizeof(DtlsHelloVerifyRequest);

      //If the amount of data in the message does not precisely match the format
      //of the HelloVerifyRequest message, then send a fatal alert
      if(message->cookieLength != length)
         return ERROR_DECODING_FAILED;

      //Check the length of the cookie
      if(message->cookieLength > DTLS_MAX_COOKIE_SIZE)
         return ERROR_ILLEGAL_PARAMETER;

      //Save cookie
      memcpy(context->cookie, message->cookie, message->cookieLength);
      context->cookieLen = message->cookieLength;

      //The client sends a second ClientHello message
      context->state = TLS_STATE_CLIENT_HELLO;

      //Successful processing
      return NO_ERROR;
   }
   else
   {
      //Report an error
      return ERROR_UNEXPECTED_MESSAGE;
   }
}


/**
 * @brief Initialize sliding window
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

void dtlsInitReplayWindow(TlsContext *context)
{
#if (DTLS_REPLAY_DETECTION_SUPPORT == ENABLED)
   uint_t i;

   //Clear the bitmap window
   for(i = 0; i < (DTLS_REPLAY_WINDOW_SIZE + 31) / 32; i++)
   {
      context->replayWindow[i] = 0;
   }
#endif
}


/**
 * @brief Perform replay detection
 * @param[in] context Pointer to the TLS context
 * @param[in] seqNum Sequence number of the received DTLS record
 * @return Error code
 **/

error_t dtlsCheckReplayWindow(TlsContext *context, DtlsSequenceNumber *seqNum)
{
   error_t error;

#if (DTLS_REPLAY_DETECTION_SUPPORT == ENABLED)
   //Check whteher anti-replay mechanism is enabled
   if(context->replayDetectionEnabled)
   {
      uint_t j;
      uint_t k;
      uint64_t n;
      uint64_t right;

      //Get the sequence number of the received DTLS record
      n = LOAD48BE(seqNum);

      //The right edge of the window represents the highest validated sequence
      //number value received on this session
      right = LOAD48BE(&context->decryptionEngine.dtlsSeqNum);

      //Check sequence number
      if(n <= right)
      {
         //Calculate the position relative to the right edge of the window
         n = right - n;

         //Check whether the sequence number falls within the window
         if(n < DTLS_REPLAY_WINDOW_SIZE)
         {
            //Records falling within the window are checked against a list of
            //received packets within the window
            j = (uint_t) (n / 32);
            k = (uint_t) (n % 32);

            //Duplicate record are rejected through the use of a sliding
            //receive window
            if(context->replayWindow[j] & (1 << k))
            {
               //The received record is a duplicate
               error = ERROR_INVALID_SEQUENCE_NUMBER;
            }
            else
            {
               //If the received record falls within the window and is new,
               //then the receiver proceeds to MAC verification
               error = NO_ERROR;
            }

         }
         else
         {
            //Records that contain sequence numbers lower than the left edge
            //of the window are rejected
            error = ERROR_INVALID_SEQUENCE_NUMBER;
         }
      }
      else
      {
         //If the packet is to the right of the window, then the receiver
         //proceeds to MAC verification
         error = NO_ERROR;
      }
   }
   else
#endif
   {
      //Anti-replay mechanism is disabled
      error = NO_ERROR;
   }

   //Return status code
   return error;
}


/**
 * @brief Update sliding window
 * @param[in] context Pointer to the TLS context
 * @param[in] seqNum Sequence number of the received DTLS record
 **/

void dtlsUpdateReplayWindow(TlsContext *context, DtlsSequenceNumber *seqNum)
{
   uint64_t n;
   uint64_t right;

   //Get the sequence number of the received DTLS record
   n = LOAD48BE(seqNum);

   //The right edge of the window represents the highest validated sequence
   //number value received on this session
   right = LOAD48BE(&context->decryptionEngine.dtlsSeqNum);

   //Check sequence number
   if(n <= right)
   {
#if (DTLS_REPLAY_DETECTION_SUPPORT == ENABLED)
      uint_t j;
      uint_t k;

      //Calculate the position relative to the right edge of the window
      n = right - n;

      //Check whether the sequence number falls within the window
      if(n < DTLS_REPLAY_WINDOW_SIZE)
      {
         j = (uint_t) (n / 32);
         k = (uint_t) (n % 32);

         //Set the corresponding bit in the bitmap window
         context->replayWindow[j] |= 1 << k;
      }
#endif
   }
   else
   {
#if (DTLS_REPLAY_DETECTION_SUPPORT == ENABLED)
      uint_t i;
      uint_t j;
      uint_t k;

      //Calculate the position relative to the right edge of the window
      n -= right;

      //Check resulting value
      if(n < DTLS_REPLAY_WINDOW_SIZE)
      {
         j = (uint_t) (n / 32);
         k = (uint_t) (n % 32);

         //First, shift words
         if(j > 0)
         {
            //Shift the most significant words of the window
            for(i = (DTLS_REPLAY_WINDOW_SIZE - 1) / 32; i >= j; i--)
            {
               context->replayWindow[i] = context->replayWindow[i - j];
            }

            //Fill the least significant words with zeroes
            for(i = 0; i < j; i++)
            {
               context->replayWindow[i] = 0;
            }
         }

         //Then shift bits
         if(k > 0)
         {
            //Shift the most significant words of the window
            for(i = (DTLS_REPLAY_WINDOW_SIZE - 1) / 32; i >= 1; i--)
            {
               context->replayWindow[i] = (context->replayWindow[i] << k) |
                  (context->replayWindow[i - 1] >> (32 - k));
            }

            //Shift the least significant word
            context->replayWindow[0] <<= k;
         }
      }
      else
      {
         //Clear the bitmap window
         for(i = 0; i < (DTLS_REPLAY_WINDOW_SIZE + 31) / 32; i++)
         {
            context->replayWindow[i] = 0;
         }
      }

      //Set the corresponding bit in the bitmap window
      context->replayWindow[0] |= 1;
#endif

      //Save the highest sequence number value received on this session
      context->decryptionEngine.dtlsSeqNum = *seqNum;
   }
}

#endif
