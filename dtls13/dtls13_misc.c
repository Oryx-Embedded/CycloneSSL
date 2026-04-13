/**
 * @file dtls13_misc.c
 * @brief DTLS 1.3 (Datagram Transport Layer Security)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2026 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.6.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include "tls/tls.h"
#include "tls/tls_misc.h"
#include "dtls/dtls_record.h"
#include "dtls13/dtls13_misc.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && DTLS_SUPPORT == ENABLED && \
   TLS_MAX_VERSION >= TLS_VERSION_1_3)


/**
 * @brief Update the list of record numbers
 * @param[in] context Pointer to the TLS context
 * @param[in] epoch Epoch number of the received DTLS record
 * @param[in] seqNum Sequence number of the received DTLS record
 **/

void dtls13SaveRecordNumber(TlsContext *context, uint64_t epoch,
   uint64_t seqNum)
{
   uint_t i;

   //Discard duplicate record numbers
   for(i = 0; i < context->numAckRecords; i++)
   {
      if(context->ackRecords[i].epoch == epoch &&
         context->ackRecords[i].seqNum == seqNum)
      {
         return;
      }
   }

   //If space is limited, implementations should favor including records which
   //have not yet been acknowledged (refer to RFC 9147, section 7.1)
   if(context->numAckRecords < DTLS13_MAX_ACK_RECORDS)
   {
      //Append the record number to the end of the list
      i = context->numAckRecords;
      context->ackRecords[i].epoch = epoch;
      context->ackRecords[i].seqNum = seqNum;

      //Update the length of the list
      context->numAckRecords++;
   }
   else
   {
      //Make room for the new record number
      for(i = 1; i < context->numAckRecords; i++)
      {
         context->ackRecords[i - 1] = context->ackRecords[i];
      }

      //Append the record number to the end of the list
      i = context->numAckRecords - 1;
      context->ackRecords[i].epoch = epoch;
      context->ackRecords[i].seqNum = seqNum;
   }

   //DTLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      //Start the ACK timer when the first record in the flight is received
      if(!context->ackTimerRunning)
      {
         context->ackTimestamp = osGetSystemTime();
         context->ackTimerRunning = TRUE;
      }
   }
}


/**
 * @brief Send ACK message
 *
 * The ACK message is used by an endpoint to indicate which handshake records
 * it has received and processed from the other side
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t dtls13SendAck(TlsContext *context)
{
   error_t error;
   size_t length;
   Dtls13Ack *message;

   //Point to the buffer where to format the message
   message = (Dtls13Ack *) (context->txBuffer + context->txBufferLen);

   //Format ACK message
   error = dtls13FormatAck(context, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending ACK message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //ACK is not a handshake message but is rather a separate content type,
      //with code point 26 (refer to RFC 9147, section 7)
      error = dtlsWriteProtocolData(context, (uint8_t *) message, length,
         TLS_TYPE_ACK);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //For post-handshake messages, ACKs should be sent once for each received
      //and processed handshake record (refer to RFC 9147, section 7)
      if(context->state == TLS_STATE_APPLICATION_DATA ||
         context->state == TLS_STATE_CLIENT_FINISHED_ACK ||
         context->state == TLS_STATE_NEW_SESSION_TICKET_ACK ||
         context->state == TLS_STATE_KEY_UPDATE_ACK)
      {
         context->numAckRecords = 0;
      }

      //Check whether the ACK message was for the client's final flight
      if(context->entity == TLS_CONNECTION_END_SERVER &&
         context->state == TLS_STATE_FINAL_ACK)
      {
#if (TLS_TICKET_SUPPORT == ENABLED)
         //Check whether session ticket mechanism is enabled
         if(context->ticketEncryptCallback != NULL &&
            context->pskKeModeSupported)
         {
            //At any time after the server has received the client Finished
            //message, it may send a NewSessionTicket message
            tlsChangeState(context, TLS_STATE_NEW_SESSION_TICKET_2);
         }
         else
#endif
         {
            //The client and server can now exchange application-layer data
            tlsChangeState(context, TLS_STATE_APPLICATION_DATA);
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Format ACK message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the ACK message
 * @param[out] length Length of the resulting ACK message
 * @return Error code
 **/

error_t dtls13FormatAck(TlsContext *context, Dtls13Ack *message,
   size_t *length)
{
   uint_t i;
   uint_t j;
   size_t n;
   Dtls13RecordNumber t;
   Dtls13RecordNumber *p;

   //Point to the record_numbers field
   p = message->recordNumbers;

   //Record numbers are formed by combining the epoch and sequence numbers
   for(i = 0; i < context->numAckRecords; i++)
   {
      p[i].epoch = context->ackRecords[i].epoch;
      p[i].seqNum = context->ackRecords[i].seqNum;
   }

   //The record_numbers field is a list of the records containing handshake
   //messages in the current flight which the endpoint has received and
   //either processed or buffered, in numerically increasing order (refer to
   //RFC 9147, section 7)
   for(i = 0; i < context->numAckRecords; i++)
   {
      for(j = i + 1; j < context->numAckRecords; j++)
      {
         //Compare record numbers
         if((p[i].epoch == p[j].epoch && p[i].seqNum > p[j].seqNum) ||
            p[i].epoch > p[j].epoch)
         {
            //Swap record numbers
            t = p[i];
            p[i] = p[j];
            p[j] = t;
         }
      }
   }

   //Convert epoch and sequence numbers to network byte order
   for(i = 0; i < context->numAckRecords; i++)
   {
      p[i].epoch = htonll(p[i].epoch);
      p[i].seqNum = htonll(p[i].seqNum);
   }

   //Compute the length of the list
   n = context->numAckRecords * sizeof(Dtls13RecordNumber);
   //Set the length of the record_numbers field
   message->length = htons(n);

   //Length of the ACK message
   *length = sizeof(Dtls13Ack) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ACK message
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming ACK message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t dtls13ParseAck(TlsContext *context, const Dtls13Ack *message,
   size_t length)
{
   uint_t i;
   uint_t j;
   uint64_t epoch;
   uint64_t seqNum;
   uint_t index;
   uint_t numRecords;
   Dtls13RetransmitState *state;

   //Debug message
   TRACE_INFO("ACK message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check transport protocol
   if(context->transportProtocol != TLS_TRANSPORT_PROTOCOL_DATAGRAM)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check TLS version
   if(context->version != TLS_VERSION_1_3)
   {
      //The client must tolerate ACKs in response to its initial ClientHello
      if(context->versionMax >= TLS_VERSION_1_3 &&
         context->entity == TLS_CONNECTION_END_CLIENT &&
         context->state == TLS_STATE_SERVER_HELLO)
      {
         //Drop the ACK message
         return NO_ERROR;
      }
      else
      {
         //Report an error
         return ERROR_UNEXPECTED_MESSAGE;
      }
   }

   //Check message length
   if(length < sizeof(Dtls13Ack))
      return ERROR_INVALID_LENGTH;

   //Malformed ACK message?
   if(((length - sizeof(Dtls13Ack)) % sizeof(Dtls13RecordNumber)) != 0)
      return ERROR_INVALID_LENGTH;

   //Dtermine the number of records in the list
   numRecords = (length - sizeof(Dtls13Ack)) / sizeof(Dtls13RecordNumber);

   //The ACK message is used by an endpoint to indicate which handshake records
   //it has received and processed from the other side
   for(i = 0; i < numRecords; i++)
   {
      //A record number combines an epoch and a sequence number
      epoch = ntohll(message->recordNumbers[i].epoch);
      seqNum = ntohll(message->recordNumbers[i].seqNum);

      //Loop through the encryption engines
      for(state = NULL, j = 0; j < TLS_MAX_ENCRYPTION_ENGINES; j++)
      {
         //Compare epochs
         if(context->encryptionEngine[j].epoch == epoch)
         {
            state = &context->encryptionEngine[j].retransmitState;
            break;
         }
      }

      //Matching epoch?
      if(state != NULL)
      {
         //Implementations must treat a record as having been acknowledged if
         //it appears in any ACK (refer to RFC9147, section 7.2)
         if(seqNum >= state->start && state->count > 0 && state->count <= 32)
         {
            if(context->state == TLS_STATE_CLIENT_FINISHED_ACK ||
               context->state == TLS_STATE_NEW_SESSION_TICKET_ACK ||
               context->state == TLS_STATE_KEY_UPDATE_ACK)
            {
               if(seqNum < (state->start + state->count))
               {
                  index = (uint_t) (seqNum - state->start);
                  state->mask &= ~(1 << index);
               }
            }
            else
            {
               index = (seqNum - state->start) % state->count;
               state->mask &= ~(1 << index);
            }
         }
      }
   }

   //Check whether all the messages have been acknowledged
   if(context->encryptionEngine[0].retransmitState.mask == 0 &&
      context->encryptionEngine[1].retransmitState.mask == 0 &&
      context->encryptionEngine[2].retransmitState.mask == 0)
   {
      //Once all the messages in a flight have been acknowledged, the
      //implementation must cancel all retransmissions of that flight
      context->txBufferLen = 0;

      //Check current state
      if(context->state == TLS_STATE_CLIENT_FINISHED_ACK ||
         context->state == TLS_STATE_NEW_SESSION_TICKET_ACK ||
         context->state == TLS_STATE_KEY_UPDATE_ACK)
      {
         context->state = TLS_STATE_APPLICATION_DATA;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format nonce
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @param[in] seqNum Pointer to the sequence number
 * @param[out] nonce Pointer to the buffer where to store the resulting nonce
 * @param[out] nonceLen Length of the nonce, in bytes
 **/

void dtls13FormatNonce(TlsEncryptionEngine *encryptionEngine,
   const DtlsSequenceNumber *seqNum, uint8_t *nonce, size_t *nonceLen)
{
   size_t i;
   size_t n;

   //Calculate the total length of the nonce
   n = encryptionEngine->fixedIvLen;

   //In DTLS 1.3 the 64-bit sequence_number is used as the sequence number for
   //the AEAD computation; unlike DTLS 1.2, the epoch is not included (refer to
   //RFC 9147, section 4)
   osMemset(nonce + n - 8, 0, 2);
   osMemcpy(nonce + n - 6, seqNum->b, 6);

   //The 64-bit record sequence number is padded on the left by zeros
   osMemset(nonce, 0, n - 8);

   //The padded sequence number is XORed with the IV to form the nonce
   for(i = 0; i < n; i++)
   {
      nonce[i] ^= encryptionEngine->iv[i];
   }

   //Return the total length of the nonce
   *nonceLen = n;
}


/**
 * @brief Compute overhead caused by encryption
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @return Overhead, in bytes, caused by encryption
 **/

size_t dtls13ComputeEncryptionOverhead(TlsEncryptionEngine *encryptionEngine)
{
   size_t n;

   //Initialize variable
   n = 6;

   //Check cipher mode of operation
   //Message authentication?
   if(encryptionEngine->cipherMode == CIPHER_MODE_CCM ||
      encryptionEngine->cipherMode == CIPHER_MODE_GCM ||
      encryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      n += encryptionEngine->authTagLen;
   }
   else if(encryptionEngine->cipherMode == CIPHER_MODE_NULL)
   {
      n += encryptionEngine->hashAlgo->digestSize;
   }

   //Return the total overhead caused by encryption
   return n;
}

#endif
