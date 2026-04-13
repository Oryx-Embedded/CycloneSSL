/**
 * @file dtls_record.c
 * @brief DTLS record layer
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
#include "tls/tls_common.h"
#include "tls/tls_record.h"
#include "tls/tls_record_encrypt.h"
#include "tls/tls_record_decrypt.h"
#include "tls/tls_misc.h"
#include "tls13/tls13_client_misc.h"
#include "dtls/dtls_misc.h"
#include "dtls/dtls_record.h"
#include "dtls13/dtls13_record_encrypt.h"
#include "dtls13/dtls13_record_decrypt.h"
#include "dtls13/dtls13_misc.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && DTLS_SUPPORT == ENABLED)


/**
 * @brief Write protocol data
 * @param[in] context Pointer to the TLS context
 * @param[in] data Pointer to the data buffer
 * @param[in] length Number of data bytes to be written
 * @param[in] contentType Higher level protocol
 * @return Error code
 **/

error_t dtlsWriteProtocolData(TlsContext *context,
   const uint8_t *data, size_t length, TlsContentType contentType)
{
   error_t error;
   DtlsRetransmitState state;

   //Prepare DTLS record
   error = dtlsWriteRecord(context, data, length, contentType);

   //Check status code
   if(!error)
   {
      //DTLS operates as a client or a server?
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //Client messages are grouped into a series of message flights
         if(context->state == TLS_STATE_CLIENT_HELLO ||
            context->state == TLS_STATE_CLIENT_HELLO_2 ||
            context->state == TLS_STATE_CLIENT_FINISHED ||
            context->state == TLS_STATE_KEY_UPDATE)
         {
            state = DTLS_RETRANSMIT_STATE_SENDING;
         }
         else
         {
            state = DTLS_RETRANSMIT_STATE_PREPARING;
         }
      }
      else
      {
         //Server messages are grouped into a series of message flights
         if(context->state == TLS_STATE_HELLO_VERIFY_REQUEST ||
            context->state == TLS_STATE_HELLO_RETRY_REQUEST ||
            context->state == TLS_STATE_SERVER_HELLO_DONE ||
            context->state == TLS_STATE_SERVER_FINISHED ||
            context->state == TLS_STATE_KEY_UPDATE)
         {
            state = DTLS_RETRANSMIT_STATE_SENDING;
         }
         else if(context->state == TLS_STATE_NEW_SESSION_TICKET_2)
         {
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
            //A server may send multiple NewSessionTicket messages at once
            //without awaiting ACKs for earlier NewSessionTicket messages
            //first (refer to RFC 9147, section 5.8.4)
            if(context->newSessionTicketCount >= TLS13_NEW_SESSION_TICKET_COUNT)
            {
               state = DTLS_RETRANSMIT_STATE_SENDING;
            }
            else
#endif
            {
               state = DTLS_RETRANSMIT_STATE_PREPARING;
            }
         }
         else
         {
            state = DTLS_RETRANSMIT_STATE_PREPARING;
         }
      }

      //Check retransmission state
      if(state == DTLS_RETRANSMIT_STATE_SENDING)
      {
         //Reset retransmission counter
         context->retransmitCount = 0;
         //Implementations should use an initial timer value of 1 second
         context->retransmitTimeout = DTLS_INIT_TIMEOUT;

         //In the SENDING state, the implementation transmits the buffered
         //flight of messages (refer to RFC 6347, section 4.2.4)
         error = dtlsSendFlight(context);

         //Timeout and retransmission do not apply to HelloVerifyRequest and
         //HelloRetryRequest messages, because this would require creating
         //state on the server
         if(context->state == TLS_STATE_HELLO_VERIFY_REQUEST ||
            context->state == TLS_STATE_HELLO_RETRY_REQUEST)
         {
            context->txBufferLen = 0;
         }

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
         //Implementations must clear their ACK list upon receiving the start
         //of the next flight (refer to RFC 9147, section 7)
         context->numAckRecords = 0;
         context->ackTimerRunning = FALSE;
#endif
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Read protocol data
 * @param[in] context Pointer to the TLS context
 * @param[out] data Pointer to the received data
 * @param[out] length Number of data bytes that were received
 * @param[out] contentType Higher level protocol
 * @return Error code
 **/

error_t dtlsReadProtocolData(TlsContext *context,
   uint8_t **data, size_t *length, TlsContentType *contentType)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Receive process
   while(error == NO_ERROR)
   {
      if(context->rxBufferLen > 0)
      {
         //Pass the received data to the higher layer
         break;
      }
      else if(context->rxRecordLen > 0)
      {
         //Process the incoming DTLS record
         error = dtlsProcessRecord(context);

         //Invalid record?
         if(error)
         {
            //Debug message
            TRACE_WARNING("Discarding DTLS record!\r\n");

            //DTLS implementations should silently discard records with bad MACs
            //and continue with the connection
            error = NO_ERROR;
         }
      }
      else if(context->rxDatagramLen > 0)
      {
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
         //DTLS 1.3 protocol?
         if(context->version == TLS_VERSION_1_3)
         {
            //Read a new DTLS 1.3 record from the datagram
            error = dtls13ReadRecord(context);
         }
         else
#endif
         {
            //Read a new DTLS record from the datagram
            error = dtlsReadRecord(context);
         }

         //Malformed record?
         if(error != NO_ERROR && error != ERROR_RECORD_OVERFLOW)
         {
            //Debug message
            TRACE_WARNING("Discarding DTLS record!\r\n");

            //The receiving implementation should discard the offending record
            error = NO_ERROR;
         }
      }
      else
      {
         //Read a new datagram
         error = dtlsReadDatagram(context, context->rxBuffer + context->rxFragQueueLen,
            context->rxBufferSize - context->rxFragQueueLen, &context->rxDatagramLen);

         //Check whether a valid datagram has been received
         if(!error)
         {
            //Make room for the fragment reassembly process
            context->rxDatagramPos = context->rxBufferSize - context->rxDatagramLen;

            //Copy the received datagram
            osMemmove(context->rxBuffer + context->rxDatagramPos,
               context->rxBuffer + context->rxFragQueueLen, context->rxDatagramLen);
         }
      }
   }

   //Successful processing?
   if(!error)
   {
#if (TLS_MAX_WARNING_ALERTS > 0)
      //Reset the count of consecutive warning alerts
      if(context->rxBufferType != TLS_TYPE_ALERT)
      {
         context->alertCount = 0;
      }
#endif
#if (TLS_MAX_KEY_UPDATE_MESSAGES > 0)
      //Reset the count of consecutive KeyUpdate messages
      if(context->rxBufferType != TLS_TYPE_HANDSHAKE)
      {
         context->keyUpdateCount = 0;
      }
#endif

      //Pointer to the received data
      *data = context->rxBuffer + context->rxBufferPos;
      //Length, in byte, of the data
      *length = context->rxBufferLen;
      //Protocol type
      *contentType = context->rxBufferType;
   }

   //Return status code
   return error;
}


/**
 * @brief Send a DTLS record
 * @param[in] context Pointer to the TLS context
 * @param[in] data Pointer to the record data
 * @param[in] length Length of the record data
 * @param[in] contentType Record type
 * @return Error code
 **/

error_t dtlsWriteRecord(TlsContext *context, const uint8_t *data,
   size_t length, TlsContentType contentType)
{
   error_t error;
   size_t n;
   uint16_t legacyVersion;
   DtlsRecord *record;
   TlsEncryptionEngine *encryptionEngine;

   //Calculate the length of the DTLSPlaintext record
   n = length + sizeof(DtlsRecord);

   //Make sure the buffer is large enough to hold the DTLSPlaintext record
   if((context->txBufferLen + n) > context->txBufferSize)
      return ERROR_BUFFER_OVERFLOW;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //Implementations must not send records with the new keys until the previous
   //KeyUpdate has been acknowledged (refer to RFC 9147, section 8)
   if(context->version == TLS_VERSION_1_3 &&
      context->state == TLS_STATE_KEY_UPDATE_ACK)
   {
      encryptionEngine = &context->encryptionEngine[1];
   }
   else
#endif
   {
      encryptionEngine = &context->encryptionEngine[0];
   }

   //Point to the DTLS record header
   record = (DtlsRecord *) (context->txBuffer + context->txBufferLen);

   //Copy record data
   osMemmove(record->data, data, length);

   //The record version must be set to {254, 253} for all records generated
   //by a DTLS 1.3 implementation other than an initial ClientHello
   legacyVersion = MIN(encryptionEngine->version, TLS_VERSION_1_2);
   legacyVersion = dtlsTranslateVersion(legacyVersion);

   //Format DTLSPlaintext structure
   record->type = contentType;
   record->version = htons(legacyVersion);
   record->epoch = htons(encryptionEngine->epoch);
   record->length = htons(length);

   //Check record type
   if(contentType == TLS_TYPE_HANDSHAKE ||
      contentType == TLS_TYPE_CHANGE_CIPHER_SPEC)
   {
      //Sequence numbers are handled at record layer
      osMemset(&record->seqNum, 0, sizeof(DtlsSequenceNumber));

      //Adjust the length of the buffered flight of messages
      context->txBufferLen += n;
   }
   else
   {
      //This record will have a new sequence number
      record->seqNum = encryptionEngine->dtlsSeqNum;

      //Protect record payload?
      if(encryptionEngine->cipherMode != CIPHER_MODE_NULL ||
         encryptionEngine->hashAlgo != NULL)
      {
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
         //DTLS 1.3 protocol?
         if(context->version == TLS_VERSION_1_3)
         {
            //Overhead caused by record encryption must be considered
            n = length + dtls13ComputeEncryptionOverhead(encryptionEngine);

            //Make sure the buffer is large enough to hold the DTLSCiphertext
            //record
            if((context->txBufferLen + n) > context->txBufferSize)
               return ERROR_BUFFER_OVERFLOW;

            //Encrypt DTLS 1.3 record
            error = dtls13EncryptRecord(context, encryptionEngine, record->type,
               record->data, ntohs(record->length), (uint8_t *) record, &n);
            //Any error to report?
            if(error)
               return error;
         }
         else
#endif
         {
            //Overhead caused by record encryption must be considered
            n += tlsComputeEncryptionOverhead(encryptionEngine, n);

            //Make sure the buffer is large enough to hold the DTLSCiphertext
            //record
            if((context->txBufferLen + n) > context->txBufferSize)
               return ERROR_BUFFER_OVERFLOW;

            //Encrypt DTLS record
            error = tlsEncryptRecord(context, encryptionEngine, record);
            //Any error to report?
            if(error)
               return error;

            //Length of the resulting datagram, in bytes
            n = ntohs(record->length) + sizeof(DtlsRecord);
         }
      }
      else
      {
         //Length of the datagram, in bytes
         n = ntohs(record->length) + sizeof(DtlsRecord);
      }

      //Debug message
      TRACE_DEBUG("Encrypted DTLS record (%" PRIuSIZE " bytes)...\r\n", n);
      TRACE_DEBUG_ARRAY("  ", record, n);

      //Increment sequence number
      dtlsIncSequenceNumber(&encryptionEngine->dtlsSeqNum);

      //Debug message
      TRACE_INFO("Sending UDP datagram (%" PRIuSIZE " bytes)...\r\n", n);

      //Send datagram
      error = context->socketSendCallback(context->socketHandle, record, n, &n, 0);
      //Any error to report?
      if(error)
         return error;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Receive a DTLS record
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t dtlsReadRecord(TlsContext *context)
{
   error_t error;
   DtlsRecord *record;
   size_t recordLen;
   TlsEncryptionEngine *decryptionEngine;

   //Point to the decryption engine
   decryptionEngine = &context->decryptionEngine[0];

   //Malformed datagram?
   if(context->rxDatagramLen < sizeof(DtlsRecord))
   {
      //Drop the received datagram
      context->rxDatagramLen = 0;
      //Report an error
      return ERROR_INVALID_LENGTH;
   }

   //Point to the DTLS record
   record = (DtlsRecord *) (context->rxBuffer + context->rxDatagramPos);
   //Retrieve the length of the record
   recordLen = ntohs(record->length);

   //Malformed DTLS record?
   if((recordLen + sizeof(DtlsRecord)) > context->rxDatagramLen)
   {
      //Drop the received datagram
      context->rxDatagramLen = 0;
      //Report an error
      return ERROR_INVALID_LENGTH;
   }

   //Debug message
   TRACE_DEBUG("DTLS encrypted record received (%" PRIuSIZE " bytes)...\r\n", recordLen);
   TRACE_DEBUG_ARRAY("  ", record, recordLen + sizeof(DtlsRecord));

   //Point to the payload data
   context->rxRecordPos = context->rxDatagramPos + sizeof(DtlsRecord);

   //It is acceptable to pack multiple DTLS records in the same datagram
   context->rxDatagramPos += recordLen + sizeof(DtlsRecord);
   context->rxDatagramLen -= recordLen + sizeof(DtlsRecord);

   //Compliant servers must accept any value {254,XX} as the record layer
   //version number for ClientHello
   if(MSB(ntohs(record->version)) != MSB(DTLS_VERSION_1_0))
      return ERROR_VERSION_NOT_SUPPORTED;

   //Discard packets from earlier epochs
   if(ntohs(record->epoch) != decryptionEngine->epoch)
      return ERROR_INVALID_EPOCH;

   //Check whether anti-replay mechanism is enabled
   if(context->replayDetectionEnabled)
   {
      //Perform replay detection
      error = dtlsCheckReplayWindow(decryptionEngine, &record->seqNum);
      //Any error to report?
      if(error)
         return error;
   }

   //Check whether the record payload is protected
   if(decryptionEngine->cipherMode != CIPHER_MODE_NULL ||
      decryptionEngine->hashAlgo != NULL)
   {
      //Decrypt DTLS record
      error = tlsDecryptRecord(context, decryptionEngine, record);
      //If the MAC validation fails, the receiver must discard the record
      if(error)
         return error;

      //The length of the plaintext record must not exceed 2^14 bytes
      if(ntohs(record->length) > TLS_MAX_RECORD_LENGTH)
         return ERROR_RECORD_OVERFLOW;
   }

   //The receive window is updated only if the MAC verification succeeds
   dtlsUpdateReplayWindow(decryptionEngine, &record->seqNum);

   //Retrieve the length of the record
   recordLen = ntohs(record->length);

   //Debug message
   TRACE_DEBUG("DTLS decrypted record received (%" PRIuSIZE " bytes)...\r\n", recordLen);
   TRACE_DEBUG_ARRAY("  ", record, recordLen + sizeof(DtlsRecord));

   //Save record version
   context->rxRecordVersion = ntohs(record->version);
   //Save record type
   context->rxBufferType = (TlsContentType) record->type;
   //Save record length
   context->rxRecordLen = recordLen;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //Save record number
   context->rxRecordNum.epoch = ntohs(record->epoch);
   context->rxRecordNum.seqNum = LOAD48BE(record->seqNum.b);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Process incoming DTLS record
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t dtlsProcessRecord(TlsContext *context)
{
   error_t error;
   systime_t time;

   //Handshake message received?
   if(context->rxBufferType == TLS_TYPE_HANDSHAKE)
   {
      size_t length;
      size_t fragLen;
      DtlsHandshake *message;

      //Make sure the DTLS record is large enough to hold a handshake message
      if(context->rxRecordLen < sizeof(DtlsHandshake))
      {
         //Drop the received DTLS record
         context->rxRecordLen = 0;
         //Report an error
         return ERROR_INVALID_LENGTH;
      }

      //Point to the handshake message
      message = (DtlsHandshake *) (context->rxBuffer + context->rxRecordPos);

      //Debug message
      TRACE_DEBUG("Handshake message fragment received (%" PRIuSIZE " bytes)...\r\n",
         LOAD24BE(message->fragLength));
      TRACE_DEBUG("  msgType = %u\r\n", message->msgType);
      TRACE_DEBUG("  msgSeq = %u\r\n", ntohs(message->msgSeq));
      TRACE_DEBUG("  fragOffset = %u\r\n", LOAD24BE(message->fragOffset));
      TRACE_DEBUG("  fragLength = %u\r\n", LOAD24BE(message->fragLength));
      TRACE_DEBUG("  length = %u\r\n", LOAD24BE(message->length));

      //Retrieve fragment length
      fragLen = LOAD24BE(message->fragLength) + sizeof(DtlsHandshake);

      //Sanity check
      if(fragLen > context->rxRecordLen)
      {
         //Drop the received DTLS record
         context->rxRecordLen = 0;
         //Report an error
         return ERROR_INVALID_LENGTH;
      }

      //It is acceptable to pack multiple handshake messages in the same record
      context->rxRecordPos += fragLen;
      context->rxRecordLen -= fragLen;

      //Invalid fragment length?
      if(LOAD24BE(message->fragLength) > LOAD24BE(message->length))
         return ERROR_INVALID_LENGTH;

      //Empty fragment?
      if(LOAD24BE(message->fragLength) == 0 && LOAD24BE(message->length) != 0)
         return ERROR_INVALID_LENGTH;

      //Check whether TLS operates as a client or a server
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //HelloRequest message received?
         if(message->msgType == TLS_TYPE_HELLO_REQUEST &&
            context->state == TLS_STATE_APPLICATION_DATA)
         {
            //Re-initialize message sequence numbers
            context->rxMsgSeq = ntohs(message->msgSeq);
            context->txMsgSeq = 0;
         }
      }
      else
      {
         //ClientHello message received?
         if(message->msgType == TLS_TYPE_CLIENT_HELLO &&
            context->state == TLS_STATE_CLIENT_HELLO)
         {
            //Initial handshake?
            if(context->decryptionEngine[0].epoch == 0)
            {
               //DTLS 1.2 adds a record sequence number mirroring technique
               //for handling repeated ClientHello messages (refer to RFC 6347,
               //section 8)
               context->encryptionEngine[0].dtlsSeqNum =
                  context->decryptionEngine[0].dtlsSeqNum;

               //Re-initialize message sequence numbers
               context->rxMsgSeq = ntohs(message->msgSeq);
               context->txMsgSeq = ntohs(message->msgSeq);
            }
         }
      }

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //DTLS 1.3 protocol?
      if(context->version == TLS_VERSION_1_3)
      {
         //DTLS 1.3 assigns dedicated epoch values to messages in the protocol
         //exchange to allow identification of the correct cipher state (refer
         //to RFC 9147, section 6.1)
         if(message->msgType == TLS_TYPE_CLIENT_HELLO ||
            message->msgType == TLS_TYPE_SERVER_HELLO ||
            message->msgType == TLS_TYPE_HELLO_RETRY_REQUEST)
         {
            //Epoch value 0 is used with unencrypted messages
            if(context->rxRecordNum.epoch != 0)
               return ERROR_INVALID_EPOCH;
         }
         else if(message->msgType == TLS_TYPE_NEW_SESSION_TICKET ||
            message->msgType == TLS_TYPE_REQUEST_CONNECTION_ID ||
            message->msgType == TLS_TYPE_NEW_CONNECTION_ID ||
            message->msgType == TLS_TYPE_KEY_UPDATE)
         {
            //Epoch values 3 to 2^64-1 are used for post-handshake messages
            if(context->rxRecordNum.epoch < 3)
               return ERROR_INVALID_EPOCH;
         }
         else
         {
            //Epoch value 2 is used for messages transmitted during the initial
            //handshake
            if(context->rxRecordNum.epoch != 2)
               return ERROR_INVALID_EPOCH;
         }

         //Check current state
         if(context->state != TLS_STATE_SERVER_HELLO &&
            context->state != TLS_STATE_SERVER_HELLO_2 &&
            context->state != TLS_STATE_CLIENT_FINISHED_ACK)
         {
            //Check whether the sequence number of the received message matches
            //the expected value
            if(ntohs(message->msgSeq) == context->rxMsgSeq)
            {
               //Receiving a message from a handshake flight implicitly
               //acknowledges all messages from the previous flight (refer to
               //RFC 9147, section 7)
               context->txBufferLen = 0;
            }
         }
      }

      //Check whether DTLS 1.3 is supported
      if(context->versionMax >= TLS_VERSION_1_3 &&
         context->versionMin <= TLS_VERSION_1_3)
      {
         //Implementations must not send ACKs for handshake messages which they
         //discard because they are not the next expected message (refer to
         //RFC 9147, section 7)
         if(ntohs(message->msgSeq) <= context->rxMsgSeq)
         {
            dtls13SaveRecordNumber(context, context->rxRecordNum.epoch,
               context->rxRecordNum.seqNum);
         }
      }
#endif

      //When a peer receives a handshake message, it can quickly determine
      //whether that message is the next message it expects
      if(ntohs(message->msgSeq) < context->rxMsgSeq)
      {
         //Retransmitted flight from the peer?
         if(message->msgType == TLS_TYPE_CLIENT_HELLO ||
            message->msgType == TLS_TYPE_SERVER_HELLO_DONE ||
            message->msgType == TLS_TYPE_FINISHED)
         {
            //First fragment of the handshake message?
            if(LOAD24BE(message->fragOffset) == 0)
            {
               //Check whether a flight of messages is buffered
               if(context->txBufferLen > 0)
               {
                  //Get current time
                  time = osGetSystemTime();

                  //Send only one response in the case multiple retransmitted
                  //flights are received from the peer
                  if((time - context->retransmitTimestamp) >= DTLS_MIN_TIMEOUT)
                  {
                     //The implementation transitions to the SENDING state,
                     //where it retransmits the flight, resets the retransmit
                     //timer, and returns to the WAITING state
                     if(context->retransmitCount < DTLS_MAX_RETRIES)
                     {
                        dtlsSendFlight(context);
                     }
                  }
               }
            }
         }

         //If the sequence number of the received message is less than the
         //expected value, the message must be discarded
         return ERROR_INVALID_SEQUENCE_NUMBER;
      }
      else if(ntohs(message->msgSeq) > context->rxMsgSeq)
      {
         //If the sequence number of the received message is greater than the
         //expected value, the implementation may discard it
         return ERROR_INVALID_SEQUENCE_NUMBER;
      }
      else
      {
         //If the sequence number of the received message matches the expected
         //value, the message is processed
      }

      //Check current state
      if(context->state > TLS_STATE_SERVER_HELLO_2)
      {
         //Once the server has sent the ServerHello message, enforce the version
         //of incoming records
         if(context->rxRecordVersion != dtlsTranslateVersion(context->version))
            return ERROR_VERSION_NOT_SUPPORTED;
      }

      //When a DTLS implementation receives a handshake message fragment, it
      //must buffer it until it has the entire handshake message. DTLS
      //implementations must be able to handle overlapping fragment ranges
      error = dtlsReassembleHandshakeMessage(context, message);
      //Unacceptable message received?
      if(error)
      {
         //Flush the reassembly queue
         context->rxFragQueueLen = 0;
         //Report an error
         return error;
      }

      //Point to the first fragment of the reassembly queue
      message = (DtlsHandshake *) context->rxBuffer;
      //Retrive the length of the handshake message
      length = LOAD24BE(message->length);

      //An unfragmented message is a degenerate case with fragment_offset = 0
      //and fragment_length = length
      if(LOAD24BE(message->fragOffset) == 0 &&
         LOAD24BE(message->fragLength) == length)
      {
         //The reassembly process is now complete
         context->rxFragQueueLen = 0;

         //Number of bytes available for reading
         context->rxBufferLen = length + sizeof(DtlsHandshake);
         //Rewind to the beginning of the buffer
         context->rxBufferPos = 0;

         //The message sequence number is incremented by one
         context->rxMsgSeq++;

         //Version of TLS prior to TLS 1.3?
         if(context->version <= TLS_VERSION_1_2)
         {
            //Check whether a complete flight of messages has been received
            if(message->msgType == TLS_TYPE_CLIENT_HELLO ||
               message->msgType == TLS_TYPE_HELLO_VERIFY_REQUEST ||
               message->msgType == TLS_TYPE_SERVER_HELLO_DONE ||
               message->msgType == TLS_TYPE_FINISHED)
            {
               //Exit from the WAITING state
               context->txBufferLen = 0;
            }
         }
      }
   }
   else
   {
      //ChangeCipherSpec message received?
      if(context->rxBufferType == TLS_TYPE_CHANGE_CIPHER_SPEC)
      {
         //Malformed ChangeCipherSpec message?
         if(context->rxRecordLen < sizeof(TlsChangeCipherSpec))
         {
            //Drop the received DTLS record
            context->rxRecordLen = 0;
            //Report an error
            return ERROR_INVALID_LENGTH;
         }

         //DTLS operates as a client or a server?
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            //Check current state
            if(context->state != TLS_STATE_SERVER_CHANGE_CIPHER_SPEC)
            {
               //Drop the received DTLS record
               context->rxRecordLen = 0;
               //Report an error
               return ERROR_UNEXPECTED_MESSAGE;
            }
         }
         else
         {
            //Check current state
            if(context->state != TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC)
            {
               //Drop the received DTLS record
               context->rxRecordLen = 0;
               //Report an error
               return ERROR_UNEXPECTED_MESSAGE;
            }
         }

         //Enforce the version the received DTLS record
         if(context->rxRecordVersion != dtlsTranslateVersion(context->version))
         {
            //Drop the received DTLS record
            context->rxRecordLen = 0;
            //Report an error
            return ERROR_VERSION_NOT_SUPPORTED;
         }
      }
      //Alert message received?
      else if(context->rxBufferType == TLS_TYPE_ALERT)
      {
         //Malformed Alert message?
         if(context->rxRecordLen < sizeof(TlsAlert))
         {
            //Drop the received DTLS record
            context->rxRecordLen = 0;
            //Report an error
            return ERROR_INVALID_LENGTH;
         }
      }
      //Application data received?
      else if(context->rxBufferType == TLS_TYPE_APPLICATION_DATA)
      {
         //Check current state
         if(context->state == TLS_STATE_APPLICATION_DATA ||
            context->state == TLS_STATE_CLIENT_FINISHED_ACK ||
            context->state == TLS_STATE_NEW_SESSION_TICKET_ACK ||
            context->state == TLS_STATE_KEY_UPDATE_ACK)
         {
            //Version of TLS prior to TLS 1.3?
            if(context->version <= TLS_VERSION_1_2)
            {
               //The last flight of messages has been received by the peer
               context->txBufferLen = 0;
            }
         }
         else
         {
            //Drop the received DTLS record
            context->rxRecordLen = 0;
            //Report an error
            return ERROR_UNEXPECTED_MESSAGE;
         }

         //Enforce the version the received DTLS record
         if(context->rxRecordVersion != dtlsTranslateVersion(context->version))
         {
            //Drop the received DTLS record
            context->rxRecordLen = 0;
            //Report an error
            return ERROR_VERSION_NOT_SUPPORTED;
         }

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
         //DTLS 1.3 assigns dedicated epoch values to messages in the protocol
         //exchange to allow identification of the correct cipher state (refer
         //to RFC 9147, section 6.1)
         if(context->version == TLS_VERSION_1_3)
         {
            //Epoch values 3 to 2^64-1 are used for application data messages
            if(context->rxRecordNum.epoch < 3)
            {
               //Drop the received DTLS record
               context->rxRecordLen = 0;
               //Report an error
               return ERROR_INVALID_EPOCH;
            }
         }
#endif
      }
      //ACK message received?
      else if(context->rxBufferType == TLS_TYPE_ACK)
      {
         //Malformed ACK message?
         if(context->rxRecordLen < sizeof(Dtls13Ack))
         {
            //Drop the received DTLS record
            context->rxRecordLen = 0;
            //Report an error
            return ERROR_INVALID_LENGTH;
         }
      }
      //Unknown content type?
      else
      {
         //Drop the received DTLS record
         context->rxRecordLen = 0;
         //Report an error
         return ERROR_UNEXPECTED_MESSAGE;
      }

      //Number of bytes available for reading
      context->rxBufferLen = context->rxRecordLen;
      //Rewind to the beginning of the buffer
      context->rxBufferPos = 0;

      //Copy application data
      osMemcpy(context->rxBuffer, context->rxBuffer + context->rxRecordPos,
         context->rxRecordLen);

      //The DTLS record has been entirely processed
      context->rxRecordLen = 0;
      //Flush the reassembly queue
      context->rxFragQueueLen = 0;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Send the buffered flight of messages
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t dtlsSendFlight(TlsContext *context)
{
   error_t error;
   uint_t i;
   size_t n;
   size_t pmtu;
   uint8_t *datagram;
   DtlsRecord *record;
   DtlsHandshake *message;
   TlsEncryptionEngine *encryptionEngine;

   //Determine the value of the PMTU
   pmtu = MIN(context->pmtu, context->txBufferSize - context->txBufferLen);

   //Make sure the PMTU value is acceptable
   if(pmtu < DTLS_MIN_PMTU)
      return ERROR_BUFFER_OVERFLOW;

   //Point to the buffer where to format the datagram
   datagram = context->txBuffer + context->txBufferLen;
   //Length of the datagram, in bytes
   context->txDatagramLen = 0;
   //Point to the first message of the flight
   context->txBufferPos = 0;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //Initial transmission?
   if(context->retransmitCount == 0)
   {
      //Initialize retransmission state
      osMemset(&context->encryptionEngine[0].retransmitState, 0,
         sizeof(Dtls13RetransmitState));

      osMemset(&context->encryptionEngine[1].retransmitState, 0,
         sizeof(Dtls13RetransmitState));

      osMemset(&context->encryptionEngine[2].retransmitState, 0,
         sizeof(Dtls13RetransmitState));
   }

   //Prepare to send the first packet of the flight
   context->encryptionEngine[0].retransmitState.index = 0;
   context->encryptionEngine[1].retransmitState.index = 0;
   context->encryptionEngine[2].retransmitState.index = 0;
#endif

   //In the SENDING state, the implementation transmits the buffered flight of
   //messages (refer to RFC 6347, section 4.2.4)
   while(context->txBufferPos < context->txBufferLen)
   {
      //Point to the current DTLS record
      record = (DtlsRecord *) (context->txBuffer + context->txBufferPos);

      //Advance data pointer
      context->txBufferPos += ntohs(record->length) + sizeof(DtlsRecord);

      //Implementations must send retransmissions of lost messages using the
      //same epoch and keying material as the original transmission
      for(encryptionEngine = NULL, i = 0; i < TLS_MAX_ENCRYPTION_ENGINES; i++)
      {
         //Compare epochs
         if(context->encryptionEngine[i].epoch == ntohs(record->epoch))
         {
            encryptionEngine = &context->encryptionEngine[i];
            break;
         }
      }

      //Invalid keying material?
      if(encryptionEngine == NULL)
         return ERROR_INVALID_EPOCH;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //Save the sequence number of the first packet of the flight
      if(context->retransmitCount == 0 ||
         context->state == TLS_STATE_APPLICATION_DATA ||
         context->state == TLS_STATE_CLIENT_FINISHED_ACK ||
         context->state == TLS_STATE_NEW_SESSION_TICKET_ACK ||
         context->state == TLS_STATE_KEY_UPDATE_ACK)
      {
         //First packet of the flight?
         if(encryptionEngine->retransmitState.index == 0)
         {
            encryptionEngine->retransmitState.start =
               LOAD48BE(encryptionEngine->dtlsSeqNum.b);
         }
      }
#endif

      //Handshake message?
      if(record->type == TLS_TYPE_HANDSHAKE)
      {
         //Point to the handshake message header to be fragmented
         message = (DtlsHandshake *) record->data;

         //Fragment handshake message into smaller fragments
         error = dtlsFragmentHandshakeMessage(context, ntohs(record->version),
            encryptionEngine, message);
         //Any error to report?
         if(error)
            return error;
      }
      else
      {
         //Any datagram pending to be sent?
         if(context->txDatagramLen > 0)
         {
            //Estimate the length of the DTLS record
            n = ntohs(record->length) + sizeof(DtlsRecord);
            //Overhead caused by record encryption must be considered
            n += tlsComputeEncryptionOverhead(encryptionEngine, n);

            //Records may not span datagrams
            if((context->txDatagramLen + n) > pmtu)
            {
               //Debug message
               TRACE_INFO("Sending UDP datagram (%" PRIuSIZE " bytes)...\r\n",
                  context->txDatagramLen);

               //Send datagram
               error = context->socketSendCallback(context->socketHandle,
                  datagram, context->txDatagramLen, &n, 0);
               //Any error to report?
               if(error)
                  return error;

               //The datagram has been successfully transmitted
               context->txDatagramLen = 0;
            }
         }

         //Estimate the length of the DTLS record
         n = ntohs(record->length) + sizeof(DtlsRecord);
         //Overhead caused by record encryption must be considered
         n += tlsComputeEncryptionOverhead(encryptionEngine, n);

         //Make sure the buffer is large enough to hold the DTLSCiphertext
         //record
         if((context->txBufferLen + context->txDatagramLen + n) > context->txBufferSize)
            return ERROR_BUFFER_OVERFLOW;

         //Multiple DTLS records may be placed in a single datagram. They are
         //simply encoded consecutively
         osMemcpy(datagram + context->txDatagramLen, record,
            ntohs(record->length) + sizeof(DtlsRecord));

         //Point to the DTLS record header
         record = (DtlsRecord *) (datagram + context->txDatagramLen);

         //From the perspective of the DTLS record layer, the retransmission is
         //a new record. This record will have a new sequence number
         record->seqNum = encryptionEngine->dtlsSeqNum;

         //Protect record payload?
         if(encryptionEngine->cipherMode != CIPHER_MODE_NULL ||
            encryptionEngine->hashAlgo != NULL)
         {
            //Encrypt DTLS record
            error = tlsEncryptRecord(context, encryptionEngine, record);
            //Any error to report?
            if(error)
               return error;
         }

         //Debug message
         TRACE_DEBUG("Encrypted DTLS record (%" PRIuSIZE " bytes)...\r\n", ntohs(record->length));
         TRACE_DEBUG_ARRAY("  ", record, ntohs(record->length) + sizeof(DtlsRecord));

         //Increment sequence number
         dtlsIncSequenceNumber(&encryptionEngine->dtlsSeqNum);

         //Adjust the length of the datagram
         context->txDatagramLen += ntohs(record->length) + sizeof(DtlsRecord);
      }
   }

   //Any datagram pending to be sent?
   if(context->txDatagramLen > 0)
   {
      //Debug message
      TRACE_INFO("Sending UDP datagram (%" PRIuSIZE " bytes)...\r\n",
         context->txDatagramLen);

      //Send datagram
      error = context->socketSendCallback(context->socketHandle, datagram,
         context->txDatagramLen, &n, 0);
      //Any error to report?
      if(error)
         return error;

      //The datagram has been successfully transmitted
      context->txDatagramLen = 0;
   }

   //Save the time at which the flight of messages was sent
   context->retransmitTimestamp = osGetSystemTime();
   //Increment retransmission counter
   context->retransmitCount++;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Handshake message fragmentation
 * @param[in] context Pointer to the TLS context
 * @param[in] version DTLS version to be used
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @param[in] message Pointer the handshake message to be fragmented
 * @return Error code
 **/

error_t dtlsFragmentHandshakeMessage(TlsContext *context, uint16_t version,
   TlsEncryptionEngine *encryptionEngine, const DtlsHandshake *message)
{
   error_t error;
   size_t n;
   size_t pmtu;
   size_t totalLength;
   size_t fragOffset;
   size_t fragLen;
   size_t maxFragSize;
   uint8_t *datagram;
   DtlsRecord *record;
   DtlsHandshake *fragment;

   //Determine the value of the PMTU
   pmtu = MIN(context->pmtu, context->txBufferSize - context->txBufferLen);

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //The DTLS 1.3 record layer is different from the DTLS 1.2 record layer
   if(context->version == TLS_VERSION_1_3 &&
      (encryptionEngine->cipherMode != CIPHER_MODE_NULL ||
      encryptionEngine->hashAlgo != NULL))
   {
      //DTLS handshake messages have 12 bytes of overhead
      n = sizeof(DtlsHandshake);
      //Overhead caused by record encryption must be considered
      n += dtls13ComputeEncryptionOverhead(encryptionEngine);
   }
   else
#endif
   {
      //DTLS records have 25 bytes of overhead
      n = sizeof(DtlsRecord) + sizeof(DtlsHandshake);
      //Overhead caused by record encryption must be considered
      n += tlsComputeEncryptionOverhead(encryptionEngine, 0);
   }

   //Make sure the PMTU value is acceptable
   if(pmtu <= n || pmtu < DTLS_MIN_PMTU)
      return ERROR_BUFFER_OVERFLOW;

   //Determine the maximum payload size for fragmented messages
   maxFragSize = pmtu - n;

   //Point to the buffer where to format the datagram
   datagram = context->txBuffer + context->txBufferLen;
   //Get the length of the handshake message
   totalLength = LOAD24BE(message->length);
   //Prepare to send the first fragment
   fragOffset = 0;

   //Fragmentation process
   do
   {
      //Calculate the length of the current fragment
      fragLen = MIN(totalLength - fragOffset, maxFragSize);

      //Any datagram pending to be sent?
      if(context->txDatagramLen > 0)
      {
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
         //The DTLS 1.3 record layer is different from the DTLS 1.2 record layer
         if(context->version == TLS_VERSION_1_3 &&
            (encryptionEngine->cipherMode != CIPHER_MODE_NULL ||
            encryptionEngine->hashAlgo != NULL))
         {
            //Estimate the length of the DTLS handshake message
            n = fragLen + sizeof(DtlsHandshake);
            //Overhead caused by record encryption must be considered
            n += dtls13ComputeEncryptionOverhead(encryptionEngine);
         }
         else
#endif
         {
            //Estimate the length of the DTLS record
            n = fragLen + sizeof(DtlsRecord) + sizeof(DtlsHandshake);
            //Overhead caused by record encryption must be considered
            n += tlsComputeEncryptionOverhead(encryptionEngine, n);
         }

         //Records may not span datagrams
         if((context->txDatagramLen + n) > pmtu)
         {
            //Debug message
            TRACE_INFO("Sending UDP datagram (%" PRIuSIZE " bytes)...\r\n",
               context->txDatagramLen);

            //Send datagram
            error = context->socketSendCallback(context->socketHandle,
               datagram, context->txDatagramLen, &n, 0);
            //Any error to report?
            if(error)
               return error;

            //The datagram has been successfully transmitted
            context->txDatagramLen = 0;
         }
      }

      //Multiple DTLS records may be placed in a single datagram. They are
      //simply encoded consecutively
      record = (DtlsRecord *) (datagram + context->txDatagramLen);

      //The DTLS 1.3 record layer is different from the DTLS 1.2 record layer
      if(context->version == TLS_VERSION_1_3 &&
         (encryptionEngine->cipherMode != CIPHER_MODE_NULL ||
         encryptionEngine->hashAlgo != NULL))
      {
         //Point to the handshake message header
         fragment = (DtlsHandshake *) (datagram + context->txDatagramLen);
      }
      else
      {
         //Format DTLS record
         record->type = TLS_TYPE_HANDSHAKE;
         record->version = htons(version);
         record->epoch = htons(encryptionEngine->epoch);
         record->seqNum = encryptionEngine->dtlsSeqNum;
         record->length = htons(fragLen + sizeof(DtlsHandshake));

         //Point to the handshake message header
         fragment = (DtlsHandshake *) record->data;
      }

      //Handshake message type
      fragment->msgType = message->msgType;
      //Number of bytes in the message
      STORE24BE(totalLength, fragment->length);
      //Message sequence number
      fragment->msgSeq = message->msgSeq;
      //Fragment offset
      STORE24BE(fragOffset, fragment->fragOffset);
      //Fragment length
      STORE24BE(fragLen, fragment->fragLength);

      //Copy data
      osMemcpy(fragment->data, message->data + fragOffset, fragLen);

      //Debug message
      TRACE_DEBUG("Sending handshake message fragment (%" PRIuSIZE " bytes)...\r\n",
         LOAD24BE(fragment->fragLength));
      TRACE_DEBUG("  msgType = %u\r\n", fragment->msgType);
      TRACE_DEBUG("  msgSeq = %u\r\n", ntohs(fragment->msgSeq));
      TRACE_DEBUG("  fragOffset = %u\r\n", LOAD24BE(fragment->fragOffset));
      TRACE_DEBUG("  fragLength = %u\r\n", LOAD24BE(fragment->fragLength));
      TRACE_DEBUG("  length = %u\r\n", LOAD24BE(fragment->length));

      //Protect record payload?
      if(encryptionEngine->cipherMode != CIPHER_MODE_NULL ||
         encryptionEngine->hashAlgo != NULL)
      {
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
         //DTLS 1.3 protocol?
         if(context->version == TLS_VERSION_1_3)
         {
            //Encrypt DTLS 1.3 record
            error = dtls13EncryptRecord(context, encryptionEngine,
               TLS_TYPE_HANDSHAKE, (uint8_t *) fragment,
               fragLen + sizeof(DtlsHandshake), (uint8_t *) record, &n);
            //Any error to report?
            if(error)
               return error;
         }
         else
#endif
         {
            //Encrypt DTLS record
            error = tlsEncryptRecord(context, encryptionEngine, record);
            //Any error to report?
            if(error)
               return error;

            //Length of the resulting datagram, in bytes
            n = ntohs(record->length) + sizeof(DtlsRecord);
         }
      }
      else
      {
         //Length of the datagram, in bytes
         n = ntohs(record->length) + sizeof(DtlsRecord);
      }

      //Debug message
      TRACE_DEBUG("Encrypted DTLS record (%" PRIuSIZE " bytes)...\r\n", n);
      TRACE_DEBUG_ARRAY("  ", record, n);

      //Increment sequence number
      dtlsIncSequenceNumber(&encryptionEngine->dtlsSeqNum);

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //DTLS 1.3 protocol?
      if(context->version == TLS_VERSION_1_3)
      {
         Dtls13RetransmitState *retransmitState;

         //Point to the retransmission state
         retransmitState = &encryptionEngine->retransmitState;

         //Initial transmission?
         if(context->retransmitCount == 0)
         {
            //Each flight may consist of a number of records
            retransmitState->count++;
            //The record is initially marked as unacknowledged
            retransmitState->mask = (retransmitState->mask << 1) | 1;
         }
         else
         {
            //An implementation should omit ACKed records from any future
            //retransmissions
            if(retransmitState->index < 32 &&
               (retransmitState->mask & (1 << retransmitState->index)) == 0)
            {
               n = 0;
            }
         }

         //Next record of the flight
         retransmitState->index++;
      }
#endif

      //Adjust the length of the datagram
      context->txDatagramLen += n;
      //Next fragment
      fragOffset += fragLen;

      //Check whether fragmentation process is complete
   } while(fragOffset < totalLength);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Handshake message reassembly algorithm
 * @param[in] context Pointer to the TLS context
 * @param[in] message Pointer the newly arrived fragment
 * @return Error code
 **/

error_t dtlsReassembleHandshakeMessage(TlsContext *context,
   const DtlsHandshake *message)
{
   size_t n;
   size_t pos;
   size_t fragOffset;
   size_t fragLen;
   size_t prevFragOffset;
   size_t prevFragLen;
   DtlsHandshake *fragment;
   DtlsHandshake *prevFragment;

   //Retrieve fragment offset
   fragOffset = LOAD24BE(message->fragOffset);
   //Retrieve fragment length
   fragLen = LOAD24BE(message->fragLength) + sizeof(DtlsHandshake);

   //Point to the beginning of the reassembly queue
   pos = 0;

   //Loop through the reassembly queue
   while(pos < context->rxFragQueueLen)
   {
      //Point to the current fragment
      fragment = (DtlsHandshake *) (context->rxBuffer + pos);

      //Message type mismatch?
      if(message->msgType != fragment->msgType)
         return ERROR_UNEXPECTED_MESSAGE;

      //Message length mismatch?
      if(LOAD24BE(message->length) != LOAD24BE(fragment->length))
         return ERROR_UNEXPECTED_MESSAGE;

      //Sort fragments in ascending order
      if(fragOffset < LOAD24BE(fragment->fragOffset))
         break;

      //Next fragment
      pos += LOAD24BE(fragment->fragLength) + sizeof(DtlsHandshake);
   }

   //Sanity check
   if((context->rxFragQueueLen + fragLen) >
      (context->rxBufferSize - context->rxDatagramLen))
   {
      return ERROR_BUFFER_OVERFLOW;
   }

   //Position where to insert the new fragment
   fragment = (DtlsHandshake *) (context->rxBuffer + pos);

   //Make room for the new fragment
   osMemmove(context->rxBuffer + pos + fragLen, fragment,
      context->rxFragQueueLen - pos);

   //Insert the new fragment in the reassembly queue
   osMemcpy(fragment, message, fragLen);
   //Update the length of the reassembly queue
   context->rxFragQueueLen += fragLen;

   //Point to the first fragment of the reassembly queue
   prevFragment = (DtlsHandshake *) context->rxBuffer;
   //Retrieve fragment offset
   prevFragOffset = LOAD24BE(prevFragment->fragOffset);
   //Retrieve fragment length
   prevFragLen = LOAD24BE(prevFragment->fragLength);

   //Position of the next fragment
   pos = prevFragLen + sizeof(DtlsHandshake);

   //Loop through the reassembly queue
   while(pos < context->rxFragQueueLen)
   {
      //Point to the current fragment
      fragment = (DtlsHandshake *) (context->rxBuffer + pos);
      //Retrieve fragment offset
      fragOffset = LOAD24BE(fragment->fragOffset);
      //Retrieve fragment length
      fragLen = LOAD24BE(fragment->fragLength);

      //Check whether the current fragment interacts in some way with the
      //previous fragment
      if(fragOffset <= (prevFragOffset + prevFragLen))
      {
         //DTLS implementations must be able to handle overlapping fragment
         //ranges
         if((fragOffset + fragLen) > (prevFragOffset + prevFragLen))
         {
            //Coalesce overlapping fragments
            osMemmove(prevFragment->data + fragOffset - prevFragOffset,
               fragment->data,
               context->rxFragQueueLen - pos - sizeof(DtlsHandshake));

            //Number of bytes that do not overlap with the previous fragment
            n = fragOffset + fragLen - prevFragOffset - prevFragLen;

            //Update the length of the reassembly queue
            context->rxFragQueueLen -= fragLen - n + sizeof(DtlsHandshake);

            //Adjust the length of the previous fragment
            prevFragLen += n;
            //Fix fragment length field
            STORE24BE(prevFragLen, prevFragment->fragLength);

            //Jump to the next fragment
            pos += n;
         }
         else
         {
            //Drop current fragment
            osMemmove(fragment, fragment->data + fragLen,
               context->rxFragQueueLen - fragLen - sizeof(DtlsHandshake));

            //Update the length of the reassembly queue
            context->rxFragQueueLen -= fragLen + sizeof(DtlsHandshake);
         }
      }
      else
      {
         //Jump to the next fragment
         pos += fragLen + sizeof(DtlsHandshake);

         //Keep track of the previous fragment
         prevFragment = fragment;
         prevFragOffset = fragOffset;
         prevFragLen = fragLen;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Receive a datagram
 * @param[in] context Pointer to the TLS context
 * @param[out] data Buffer where to store the incoming datagram
 * @param[in] size Maximum number of bytes that can be received
 * @param[out] length Number of bytes that have been received
 * @return Error code
 **/

error_t dtlsReadDatagram(TlsContext *context, uint8_t *data,
   size_t size, size_t *length)
{
   error_t error;
   systime_t time;

   //Initialize status code
   error = NO_ERROR;

   //Wait for an incoming datagram
   while(!error)
   {
      //Receive datagram
      error = context->socketReceiveCallback(context->socketHandle, data,
         size, length, 0);

      //Check status code
      if(error == NO_ERROR)
      {
         //Debug message
         TRACE_INFO("UDP datagram received (%" PRIuSIZE " bytes)...\r\n", *length);
         TRACE_DEBUG_ARRAY("  ", data, *length);

         //A datagram has been successfully received
         break;
      }
      else if(error == ERROR_WOULD_BLOCK)
      {
         //Manage retransmission timer
         error = dtlsTick(context);

         //Check status code
         if(!error)
         {
            //Exit immediately
            error = ERROR_WOULD_BLOCK;
         }
      }
      else if(error == ERROR_TIMEOUT)
      {
         //Manage retransmission timer
         error = dtlsTick(context);

         //Check status code
         if(!error)
         {
            //Check whether a timeout has been specified
            if(context->timeout != INFINITE_DELAY)
            {
               //Get current time
               time = osGetSystemTime();

               //Check whether the timeout has elapsed
               if((time - context->startTime) >= context->timeout)
               {
                  //Exit immediately
                  error = ERROR_TIMEOUT;
               }
            }
         }
      }
      else
      {
         //The read operation has failed
         error = ERROR_READ_FAILED;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Manage retransmission timers
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t dtlsTick(TlsContext *context)
{
   error_t error;
   systime_t time;

   //Initialize status code
   error = NO_ERROR;

   //Get current time
   time = osGetSystemTime();

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //DTLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      uint_t i;

      //Loop through the decryption engines
      for(i = 0; i < TLS_MAX_DECRYPTION_ENGINES; i++)
      {
         //Valid decryption engine?
         if(context->decryptionEngine[i].active)
         {
            //Any lifetime specified?
            if(context->decryptionEngine[i].lifetime > 0)
            {
               //Check whether the lifetime has expired
               if((time - context->decryptionEngine[i].timestamp) >=
                  context->decryptionEngine[i].lifetime)
               {
                  tlsFreeEncryptionEngine(&context->decryptionEngine[i]);
                  context->decryptionEngine[i].epoch = 0;
               }
            }
         }
      }

      //Check whether the ACK timer is running
      if(context->ackTimerRunning)
      {
         //It is recommended that implementations generate ACKs when they have
         //received part of a flight and do not immediately receive the rest of the
         //flight. One approach is to set a timer for 1/4 the current retransmit
         //timer value when the first record in the flight is received and then
         //send an ACK when that timer expires (refer to RFC 9147, section 7.1)
         if((time - context->ackTimestamp) >= (context->retransmitTimeout / 4))
         {
            //Generate ACKs
            dtls13SendAck(context);
            //Stop the ACK timer
            context->ackTimerRunning = FALSE;
         }
      }
   }
#endif

   //Check current state
   if(context->state != TLS_STATE_APPLICATION_DATA)
   {
      //Any flight of messages buffered?
      if(context->txBufferLen > 0)
      {
         //Check whether the retransmission timer has expired
         if((time - context->retransmitTimestamp) >= context->retransmitTimeout)
         {
            //Check retransmission counter
            if(context->retransmitCount < DTLS_MAX_RETRIES)
            {
               //The implementation transitions to the SENDING state, where
               //it retransmits the flight, resets the retransmit timer, and
               //returns to the WAITING state
               error = dtlsSendFlight(context);

               //Double the value at each retransmission, up to no less than
               //the RFC 6298 maximum of 60 seconds
               context->retransmitTimeout = MIN(context->retransmitTimeout * 2,
                  DTLS_MAX_TIMEOUT);
            }
            else
            {
               //The maximum number of retransmissions has been exceeded
               error = ERROR_HANDSHAKE_FAILED;
            }
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Increment sequence number
 * @param[in,out] seqNum Pointer to the 48-bit sequence number
 **/

void dtlsIncSequenceNumber(DtlsSequenceNumber *seqNum)
{
   uint16_t temp;

   //Sequence numbers are stored MSB first
   temp = seqNum->b[5] + 1;
   seqNum->b[5] = temp & 0xFF;
   temp = (temp >> 8) + seqNum->b[4];
   seqNum->b[4] = temp & 0xFF;
   temp = (temp >> 8) + seqNum->b[3];
   seqNum->b[3] = temp & 0xFF;
   temp = (temp >> 8) + seqNum->b[2];
   seqNum->b[2] = temp & 0xFF;
   temp = (temp >> 8) + seqNum->b[1];
   seqNum->b[1] = temp & 0xFF;
   temp = (temp >> 8) + seqNum->b[0];
   seqNum->b[0] = temp & 0xFF;
}

#endif
