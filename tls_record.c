/**
 * @file tls_record.c
 * @brief TLS record protocol
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
 * @version 1.7.8
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include <string.h>
#include "tls.h"
#include "tls_common.h"
#include "tls_record.h"
#include "tls_misc.h"
#include "ssl_common.h"
#include "cipher_mode_cbc.h"
#include "cipher_mode_ccm.h"
#include "cipher_mode_gcm.h"
#include "chacha20_poly1305.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Write protocol data
 * @param[in] context Pointer to the TLS context
 * @param[in] data Pointer to the data buffer
 * @param[in] length Number of data bytes to be written
 * @param[in] contentType Higher level protocol
 * @return Error code
 **/

error_t tlsWriteProtocolData(TlsContext *context,
   const void *data, size_t length, TlsContentType contentType)
{
   error_t error;
   size_t n;
   uint8_t *p;

   //Initialize status code
   error = NO_ERROR;

   //Fragmentation process
   while(!error)
   {
      if(context->txBufferLen == 0)
      {
         //Check the length of the data
         if(length > context->txRecordMaxLen)
         {
            //Report an error
            error = ERROR_MESSAGE_TOO_LONG;
         }
         else if(length > 0)
         {
            //The hash value is updated for each handshake message,
            //except for HelloRequest messages
            if(contentType == TLS_TYPE_HANDSHAKE)
               tlsUpdateHandshakeHash(context, data, length);

            //Make room for the encryption overhead
            memmove(context->txBuffer + context->txBufferSize - length, data, length);

            //Save record type
            context->txBufferType = contentType;
            //Set the length of the buffer
            context->txBufferLen = length;
            //Point to the beginning of the buffer
            context->txBufferPos = 0;
         }
         else
         {
            //We are done
            break;
         }
      }
      else if(context->txBufferPos < context->txBufferLen)
      {
         //Number of bytes left to send
         n = context->txBufferLen - context->txBufferPos;
         //Point to the current fragment
         p = context->txBuffer + context->txBufferSize - n;
         //The record length must not exceed 16384 bytes
         n = MIN(n, TLS_MAX_RECORD_LENGTH);

         //Send TLS record
         error = tlsWriteRecord(context, p, n, context->txBufferType);

         //Check status code
         if(!error)
         {
            //Advance data pointer
            context->txBufferPos += n;
         }
      }
      else
      {
         //Prepare to send new protocol data
         context->txBufferLen = 0;
         context->txBufferPos = 0;

         //We are done
         break;
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

error_t tlsReadProtocolData(TlsContext *context,
   void **data, size_t *length, TlsContentType *contentType)
{
   error_t error;
   size_t n;
   TlsContentType type;
   TlsHandshake *message;

   //Initialize status code
   error = NO_ERROR;

   //Fragment reassembly process
   do
   {
      //Empty receive buffer?
      if(context->rxBufferLen == 0)
      {
         //Read a TLS record
         error = tlsReadRecord(context, context->rxBuffer,
            context->rxBufferSize, &n, &type);

         //Check status code
         if(!error)
         {
            //Save record type
            context->rxBufferType = type;
            //Number of bytes available for reading
            context->rxBufferLen = n;
            //Rewind to the beginning of the buffer
            context->rxBufferPos = 0;
         }
      }
      //Imcomplete message received?
      else if(error == ERROR_MORE_DATA_REQUIRED)
      {
         //Make room at the end of the buffer
         if(context->rxBufferPos > 0)
         {
            //Move unread data to the beginning of the buffer
            memmove(context->rxBuffer, context->rxBuffer +
               context->rxBufferPos, context->rxBufferLen);

            //Rewind to the beginning of the buffer
            context->rxBufferPos = 0;
         }

         //Read a TLS record
         error = tlsReadRecord(context, context->rxBuffer + context->rxBufferLen,
            context->rxBufferSize - context->rxBufferLen, &n, &type);

         //Check status code
         if(!error)
         {
            //Fragmented records with mixed types cannot be interleaved
            if(type != context->rxBufferType)
               error = ERROR_UNEXPECTED_MESSAGE;
         }

         //Check status code
         if(!error)
         {
            //Number of bytes available for reading
            context->rxBufferLen += n;
         }
      }

      //Check status code
      if(!error)
      {
         //Handshake message received?
         if(context->rxBufferType == TLS_TYPE_HANDSHAKE)
         {
            //A message may be fragmented across several records
            if(context->rxBufferLen < sizeof(TlsHandshake))
            {
               //Read an additional record
               error = ERROR_MORE_DATA_REQUIRED;
            }
            else
            {
               //Point to the handshake message
               message = (TlsHandshake *) (context->rxBuffer + context->rxBufferPos);
               //Retrieve the length of the handshake message
               n = sizeof(TlsHandshake) + LOAD24BE(message->length);

               //A message may be fragmented across several records
               if(context->rxBufferLen < n)
               {
                  //Read an additional record
                  error = ERROR_MORE_DATA_REQUIRED;
               }
               else
               {
                  //Pass the handshake message to the higher layer
                  error = NO_ERROR;
               }
            }
         }
         //ChangeCipherSpec message received?
         else if(context->rxBufferType == TLS_TYPE_CHANGE_CIPHER_SPEC)
         {
            //A message may be fragmented across several records
            if(context->rxBufferLen < sizeof(TlsChangeCipherSpec))
            {
               //Read an additional record
               error = ERROR_MORE_DATA_REQUIRED;
            }
            else
            {
               //Length of the ChangeCipherSpec message
               n = sizeof(TlsChangeCipherSpec);
               //Pass the ChangeCipherSpec message to the higher layer
               error = NO_ERROR;
            }
         }
         //Alert message received?
         else if(context->rxBufferType == TLS_TYPE_ALERT)
         {
            //A message may be fragmented across several records
            if(context->rxBufferLen < sizeof(TlsAlert))
            {
               //Read an additional record
               error = ERROR_MORE_DATA_REQUIRED;
            }
            else
            {
               //Length of the Alert message
               n = sizeof(TlsAlert);
               //Pass the Alert message to the higher layer
               error = NO_ERROR;
            }
         }
         //Application data received?
         else if(context->rxBufferType == TLS_TYPE_APPLICATION_DATA)
         {
            //Length of the application data
            n = context->rxBufferLen;
            //Pass the application data to the higher layer
            error = NO_ERROR;
         }
         //Unknown content type?
         else
         {
            //Report an error
            error = ERROR_UNEXPECTED_MESSAGE;
         }
      }

      //Read as many records as necessary to reassemble the data
   } while(error == ERROR_MORE_DATA_REQUIRED);

   //Successful processing?
   if(!error)
   {
      //Pointer to the received data
      *data = context->rxBuffer + context->rxBufferPos;
      //Length, in byte, of the data
      *length = n;
      //Protocol type
      *contentType = context->rxBufferType;
   }

   //Return status code
   return error;
}


/**
 * @brief Send a TLS record
 * @param[in] context Pointer to the TLS context
 * @param[in] data Pointer to the record data
 * @param[in] length Length of the record data
 * @param[in] contentType Record type
 * @return Error code
 **/

error_t tlsWriteRecord(TlsContext *context, const uint8_t *data,
   size_t length, TlsContentType contentType)
{
   error_t error;
   size_t n;
   TlsRecord *record;

   //Point to the TLS record
   record = (TlsRecord *) context->txBuffer;

   //Initialize status code
   error = NO_ERROR;

   //Send process
   while(!error)
   {
      //Send as much data as possible
      if(context->txRecordLen == 0)
      {
         //Format TLS record
         record->type = contentType;
         record->version = htons(context->version);
         record->length = htons(length);

         //Copy record data
         memmove(record->data, data, length);

         //Debug message
         TRACE_DEBUG("Sending TLS record (%" PRIuSIZE " bytes)...\r\n", length);
         TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

         //Protect record payload?
         if(context->changeCipherSpecSent)
         {
            //Encrypt TLS record
            error = tlsEncryptRecord(context, record);
         }

         //Check status code
         if(!error)
         {
            //Actual length of the record data
            context->txRecordLen = sizeof(TlsRecord) + ntohs(record->length);
            //Point to the beginning of the record
            context->txRecordPos = 0;
         }
      }
      else if(context->txRecordPos < context->txRecordLen)
      {
         //Total number of bytes that have been written
         n = 0;

         //Send more data
         error = context->sendCallback(context->handle,
            context->txBuffer + context->txRecordPos,
            context->txRecordLen - context->txRecordPos, &n, 0);

         //Check status code
         if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Advance data pointer
            context->txRecordPos += n;
         }
         else
         {
            //The write operation has failed
            error = ERROR_WRITE_FAILED;
         }
      }
      else
      {
         //Prepare to send the next TLS record
         context->txRecordLen = 0;
         context->txRecordPos = 0;

         //We are done
         break;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Receive a TLS record
 * @param[in] context Pointer to the TLS context
 * @param[out] data Buffer where to store the record data
 * @param[in] size Maximum acceptable size for the incoming record
 * @param[out] length Length of the record data
 * @param[out] contentType Record type
 * @return Error code
 **/

error_t tlsReadRecord(TlsContext *context, uint8_t *data,
   size_t size, size_t *length, TlsContentType *contentType)
{
   error_t error;
   size_t n;
   TlsRecord *record;

   //Point to the buffer where to store the incoming TLS record
   record = (TlsRecord *) data;

   //Initialize status code
   error = NO_ERROR;

   //Receive process
   while(!error)
   {
      //Read as much data as possible
      if(context->rxRecordPos < sizeof(TlsRecord))
      {
         //Make sure that the buffer is large enough to hold the record header
         if(size >= sizeof(TlsRecord))
         {
            //Total number of bytes that have been received
            n = 0;

            //Read TLS record header
            error = context->receiveCallback(context->handle,
               data + context->rxRecordPos,
               sizeof(TlsRecord) - context->rxRecordPos, &n, 0);

            //Check status code
            if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
            {
               //Advance data pointer
               context->rxRecordPos += n;

               //TLS record header successfully received?
               if(context->rxRecordPos >= sizeof(TlsRecord))
               {
                  //Debug message
                  TRACE_DEBUG("Record header received:\r\n");
                  TRACE_DEBUG_ARRAY("  ", record, sizeof(record));

                  //Retrieve the length of the TLS record
                  context->rxRecordLen = sizeof(TlsRecord) + ntohs(record->length);
               }
            }
            else
            {
               //The read operation has failed
               error = ERROR_READ_FAILED;
            }
         }
         else
         {
            //Report an error
            error = ERROR_RECORD_OVERFLOW;
         }
      }
      else if(context->rxRecordPos < context->rxRecordLen)
      {
         //Make sure that the buffer is large enough to hold the entire record
         if(size >= context->rxRecordLen)
         {
            //Total number of bytes that have been received
            n = 0;

            //Read TLS record contents
            error = context->receiveCallback(context->handle,
               data + context->rxRecordPos,
               context->rxRecordLen - context->rxRecordPos, &n, 0);

            //Check status code
            if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
            {
               //Advance data pointer
               context->rxRecordPos += n;
            }
            else
            {
               //The read operation has failed
               error = ERROR_READ_FAILED;
            }
         }
         else
         {
            //Report an error
            error = ERROR_RECORD_OVERFLOW;
         }
      }
      else
      {
         //Check current state
         if(context->state > TLS_STATE_SERVER_HELLO)
         {
            //Once the server has sent the ServerHello message, enforce
            //incoming record versions
            if(ntohs(record->version) != context->version)
               error = ERROR_VERSION_NOT_SUPPORTED;
         }

         //Check status code
         if(!error)
         {
            //Record payload is protected?
            if(context->changeCipherSpecReceived)
            {
               //Decrypt TLS record
               error = tlsDecryptRecord(context, record);
            }
         }

         //Check status code
         if(!error)
         {
            //Actual length of the record data
            *length = ntohs(record->length);
            //Record type
            *contentType = (TlsContentType) record->type;

            //Debug message
            TRACE_DEBUG("TLS record received (%" PRIuSIZE " bytes)...\r\n", *length);
            TRACE_DEBUG_ARRAY("  ", record, *length + sizeof(TlsRecord));

            //Discard record header
            memmove(data, record->data, *length);

            //Prepare to receive the next TLS record
            context->rxRecordLen = 0;
            context->rxRecordPos = 0;

            //We are done
            break;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Encrypt an outgoing TLS record
 * @param[in] context Pointer to the TLS context
 * @param[in,out] record TLS record to be encrypted
 * @return Error code
 **/

error_t tlsEncryptRecord(TlsContext *context, TlsRecord *record)
{
   error_t error;
   size_t length;

   //Convert the length field to host byte order
   length = ntohs(record->length);

   //Message authentication is required?
   if(context->hashAlgo != NULL)
   {
#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= SSL_VERSION_3_0)
      //Check whether SSL 3.0 is currently used
      if(context->version == SSL_VERSION_3_0)
      {
         //SSL 3.0 uses an older obsolete version of the HMAC construction
         error = sslComputeMac(context, context->writeMacKey,
            context->writeSeqNum, record, record->data, length, record->data + length);
         //Any error to report?
         if(error)
            return error;
      }
      else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //Check whether TLS 1.0, TLS 1.1 or TLS 1.2 is currently used
      if(context->version >= TLS_VERSION_1_0)
      {
         //TLS uses a HMAC construction
         hmacInit(&context->hmacContext, context->hashAlgo,
            context->writeMacKey, context->macKeyLen);

         //Compute MAC over the sequence number and the record contents
         hmacUpdate(&context->hmacContext, context->writeSeqNum, sizeof(TlsSequenceNumber));
         hmacUpdate(&context->hmacContext, record, length + sizeof(TlsRecord));

         //Append the resulting MAC to the message
         hmacFinal(&context->hmacContext, record->data + length);
      }
      else
#endif
      //The negotiated TLS version is not valid...
      {
         //Report an error
         return ERROR_INVALID_VERSION;
      }

      //Debug message
      TRACE_DEBUG("Write sequence number:\r\n");
      TRACE_DEBUG_ARRAY("  ", context->writeSeqNum, sizeof(TlsSequenceNumber));
      TRACE_DEBUG("Computed MAC:\r\n");
      TRACE_DEBUG_ARRAY("  ", record->data + length, context->hashAlgo->digestSize);

      //Adjust the length of the message
      length += context->hashAlgo->digestSize;
      //Fix length field
      record->length = htons(length);

      //Increment sequence number
      tlsIncSequenceNumber(context->writeSeqNum);
   }

   //Encryption is required?
   if(context->cipherMode != CIPHER_MODE_NULL)
   {
      //Debug message
      TRACE_DEBUG("Record to be encrypted (%" PRIuSIZE " bytes):\r\n", length);
      TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

#if (TLS_STREAM_CIPHER_SUPPORT == ENABLED)
      //Stream cipher?
      if(context->cipherMode == CIPHER_MODE_STREAM)
      {
         //Encrypt record contents
         context->cipherAlgo->encryptStream(context->writeCipherContext,
            record->data, record->data, length);
      }
      else
#endif
#if (TLS_CBC_CIPHER_SUPPORT == ENABLED)
      //CBC block cipher?
      if(context->cipherMode == CIPHER_MODE_CBC)
      {
         size_t i;
         size_t paddingLength;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_1 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
         //TLS 1.1 and 1.2 use an explicit IV
         if(context->version >= TLS_VERSION_1_1)
         {
            //Make room for the IV at the beginning of the data
            memmove(record->data + context->recordIvLen, record->data, length);

            //The initialization vector should be chosen at random
            error = context->prngAlgo->read(context->prngContext,
               record->data, context->recordIvLen);
            //Any error to report?
            if(error)
               return error;

            //Adjust the length of the message
            length += context->recordIvLen;
         }
#endif
         //Get the actual amount of bytes in the last block
         paddingLength = (length + 1) % context->cipherAlgo->blockSize;

         //Padding is added to force the length of the plaintext to be
         //an integral multiple of the cipher's block length
         if(paddingLength > 0)
            paddingLength = context->cipherAlgo->blockSize - paddingLength;

         //Write padding bytes
         for(i = 0; i <= paddingLength; i++)
            record->data[length + i] = (uint8_t) paddingLength;

         //Compute the length of the resulting message
         length += paddingLength + 1;
         //Fix length field
         record->length = htons(length);

         //Debug message
         TRACE_DEBUG("Record with padding (%" PRIuSIZE " bytes):\r\n", length);
         TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

         //CBC encryption
         error = cbcEncrypt(context->cipherAlgo, context->writeCipherContext,
            context->writeIv, record->data, record->data, length);
         //Any error to report?
         if(error)
            return error;
      }
      else
#endif
#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED || \
   TLS_GCM_CIPHER_SUPPORT == ENABLED)
      //CCM or GCM AEAD cipher?
      if(context->cipherMode == CIPHER_MODE_CCM ||
         context->cipherMode == CIPHER_MODE_GCM)
      {
         uint8_t *data;
         uint8_t *tag;
         size_t nonceLength;
         uint8_t nonce[12];
         uint8_t a[13];

         //Determine the total length of the nonce
         nonceLength = context->fixedIvLen + context->recordIvLen;
         //The salt is the implicit part of the nonce and is not sent in the packet
         memcpy(nonce, context->writeIv, context->fixedIvLen);

         //The explicit part of the nonce is chosen by the sender
         error = context->prngAlgo->read(context->prngContext,
            nonce + context->fixedIvLen, context->recordIvLen);
         //Any error to report?
         if(error)
            return error;

         //Make room for the explicit nonce at the beginning of the record
         memmove(record->data + context->recordIvLen, record->data, length);
         //The explicit part of the nonce is carried in each TLS record
         memcpy(record->data, nonce + context->fixedIvLen, context->recordIvLen);

         //Additional data to be authenticated
         memcpy(a, context->writeSeqNum, sizeof(TlsSequenceNumber));
         memcpy(a + sizeof(TlsSequenceNumber), record, sizeof(TlsRecord));

         //Point to the plaintext
         data = record->data + context->recordIvLen;
         //Point to the buffer where to store the authentication tag
         tag = data + length;

#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED)
         //CCM AEAD cipher?
         if(context->cipherMode == CIPHER_MODE_CCM)
         {
            //Authenticated encryption using CCM
            error = ccmEncrypt(context->cipherAlgo, context->writeCipherContext,
               nonce, nonceLength, a, 13, data, data, length, tag, context->authTagLen);
         }
         else
#endif
#if (TLS_GCM_CIPHER_SUPPORT == ENABLED)
         //GCM AEAD cipher?
         if(context->cipherMode == CIPHER_MODE_GCM)
         {
            //Authenticated encryption using GCM
            error = gcmEncrypt(context->writeGcmContext, nonce, nonceLength,
               a, 13, data, data, length, tag, context->authTagLen);
         }
         else
#endif
         //Invalid cipher mode?
         {
            //The specified cipher mode is not supported
            error = ERROR_UNSUPPORTED_CIPHER_MODE;
         }

         //Failed to encrypt data?
         if(error)
            return error;

         //Compute the length of the resulting message
         length += context->recordIvLen + context->authTagLen;
         //Fix length field
         record->length = htons(length);

         //Increment sequence number
         tlsIncSequenceNumber(context->writeSeqNum);
      }
      else
#endif
#if (TLS_CHACHA20_POLY1305_SUPPORT == ENABLED)
      //ChaCha20Poly1305 AEAD cipher?
      if(context->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
      {
         size_t i;
         uint8_t *tag;
         uint8_t nonce[12];
         uint8_t a[13];

         //The 64-bit record sequence number is serialized as an 8-byte,
         //big-endian value and padded on the left with four 0x00 bytes
         memcpy(nonce + 4, context->writeSeqNum, 8);
         memset(nonce, 0, 4);

         //The padded sequence number is XORed with the write IV to form
         //the 96-bit nonce
         for(i = 0; i < context->fixedIvLen; i++)
            nonce[i] ^= context->writeIv[i];

         //Additional data to be authenticated
         memcpy(a, context->writeSeqNum, sizeof(TlsSequenceNumber));
         memcpy(a + sizeof(TlsSequenceNumber), record, sizeof(TlsRecord));

         //Point to the buffer where to store the authentication tag
         tag = record->data + length;

         //Authenticated encryption using ChaCha20Poly1305
         error = chacha20Poly1305Encrypt(context->writeEncKey, context->encKeyLen,
            nonce, 12, a, 13, record->data, record->data, length, tag, context->authTagLen);
         //Failed to encrypt data?
         if(error)
            return error;

         //Compute the length of the resulting message
         length += context->authTagLen;
         //Fix length field
         record->length = htons(length);

         //Increment sequence number
         tlsIncSequenceNumber(context->writeSeqNum);
      }
      else
#endif
      //Invalid cipher mode?
      {
         //The specified cipher mode is not supported
         return ERROR_UNSUPPORTED_CIPHER_MODE;
      }

      //Debug message
      TRACE_DEBUG("Encrypted record (%" PRIuSIZE " bytes):\r\n", length);
      TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));
   }

   //Successful encryption
   return NO_ERROR;
}


/**
 * @brief Decrypt an incoming TLS record
 * @param[in] context Pointer to the TLS context
 * @param[in,out] record TLS record to be decrypted
 * @return Error code
 **/

error_t tlsDecryptRecord(TlsContext *context, TlsRecord *record)
{
   error_t error;
   size_t length;

   //Convert the length field to host byte order
   length = ntohs(record->length);

   //Decrypt record if necessary
   if(context->cipherMode != CIPHER_MODE_NULL)
   {
      //Debug message
      TRACE_DEBUG("Record to be decrypted (%" PRIuSIZE " bytes):\r\n", length);
      TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

#if (TLS_STREAM_CIPHER_SUPPORT == ENABLED)
      //Stream cipher?
      if(context->cipherMode == CIPHER_MODE_STREAM)
      {
         //Decrypt record contents
         context->cipherAlgo->decryptStream(context->readCipherContext,
            record->data, record->data, length);
      }
      else
#endif
#if (TLS_CBC_CIPHER_SUPPORT == ENABLED)
      //CBC block cipher?
      if(context->cipherMode == CIPHER_MODE_CBC)
      {
         size_t i;
         size_t paddingLength;

         //The length of the data must be a multiple of the block size
         if((length % context->cipherAlgo->blockSize) != 0)
            return ERROR_DECODING_FAILED;

         //CBC decryption
         error = cbcDecrypt(context->cipherAlgo, context->readCipherContext,
            context->readIv, record->data, record->data, length);
         //Any error to report?
         if(error)
            return error;

         //Debug message
         TRACE_DEBUG("Record with padding (%" PRIuSIZE " bytes):\r\n", length);
         TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

#if (TLS_MAX_VERSION >= TLS_VERSION_1_1 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
         //TLS 1.1 and 1.2 use an explicit IV
         if(context->version >= TLS_VERSION_1_1)
         {
            //Make sure the message length is acceptable
            if(length < context->recordIvLen)
               return ERROR_DECODING_FAILED;

            //Adjust the length of the message
            length -= context->recordIvLen;
            //Discard the first cipher block (corresponding to the explicit IV)
            memmove(record->data, record->data + context->recordIvLen, length);
         }
#endif
         //Make sure the message length is acceptable
         if(length < context->cipherAlgo->blockSize)
            return ERROR_DECODING_FAILED;

         //Compute the length of the padding string
         paddingLength = record->data[length - 1];
         //Erroneous padding length?
         if(paddingLength >= length)
            return ERROR_BAD_RECORD_MAC;

         //The receiver must check the padding
         for(i = 0; i <= paddingLength; i++)
         {
            //Each byte in the padding data must be filled
            //with the padding length value
            if(record->data[length - 1 - i] != paddingLength)
               return ERROR_BAD_RECORD_MAC;
         }

         //Remove padding bytes
         length -= paddingLength + 1;
         //Fix the length field of the TLS record
         record->length = htons(length);
      }
      else
#endif
#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED || \
   TLS_GCM_CIPHER_SUPPORT == ENABLED)
      //CCM or GCM AEAD cipher?
      if(context->cipherMode == CIPHER_MODE_CCM ||
         context->cipherMode == CIPHER_MODE_GCM)
      {
         uint8_t *ciphertext;
         uint8_t *tag;
         size_t nonceLength;
         uint8_t nonce[12];
         uint8_t a[13];

         //Make sure the message length is acceptable
         if(length < (context->recordIvLen + context->authTagLen))
            return ERROR_DECODING_FAILED;

         //Determine the total length of the nonce
         nonceLength = context->fixedIvLen + context->recordIvLen;
         //The salt is the implicit part of the nonce and is not sent in the packet
         memcpy(nonce, context->readIv, context->fixedIvLen);
         //The explicit part of the nonce is chosen by the sender
         memcpy(nonce + context->fixedIvLen, record->data, context->recordIvLen);

         //Calculate the length of the ciphertext
         length -= context->recordIvLen + context->authTagLen;
         //Fix the length field of the TLS record
         record->length = htons(length);

         //Additional data to be authenticated
         memcpy(a, context->readSeqNum, sizeof(TlsSequenceNumber));
         memcpy(a + sizeof(TlsSequenceNumber), record, sizeof(TlsRecord));

         //Point to the ciphertext
         ciphertext = record->data + context->recordIvLen;
         //Point to the authentication tag
         tag = ciphertext + length;

#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED)
         //CCM AEAD cipher?
         if(context->cipherMode == CIPHER_MODE_CCM)
         {
            //Authenticated decryption using CCM
            error = ccmDecrypt(context->cipherAlgo, context->readCipherContext,
               nonce, nonceLength, a, 13, ciphertext, ciphertext, length, tag, context->authTagLen);
         }
         else
#endif
#if (TLS_GCM_CIPHER_SUPPORT == ENABLED)
         //GCM AEAD cipher?
         if(context->cipherMode == CIPHER_MODE_GCM)
         {
            //Authenticated decryption using GCM
            error = gcmDecrypt(context->readGcmContext, nonce, nonceLength,
               a, 13, ciphertext, ciphertext, length, tag, context->authTagLen);
         }
         else
#endif
         //Invalid cipher mode?
         {
            //The specified cipher mode is not supported
            error = ERROR_UNSUPPORTED_CIPHER_MODE;
         }

         //Wrong authentication tag?
         if(error)
            return ERROR_BAD_RECORD_MAC;

         //Discard the explicit part of the nonce
         memmove(record->data, record->data + context->recordIvLen, length);

         //Increment sequence number
         tlsIncSequenceNumber(context->readSeqNum);
      }
      else
#endif
#if (TLS_CHACHA20_POLY1305_SUPPORT == ENABLED)
      //ChaCha20Poly1305 AEAD cipher?
      if(context->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
      {
         size_t i;
         uint8_t *tag;
         uint8_t nonce[12];
         uint8_t a[13];

         //Make sure the message length is acceptable
         if(length < context->authTagLen)
            return ERROR_DECODING_FAILED;

         //The 64-bit record sequence number is serialized as an 8-byte,
         //big-endian value and padded on the left with four 0x00 bytes
         memcpy(nonce + 4, context->readSeqNum, 8);
         memset(nonce, 0, 4);

         //The padded sequence number is XORed with the read IV to form
         //the 96-bit nonce
         for(i = 0; i < context->fixedIvLen; i++)
            nonce[i] ^= context->readIv[i];

         //Calculate the length of the ciphertext
         length -= context->authTagLen;
         //Fix the length field of the TLS record
         record->length = htons(length);

         //Additional data to be authenticated
         memcpy(a, context->readSeqNum, sizeof(TlsSequenceNumber));
         memcpy(a + sizeof(TlsSequenceNumber), record, sizeof(TlsRecord));

         //Point to the authentication tag
         tag = record->data + length;

         //Authenticated decryption using ChaCha20Poly1305
         error = chacha20Poly1305Decrypt(context->readEncKey, context->encKeyLen,
            nonce, 12, a, 13, record->data, record->data, length, tag, context->authTagLen);
         //Wrong authentication tag?
         if(error)
            return ERROR_BAD_RECORD_MAC;

         //Increment sequence number
         tlsIncSequenceNumber(context->readSeqNum);
      }
      else
#endif
      //Invalid cipher mode?
      {
         //The specified cipher mode is not supported
         return ERROR_UNSUPPORTED_CIPHER_MODE;
      }

      //Debug message
      TRACE_DEBUG("Decrypted record (%" PRIuSIZE " bytes):\r\n", length);
      TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));
   }

   //Check message authentication code if necessary
   if(context->hashAlgo != NULL)
   {
      //Make sure the message length is acceptable
      if(length < context->hashAlgo->digestSize)
         return ERROR_DECODING_FAILED;

      //Adjust the length of the message
      length -= context->hashAlgo->digestSize;
      //Fix the length field of the TLS record
      record->length = htons(length);

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= SSL_VERSION_3_0)
      //Check whether SSL 3.0 is currently used
      if(context->version == SSL_VERSION_3_0)
      {
         //SSL 3.0 uses an older obsolete version of the HMAC construction
         error = sslComputeMac(context, context->readMacKey, context->readSeqNum,
            record, record->data, length, context->hmacContext.digest);
         //Any error to report?
         if(error)
            return error;
      }
      else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //Check whether TLS 1.0, TLS 1.1 or TLS 1.2 is currently used
      if(context->version >= TLS_VERSION_1_0)
      {
         //TLS uses a HMAC construction
         hmacInit(&context->hmacContext, context->hashAlgo,
            context->readMacKey, context->macKeyLen);

         //Compute MAC over the sequence number and the record contents
         hmacUpdate(&context->hmacContext, context->readSeqNum, sizeof(TlsSequenceNumber));
         hmacUpdate(&context->hmacContext, record, sizeof(TlsRecord));
         hmacUpdate(&context->hmacContext, record->data, length);
         hmacFinal(&context->hmacContext, NULL);
      }
      else
#endif
      //The negotiated TLS version is not valid...
      {
         //Report an error
         return ERROR_INVALID_VERSION;
      }

      //Debug message
      TRACE_DEBUG("Read sequence number:\r\n");
      TRACE_DEBUG_ARRAY("  ", context->readSeqNum, sizeof(TlsSequenceNumber));
      TRACE_DEBUG("Computed MAC:\r\n");
      TRACE_DEBUG_ARRAY("  ", context->hmacContext.digest, context->hashAlgo->digestSize);

      //Check the message authentication code
      if(memcmp(record->data + length, context->hmacContext.digest, context->hashAlgo->digestSize))
         return ERROR_BAD_RECORD_MAC;

      //Increment sequence number
      tlsIncSequenceNumber(context->readSeqNum);
   }

   //Successful decryption
   return NO_ERROR;
}


/**
 * @brief Increment sequence number
 * @param[in] seqNum Sequence number to increment
 **/

void tlsIncSequenceNumber(TlsSequenceNumber seqNum)
{
   int_t i;

   //Sequence numbers are stored MSB first
   for(i = 7; i >= 0; i--)
   {
      //Increment the current byte
      seqNum[i]++;
      //Propagate the carry if necessary
      if(seqNum[i] != 0)
         break;
   }
}

#endif
