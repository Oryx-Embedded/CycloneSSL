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
 * @version 1.8.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include <string.h>
#include "tls.h"
#include "tls_common.h"
#include "tls_record.h"
#include "tls_misc.h"
#include "ssl_misc.h"
#include "cipher_mode/cbc.h"
#include "aead/ccm.h"
#include "aead/gcm.h"
#include "aead/chacha20_poly1305.h"
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
   const uint8_t *data, size_t length, TlsContentType contentType)
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
         if(length > context->txBufferMaxLen)
         {
            //Report an error
            error = ERROR_MESSAGE_TOO_LONG;
         }
         else if(length > 0)
         {
            //Make room for the encryption overhead
            memmove(context->txBuffer + context->txBufferSize - length, data,
               length);

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
         //Do not exceed the negotiated maximum fragment length
         n = MIN(n, context->maxFragLen);

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
   uint8_t **data, size_t *length, TlsContentType *contentType)
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
#if (TLS_MAX_WARNING_ALERTS > 0)
      //Reset the count of consecutive warning alerts
      if(context->rxBufferType != TLS_TYPE_ALERT)
         context->alertCount = 0;
#endif

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
            error = tlsEncryptRecord(context, &context->encryptionEngine, record);
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
         error = context->socketSendCallback(context->socketHandle,
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
            error = context->socketReceiveCallback(context->socketHandle,
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
                  TRACE_DEBUG_ARRAY("  ", record, sizeof(TlsRecord));

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
            error = context->socketReceiveCallback(context->socketHandle,
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
            //Once the server has sent the ServerHello message, enforce the
            //version of incoming records
            if(ntohs(record->version) != context->version)
               error = ERROR_VERSION_NOT_SUPPORTED;
         }
         else
         {
            //Compliant servers must accept any value {03,XX} as the record
            //layer version number for ClientHello
            if(LSB(record->version) != MSB(TLS_VERSION_1_0))
               error = ERROR_VERSION_NOT_SUPPORTED;
         }

         //Check status code
         if(!error)
         {
            //Record payload protected?
            if(context->changeCipherSpecReceived)
            {
               //Decrypt TLS record
               error = tlsDecryptRecord(context, &context->decryptionEngine, record);
            }
         }

         //Check status code
         if(!error)
         {
            //Check the length of the plaintext record
            if(ntohs(record->length) <= TLS_MAX_RECORD_LENGTH)
            {
#if (TLS_MAX_EMPTY_RECORDS > 0)
               //Empty TLS record?
               if(ntohs(record->length) == 0)
               {
                  //Increment the count of consecutive empty records
                  context->emptyRecordCount++;

                  //Do not allow too many consecutive empty records
                  if(context->emptyRecordCount > TLS_MAX_EMPTY_RECORDS)
                     error = ERROR_UNEXPECTED_MESSAGE;
               }
               else
               {
                  //Reset the count of consecutive empty records
                  context->emptyRecordCount = 0;
               }
#endif
            }
            else
            {
               //The length of the plaintext record must not exceed 2^14 bytes
               error = ERROR_RECORD_OVERFLOW;
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
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @param[in,out] record TLS record to be encrypted
 * @return Error code
 **/

error_t tlsEncryptRecord(TlsContext *context,
   TlsEncryptionEngine *encryptionEngine, void *record)
{
   error_t error;
   size_t length;
   uint8_t *data;

   //Get the length of the TLS record
   length = tlsGetRecordLength(context, record);
   //Point to the payload
   data = tlsGetRecordData(context, record);

   //Message authentication is required?
   if(encryptionEngine->hashAlgo != NULL)
   {
#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= SSL_VERSION_3_0)
      //SSL 3.0 currently selected?
      if(encryptionEngine->version == SSL_VERSION_3_0)
      {
         //SSL 3.0 uses an older obsolete version of the HMAC construction
         error = sslComputeMac(encryptionEngine, record, data, length,
            data + length);
         //Any error to report?
         if(error)
            return error;
      }
      else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //TLS 1.0, TLS 1.1 or TLS 1.2 currently selected?
      if(encryptionEngine->version >= TLS_VERSION_1_0)
      {
         //TLS uses a HMAC construction
         error = tlsComputeMac(context, encryptionEngine, record, data,
            length, data + length);
         //Any error to report?
         if(error)
            return error;
      }
      else
#endif
      //Invalid TLS version?
      {
         //Report an error
         return ERROR_INVALID_VERSION;
      }

      //Debug message
      TRACE_DEBUG("Write sequence number:\r\n");
      TRACE_DEBUG_ARRAY("  ", &encryptionEngine->seqNum, sizeof(TlsSequenceNumber));
      TRACE_DEBUG("Computed MAC:\r\n");
      TRACE_DEBUG_ARRAY("  ", data + length, encryptionEngine->hashAlgo->digestSize);

      //Adjust the length of the message
      length += encryptionEngine->hashAlgo->digestSize;
      //Fix length field
      tlsSetRecordLength(context, record, length);

      //Increment sequence number
      tlsIncSequenceNumber(&encryptionEngine->seqNum);
   }

   //Encryption is required?
   if(encryptionEngine->cipherMode != CIPHER_MODE_NULL)
   {
      //Debug message
      TRACE_DEBUG("Record to be encrypted (%" PRIuSIZE " bytes):\r\n", length);
      TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

#if (TLS_STREAM_CIPHER_SUPPORT == ENABLED)
      //Stream cipher?
      if(encryptionEngine->cipherMode == CIPHER_MODE_STREAM)
      {
         //Encrypt record contents
         encryptionEngine->cipherAlgo->encryptStream(encryptionEngine->cipherContext,
            data, data, length);
      }
      else
#endif
#if (TLS_CBC_CIPHER_SUPPORT == ENABLED)
      //CBC block cipher?
      if(encryptionEngine->cipherMode == CIPHER_MODE_CBC)
      {
         size_t i;
         size_t paddingLen;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_1 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
         //TLS 1.1 and 1.2 use an explicit IV
         if(encryptionEngine->version >= TLS_VERSION_1_1)
         {
            //Make room for the IV at the beginning of the data
            memmove(data + encryptionEngine->recordIvLen, data, length);

            //The initialization vector should be chosen at random
            error = context->prngAlgo->read(context->prngContext, data,
               encryptionEngine->recordIvLen);
            //Any error to report?
            if(error)
               return error;

            //Adjust the length of the message
            length += encryptionEngine->recordIvLen;
         }
#endif
         //Get the actual amount of bytes in the last block
         paddingLen = (length + 1) % encryptionEngine->cipherAlgo->blockSize;

         //Padding is added to force the length of the plaintext to be an
         //integral multiple of the cipher's block length
         if(paddingLen > 0)
            paddingLen = encryptionEngine->cipherAlgo->blockSize - paddingLen;

         //Write padding bytes
         for(i = 0; i <= paddingLen; i++)
            data[length + i] = (uint8_t) paddingLen;

         //Compute the length of the resulting message
         length += paddingLen + 1;
         //Fix length field
         tlsSetRecordLength(context, record, length);

         //Debug message
         TRACE_DEBUG("Record with padding (%" PRIuSIZE " bytes):\r\n", length);
         TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

         //CBC encryption
         error = cbcEncrypt(encryptionEngine->cipherAlgo,
            encryptionEngine->cipherContext, encryptionEngine->iv, data, data, length);
         //Any error to report?
         if(error)
            return error;
      }
      else
#endif
#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED || \
   TLS_GCM_CIPHER_SUPPORT == ENABLED)
      //CCM or GCM AEAD cipher?
      if(encryptionEngine->cipherMode == CIPHER_MODE_CCM ||
         encryptionEngine->cipherMode == CIPHER_MODE_GCM)
      {
         uint8_t *tag;
         size_t nonceLen;
         uint8_t nonce[12];
         uint8_t aad[13];

         //Additional data to be authenticated
         tlsFormatAdditionalData(context, &encryptionEngine->seqNum, record, aad);

         //Determine the total length of the nonce
         nonceLen = encryptionEngine->fixedIvLen + encryptionEngine->recordIvLen;
         //The salt is the implicit part of the nonce and is not sent in the packet
         memcpy(nonce, encryptionEngine->iv, encryptionEngine->fixedIvLen);

         //The explicit part of the nonce is chosen by the sender
         error = context->prngAlgo->read(context->prngContext,
            nonce + encryptionEngine->fixedIvLen, encryptionEngine->recordIvLen);
         //Any error to report?
         if(error)
            return error;

         //Make room for the explicit nonce at the beginning of the record
         memmove(data + encryptionEngine->recordIvLen, data, length);

         //The explicit part of the nonce is carried in each TLS record
         memcpy(data, nonce + encryptionEngine->fixedIvLen,
            encryptionEngine->recordIvLen);

         //Point to the plaintext
         data += encryptionEngine->recordIvLen;
         //Point to the buffer where to store the authentication tag
         tag = data + length;

#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED)
         //CCM AEAD cipher?
         if(encryptionEngine->cipherMode == CIPHER_MODE_CCM)
         {
            //Authenticated encryption using CCM
            error = ccmEncrypt(encryptionEngine->cipherAlgo,
               encryptionEngine->cipherContext, nonce, nonceLen, aad, 13,
               data, data, length, tag, encryptionEngine->authTagLen);
         }
         else
#endif
#if (TLS_GCM_CIPHER_SUPPORT == ENABLED)
         //GCM AEAD cipher?
         if(encryptionEngine->cipherMode == CIPHER_MODE_GCM)
         {
            //Authenticated encryption using GCM
            error = gcmEncrypt(encryptionEngine->gcmContext, nonce, nonceLen,
               aad, 13, data, data, length, tag, encryptionEngine->authTagLen);
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
         length += encryptionEngine->recordIvLen + encryptionEngine->authTagLen;
         //Fix length field
         tlsSetRecordLength(context, record, length);

         //Increment sequence number
         tlsIncSequenceNumber(&encryptionEngine->seqNum);
      }
      else
#endif
#if (TLS_CHACHA20_POLY1305_SUPPORT == ENABLED)
      //ChaCha20Poly1305 AEAD cipher?
      if(encryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
      {
         size_t i;
         uint8_t *tag;
         uint8_t nonce[12];
         uint8_t aad[13];

         //Additional data to be authenticated
         tlsFormatAdditionalData(context, &encryptionEngine->seqNum, record, aad);

         //The 64-bit record sequence number is serialized as an 8-byte,
         //big-endian value and padded on the left with four 0x00 bytes
         memcpy(nonce + 4, aad, 8);
         memset(nonce, 0, 4);

         //The padded sequence number is XORed with the write IV to form
         //the 96-bit nonce
         for(i = 0; i < encryptionEngine->fixedIvLen; i++)
            nonce[i] ^= encryptionEngine->iv[i];

         //Point to the buffer where to store the authentication tag
         tag = data + length;

         //Authenticated encryption using ChaCha20Poly1305
         error = chacha20Poly1305Encrypt(encryptionEngine->encKey,
            encryptionEngine->encKeyLen, nonce, 12, aad, 13, data,
            data, length, tag, encryptionEngine->authTagLen);
         //Failed to encrypt data?
         if(error)
            return error;

         //Compute the length of the resulting message
         length += encryptionEngine->authTagLen;
         //Fix length field
         tlsSetRecordLength(context, record, length);

         //Increment sequence number
         tlsIncSequenceNumber(&encryptionEngine->seqNum);
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
 * @param[in] decryptionEngine Pointer to the decryption engine
 * @param[in,out] record TLS record to be decrypted
 * @return Error code
 **/

error_t tlsDecryptRecord(TlsContext *context,
   TlsEncryptionEngine *decryptionEngine, void *record)
{
   error_t error;
   size_t length;
   uint8_t *data;

   //Get the length of the TLS record
   length = tlsGetRecordLength(context, record);
   //Point to the payload
   data = tlsGetRecordData(context, record);

   //Decrypt record if necessary
   if(decryptionEngine->cipherMode != CIPHER_MODE_NULL)
   {
      //Debug message
      TRACE_DEBUG("Record to be decrypted (%" PRIuSIZE " bytes):\r\n", length);
      TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

#if (TLS_STREAM_CIPHER_SUPPORT == ENABLED)
      //Stream cipher?
      if(decryptionEngine->cipherMode == CIPHER_MODE_STREAM)
      {
         //Decrypt record contents
         decryptionEngine->cipherAlgo->decryptStream(decryptionEngine->cipherContext,
            data, data, length);
      }
      else
#endif
#if (TLS_CBC_CIPHER_SUPPORT == ENABLED)
      //CBC block cipher?
      if(decryptionEngine->cipherMode == CIPHER_MODE_CBC)
      {
         size_t i;
         size_t paddingLen;

         //The length of the data must be a multiple of the block size
         if((length % decryptionEngine->cipherAlgo->blockSize) != 0)
            return ERROR_BAD_RECORD_MAC;

         //CBC decryption
         error = cbcDecrypt(decryptionEngine->cipherAlgo,
            decryptionEngine->cipherContext, decryptionEngine->iv, data, data, length);
         //Any error to report?
         if(error)
            return error;

         //Debug message
         TRACE_DEBUG("Record with padding (%" PRIuSIZE " bytes):\r\n", length);
         TRACE_DEBUG_ARRAY("  ", record, length + sizeof(TlsRecord));

#if (TLS_MAX_VERSION >= TLS_VERSION_1_1 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
         //TLS 1.1 and 1.2 use an explicit IV
         if(decryptionEngine->version >= TLS_VERSION_1_1)
         {
            //Make sure the message length is acceptable
            if(length < decryptionEngine->recordIvLen)
               return ERROR_BAD_RECORD_MAC;

            //Adjust the length of the message
            length -= decryptionEngine->recordIvLen;

            //Discard the first cipher block (corresponding to the explicit IV)
            memmove(data, data + decryptionEngine->recordIvLen, length);
         }
#endif
         //Make sure the message length is acceptable
         if(length < decryptionEngine->cipherAlgo->blockSize)
            return ERROR_BAD_RECORD_MAC;

         //Compute the length of the padding string
         paddingLen = data[length - 1];
         //Erroneous padding length?
         if(paddingLen >= length)
            return ERROR_BAD_RECORD_MAC;

         //The receiver must check the padding
         for(i = 0; i <= paddingLen; i++)
         {
            //Each byte in the padding data must be filled with the padding
            //length value
            if(data[length - 1 - i] != paddingLen)
               return ERROR_BAD_RECORD_MAC;
         }

         //Remove padding bytes
         length -= paddingLen + 1;
         //Fix the length field of the TLS record
         tlsSetRecordLength(context, record, length);
      }
      else
#endif
#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED || \
   TLS_GCM_CIPHER_SUPPORT == ENABLED)
      //CCM or GCM AEAD cipher?
      if(decryptionEngine->cipherMode == CIPHER_MODE_CCM ||
         decryptionEngine->cipherMode == CIPHER_MODE_GCM)
      {
         uint8_t *ciphertext;
         uint8_t *tag;
         size_t nonceLen;
         uint8_t nonce[12];
         uint8_t aad[13];

         //Make sure the message length is acceptable
         if(length < (decryptionEngine->recordIvLen + decryptionEngine->authTagLen))
            return ERROR_BAD_RECORD_MAC;

         //Calculate the length of the ciphertext
         length -= decryptionEngine->recordIvLen + decryptionEngine->authTagLen;
         //Fix the length field of the TLS record
         tlsSetRecordLength(context, record, length);

         //Additional data to be authenticated
         tlsFormatAdditionalData(context, &decryptionEngine->seqNum, record, aad);

         //Determine the total length of the nonce
         nonceLen = decryptionEngine->fixedIvLen + decryptionEngine->recordIvLen;

         //The salt is the implicit part of the nonce and is not sent in the packet
         memcpy(nonce, decryptionEngine->iv, decryptionEngine->fixedIvLen);

         //The explicit part of the nonce is chosen by the sender
         memcpy(nonce + decryptionEngine->fixedIvLen, data,
            decryptionEngine->recordIvLen);

         //Point to the ciphertext
         ciphertext = data + decryptionEngine->recordIvLen;
         //Point to the authentication tag
         tag = ciphertext + length;

#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED)
         //CCM AEAD cipher?
         if(decryptionEngine->cipherMode == CIPHER_MODE_CCM)
         {
            //Authenticated decryption using CCM
            error = ccmDecrypt(decryptionEngine->cipherAlgo,
               decryptionEngine->cipherContext, nonce, nonceLen, aad, 13,
               ciphertext, ciphertext, length, tag, decryptionEngine->authTagLen);
         }
         else
#endif
#if (TLS_GCM_CIPHER_SUPPORT == ENABLED)
         //GCM AEAD cipher?
         if(decryptionEngine->cipherMode == CIPHER_MODE_GCM)
         {
            //Authenticated decryption using GCM
            error = gcmDecrypt(decryptionEngine->gcmContext, nonce, nonceLen,
               aad, 13, ciphertext, ciphertext, length, tag, decryptionEngine->authTagLen);
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
         memmove(data, data + decryptionEngine->recordIvLen, length);

         //Increment sequence number
         tlsIncSequenceNumber(&decryptionEngine->seqNum);
      }
      else
#endif
#if (TLS_CHACHA20_POLY1305_SUPPORT == ENABLED)
      //ChaCha20Poly1305 AEAD cipher?
      if(decryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
      {
         size_t i;
         uint8_t *tag;
         uint8_t nonce[12];
         uint8_t aad[13];

         //Make sure the message length is acceptable
         if(length < decryptionEngine->authTagLen)
            return ERROR_BAD_RECORD_MAC;

         //Calculate the length of the ciphertext
         length -= decryptionEngine->authTagLen;
         //Fix the length field of the TLS record
         tlsSetRecordLength(context, record, length);

         //Additional data to be authenticated
         tlsFormatAdditionalData(context, &decryptionEngine->seqNum, record, aad);

         //The 64-bit record sequence number is serialized as an 8-byte,
         //big-endian value and padded on the left with four 0x00 bytes
         memcpy(nonce + 4, aad, 8);
         memset(nonce, 0, 4);

         //The padded sequence number is XORed with the read IV to form
         //the 96-bit nonce
         for(i = 0; i < decryptionEngine->fixedIvLen; i++)
            nonce[i] ^= decryptionEngine->iv[i];

         //Point to the authentication tag
         tag = data + length;

         //Authenticated decryption using ChaCha20Poly1305
         error = chacha20Poly1305Decrypt(decryptionEngine->encKey,
            decryptionEngine->encKeyLen, nonce, 12, aad, 13, data,
            data, length, tag, decryptionEngine->authTagLen);
         //Wrong authentication tag?
         if(error)
            return ERROR_BAD_RECORD_MAC;

         //Increment sequence number
         tlsIncSequenceNumber(&decryptionEngine->seqNum);
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
   if(decryptionEngine->hashAlgo != NULL)
   {
      //Make sure the message length is acceptable
      if(length < decryptionEngine->hashAlgo->digestSize)
         return ERROR_BAD_RECORD_MAC;

      //Adjust the length of the message
      length -= decryptionEngine->hashAlgo->digestSize;
      //Fix the length field of the TLS record
      tlsSetRecordLength(context, record, length);

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= SSL_VERSION_3_0)
      //SSL 3.0 currently selected?
      if(decryptionEngine->version == SSL_VERSION_3_0)
      {
         //SSL 3.0 uses an older obsolete version of the HMAC construction
         error = sslComputeMac(decryptionEngine, record, data, length,
            decryptionEngine->hmacContext->digest);
         //Any error to report?
         if(error)
            return error;
      }
      else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //TLS 1.0, TLS 1.1 or TLS 1.2 currently selected?
      if(decryptionEngine->version >= TLS_VERSION_1_0)
      {
         //TLS uses a HMAC construction
         error = tlsComputeMac(context, decryptionEngine, record, data,
            length, decryptionEngine->hmacContext->digest);
         //Any error to report?
         if(error)
            return error;
      }
      else
#endif
      //Invalid TLS version?
      {
         //Report an error
         return ERROR_INVALID_VERSION;
      }

      //Debug message
      TRACE_DEBUG("Read sequence number:\r\n");
      TRACE_DEBUG_ARRAY("  ", &decryptionEngine->seqNum, sizeof(TlsSequenceNumber));
      TRACE_DEBUG("Computed MAC:\r\n");
      TRACE_DEBUG_ARRAY("  ", decryptionEngine->hmacContext->digest, decryptionEngine->hashAlgo->digestSize);

      //Check the message authentication code
      if(memcmp(data + length, decryptionEngine->hmacContext->digest,
         decryptionEngine->hashAlgo->digestSize))
      {
         //Invalid MAC
         return ERROR_BAD_RECORD_MAC;
      }

      //Increment sequence number
      tlsIncSequenceNumber(&decryptionEngine->seqNum);
   }

   //Successful decryption
   return NO_ERROR;
}


/**
 * @brief Set TLS record length
 * @param[in] context Pointer to the TLS context
 * @param[in] record Pointer to the TLS record
 * @param[in] length Record length
 **/

void tlsSetRecordLength(TlsContext *context, void *record, size_t length)
{
#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Set the length of the DTLS record
      ((DtlsRecord *) record)->length = htons(length);
   }
   else
#endif
   //TLS protocol?
   {
      //Set the length of the DTLS record
      ((TlsRecord *) record)->length = htons(length);
   }
}


/**
 * @brief Get TLS record length
 * @param[in] context Pointer to the TLS context
 * @param[in] record Pointer to the TLS record
 * @return Record length
 **/

size_t tlsGetRecordLength(TlsContext *context, void *record)
{
   size_t length;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Get the length of the DTLS record
      length = ((DtlsRecord *) record)->length;
   }
   else
#endif
   //TLS protocol?
   {
      //Get the length of the TLS record
      length = ((TlsRecord *) record)->length;
   }

   //Convert the length field to host byte order
   return htons(length);
}


/**
 * @brief Get TLS record payload
 * @param[in] context Pointer to the TLS context
 * @param[in] record Pointer to the TLS record
 * @return Pointer to the first byte of the payload
 **/

uint8_t *tlsGetRecordData(TlsContext *context, void *record)
{
   uint8_t *data;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Point to the payload of the DTLS record
      data = ((DtlsRecord *) record)->data;
   }
   else
#endif
   //TLS protocol?
   {
      //Point to the payload of the TLS record
      data = ((TlsRecord *) record)->data;
   }

   //Return a pointer to the first byte of the payload
   return data;
}


/**
 * @brief Compute message authentication code
 * @param[in] context Pointer to the TLS context
 * @param[in] encryptionEngine Pointer to the encryption/decryption engine
 * @param[in] record Pointer to the TLS record
 * @param[in] data Pointer to the record data
 * @param[in] dataLen Length of the data
 * @param[out] mac The computed MAC value
 * @return Error code
 **/

error_t tlsComputeMac(TlsContext *context, TlsEncryptionEngine *encryptionEngine,
   void *record, const uint8_t *data, size_t dataLen, uint8_t *mac)
{
   //Initialize HMAC calculation
   hmacInit(encryptionEngine->hmacContext, encryptionEngine->hashAlgo,
      encryptionEngine->macKey, encryptionEngine->macKeyLen);

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      const DtlsRecord *dtlsRecord;

      //Point to the DTLS record
      dtlsRecord = (DtlsRecord *) record;

      //Compute the MAC over the 64-bit value formed by concatenating the epoch
      //and the sequence number in the order they appear on the wire
      hmacUpdate(encryptionEngine->hmacContext, &dtlsRecord->epoch, 2);
      hmacUpdate(encryptionEngine->hmacContext, &dtlsRecord->seqNum, 6);

      //Compute MAC over the record contents
      hmacUpdate(encryptionEngine->hmacContext, &dtlsRecord->type, 3);
      hmacUpdate(encryptionEngine->hmacContext, &dtlsRecord->length, 2);
      hmacUpdate(encryptionEngine->hmacContext, data, dataLen);
   }
   else
#endif
   //TLS protocol?
   {
      const TlsRecord *tlsRecord;

      //Point to the TLS record
      tlsRecord = (TlsRecord *) record;

      //Compute MAC over the implicit sequence number
      hmacUpdate(encryptionEngine->hmacContext, &encryptionEngine->seqNum,
         sizeof(TlsSequenceNumber));

      //Compute MAC over the record contents
      hmacUpdate(encryptionEngine->hmacContext, tlsRecord, sizeof(TlsRecord));
      hmacUpdate(encryptionEngine->hmacContext, data, dataLen);
   }

   //Append the resulting MAC to the message
   hmacFinal(encryptionEngine->hmacContext, mac);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format additional authenticated data (AAD)
 * @param[in] context Pointer to the TLS context
 * @param[in] seqNum Pointer to the sequence number
 * @param[in] record Pointer to the TLS record
 * @param[out] aad Additional authenticated data
 **/

void tlsFormatAdditionalData(TlsContext *context,
   const TlsSequenceNumber *seqNum, const void *record, uint8_t *aad)
{
#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      const DtlsRecord *dtlsRecord;

      //Point to the DTLS record
      dtlsRecord = (DtlsRecord *) record;

      //Additional data to be authenticated
      memcpy(aad, &dtlsRecord->epoch, 2);
      memcpy(aad + 2, &dtlsRecord->seqNum, 6);
      memcpy(aad + 8, &dtlsRecord->type, 3);
      memcpy(aad + 11, &dtlsRecord->length, 2);
   }
   else
#endif
   //TLS protocol?
   {
      const TlsRecord *tlsRecord;

      //Point to the TLS record
      tlsRecord = (TlsRecord *) record;

      //Additional data to be authenticated
      memcpy(aad, seqNum, 8);
      memcpy(aad + 8, tlsRecord, 5);
   }
}


/**
 * @brief Increment sequence number
 * @param[in] seqNum Sequence number to increment
 **/

void tlsIncSequenceNumber(TlsSequenceNumber *seqNum)
{
   int_t i;

   //Sequence numbers are stored MSB first
   for(i = 7; i >= 0; i--)
   {
      //Increment the current byte
      seqNum->b[i]++;

      //Propagate the carry if necessary
      if(seqNum->b[i] != 0)
         break;
   }
}

#endif
