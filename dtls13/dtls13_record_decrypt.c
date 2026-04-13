/**
 * @file dtls13_record_decrypt.c
 * @brief DTLS 1.3 record decryption
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
#include "dtls13/dtls13_record_decrypt.h"
#include "dtls13/dtls13_misc.h"
#include "cipher/cipher_algorithms.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && DTLS_SUPPORT == ENABLED && \
   TLS_MAX_VERSION >= TLS_VERSION_1_3)


/**
 * @brief Receive a DTLS 1.3 record
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t dtls13ReadRecord(TlsContext *context)
{
   error_t error;
   uint8_t *record;

   //Point to the DTLS record
   record = context->rxBuffer + context->rxDatagramPos;

   //Implementations can demultiplex DTLS 1.3 records by examining the first
   //byte (refer to RFC 9147, section 4.1)
   if(record[0] == TLS_TYPE_ALERT || record[0] == TLS_TYPE_HANDSHAKE ||
      record[0] == TLS_TYPE_ACK)
   {
      //If the first byte is alert(21), handshake(22), or ack(26), the record
      //must be interpreted as a DTLSPlaintext record
      error = dtls13ReadPlaintextRecord(context, record);
   }
   else if((record[0] & DTLS13_HEADER_MASK) == DTLS13_HEADER_FIXED)
   {
      //If the leading bits of the first byte are 001, the implementation
      //must process the record as DTLSCiphertext
      error = dtls13ReadCiphertextRecord(context, record);
   }
   else
   {
      //Otherwise, the record must be rejected as if it had failed deprotection
      context->rxDatagramLen = 0;
      //Report an error
      error = ERROR_BAD_RECORD_MAC;
   }

   //Return status code
   return error;
}


/**
 * @brief Receive a DTLSPlaintext record
 * @param[in] context Pointer to the TLS context
 * @param[in] record Pointer to the DTLSPlaintext structure
 * @return Error code
 **/

error_t dtls13ReadPlaintextRecord(TlsContext *context, uint8_t *record)
{
   error_t error;
   size_t dataLen;
   DtlsRecord *header;
   TlsEncryptionEngine *decryptionEngine;

   //The DTLSPlaintext structure has a fixed-length header
   header = (DtlsRecord *) record;

   //Malformed datagram?
   if(context->rxDatagramLen < sizeof(DtlsRecord))
   {
      //Drop the received datagram
      context->rxDatagramLen = 0;
      //Report an error
      return ERROR_INVALID_LENGTH;
   }

   //Retrieve the length of the payload
   dataLen = ntohs(header->length);

   //Malformed DTLS record?
   if((dataLen + sizeof(DtlsRecord)) > context->rxDatagramLen)
   {
      //Drop the received datagram
      context->rxDatagramLen = 0;
      //Report an error
      return ERROR_BAD_RECORD_MAC;
   }

   //Point to the payload data
   context->rxRecordPos = context->rxDatagramPos + sizeof(DtlsRecord);

   //Multiple DTLSPlaintext and DTLSCiphertext records can be included in the
   //same underlying transport datagram (refer to RFC 9147, section 4)
   context->rxDatagramPos += dataLen + sizeof(DtlsRecord);
   context->rxDatagramLen -= dataLen + sizeof(DtlsRecord);

   //Point to the decryption engine
   decryptionEngine = &context->decryptionEngine[0];

   //DTLSPlaintext records are used to send unprotected records
   if(decryptionEngine->cipherMode != CIPHER_MODE_NULL ||
      decryptionEngine->hashAlgo != NULL)
   {
      //Discard the offending record
      return ERROR_UNEXPECTED_MESSAGE;
   }

   //Compliant servers must accept any value {254,XX} as the record layer
   //version number for ClientHello
   if(MSB(ntohs(header->version)) != MSB(DTLS_VERSION_1_0))
      return ERROR_VERSION_NOT_SUPPORTED;

   //Discard packets from earlier epochs
   if(ntohs(header->epoch) != decryptionEngine->epoch)
      return ERROR_INVALID_EPOCH;

   //Check whether anti-replay mechanism is enabled
   if(context->replayDetectionEnabled)
   {
      //Perform replay detection
      error = dtlsCheckReplayWindow(decryptionEngine, &header->seqNum);
      //Any error to report?
      if(error)
         return error;
   }

   //Update the receive window
   dtlsUpdateReplayWindow(decryptionEngine, &header->seqNum);

   //Save record version
   context->rxRecordVersion = ntohs(header->version);
   //Save record type
   context->rxBufferType = (TlsContentType) header->type;
   //Save record length
   context->rxRecordLen = dataLen;

   //Save record number
   context->rxRecordNum.epoch = ntohs(header->epoch);
   context->rxRecordNum.seqNum = LOAD48BE(header->seqNum.b);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Receive a DTLSCiphertext record
 * @param[in] context Pointer to the TLS context
 * @param[in] record Pointer to the DTLSCiphertext structure
 * @return Error code
 **/

error_t dtls13ReadCiphertextRecord(TlsContext *context, uint8_t *record)
{
   error_t error;
   uint_t i;
   uint8_t type;
   uint16_t epoch;
   size_t headerLen;
   size_t dataLen;
   DtlsSequenceNumber seqNum;
   TlsEncryptionEngine *decryptionEngine;

   //The unified header is a structure of variable length
   headerLen = sizeof(uint8_t);

   //Malformed datagram?
   if(context->rxDatagramLen < headerLen)
   {
      //Drop the received datagram
      context->rxDatagramLen = 0;
      //Report an error
      return ERROR_INVALID_LENGTH;
   }

   //The C bit is set if the Connection ID is present
   if((record[0] & DTLS13_HEADER_FLAG_C) != 0)
   {
      //Drop the received datagram
      context->rxDatagramLen = 0;
      //Report an error
      return ERROR_INVALID_LENGTH;
   }

   //The record sequence number is 16 bits if the S bit is set to 1, and 8 bits
   //if the S bit is 0
   if((record[0] & DTLS13_HEADER_FLAG_S) != 0)
   {
      headerLen += sizeof(uint16_t);
   }
   else
   {
      headerLen += sizeof(uint8_t);
   }

   //The length field is present if the L bit is set
   if((record[0] & DTLS13_HEADER_FLAG_L) != 0)
   {
      headerLen += sizeof(uint16_t);
   }

   //Malformed datagram?
   if(context->rxDatagramLen < headerLen)
   {
      //Drop the received datagram
      context->rxDatagramLen = 0;
      //Report an error
      return ERROR_INVALID_LENGTH;
   }

   //The length field may be omitted by clearing the L bit, which means that
   //the record consumes the entire rest of the datagram in the lower level
   //transport (refer to RFC 9147, section 4)
   if((record[0] & DTLS13_HEADER_FLAG_L) != 0)
   {
      dataLen = LOAD16BE(record + headerLen - sizeof(uint16_t));
   }
   else
   {
      dataLen = context->rxDatagramLen - headerLen;
   }

   //Malformed DTLS record?
   if((headerLen + dataLen) > context->rxDatagramLen)
   {
      //Drop the received datagram
      context->rxDatagramLen = 0;
      //Report an error
      return ERROR_BAD_RECORD_MAC;
   }

   //Point to the payload data
   context->rxRecordPos = context->rxDatagramPos + headerLen;

   //Multiple DTLSPlaintext and DTLSCiphertext records can be included in the
   //same underlying transport datagram (refer to RFC 9147, section 4)
   context->rxDatagramPos += headerLen + dataLen;
   context->rxDatagramLen -= headerLen + dataLen;

   //The two low bits include the low-order two bits of the epoch
   epoch = record[0] & DTLS13_HEADER_FLAG_E;

   //If the epoch bits do not match those from the current epoch,
   //implementations should use the most recent past epoch which has
   //matching bits (refer to RFC 9147, section 4.2.2)
   for(decryptionEngine = NULL, i = 0; i < TLS_MAX_DECRYPTION_ENGINES; i++)
   {
      //Valid decryption engine?
      if(context->decryptionEngine[i].active)
      {
         //Matching epoch bits?
         if((context->decryptionEngine[i].epoch & 3) == epoch)
         {
            decryptionEngine = &context->decryptionEngine[i];
            break;
         }
      }
   }

   //Invalid keying material?
   if(decryptionEngine == NULL)
      return ERROR_INVALID_EPOCH;

   //In DTLS 1.3, when records are encrypted, record sequence numbers are
   //also encrypted (refer to RFC 9147, section 4.2.3)
   error = dtls13DecryptSequenceNumber(decryptionEngine, record);
   //Chek status code
   if(error)
      return error;

   //Reconstruct the sequence number
   dtls13ReconstructSequenceNumber(decryptionEngine, record, &seqNum);

   //Check whether anti-replay mechanism is enabled
   if(context->replayDetectionEnabled)
   {
      //Perform replay detection
      error = dtlsCheckReplayWindow(decryptionEngine, &seqNum);
      //Any error to report?
      if(error)
         return error;
   }

   //DTLSCiphertext records are used to send protected records
   if(decryptionEngine->cipherMode != CIPHER_MODE_NULL ||
      decryptionEngine->hashAlgo != NULL)
   {
      size_t nonceLen;
      uint8_t nonce[48];

      //Generate the nonce
      dtls13FormatNonce(decryptionEngine, &seqNum, nonce, &nonceLen);

      //Decrypt DTLS 1.3 record
      error = dtls13DecryptRecord(context, decryptionEngine, nonce, nonceLen,
         record, headerLen, record + headerLen, &dataLen, &type);
      //If the MAC validation fails, the receiver must discard the record
      if(error)
         return error;

      //The length of the plaintext record must not exceed 2^14 bytes
      if(dataLen > TLS_MAX_RECORD_LENGTH)
         return ERROR_RECORD_OVERFLOW;
   }
   else
   {
      //Discard the offending record
      return ERROR_UNEXPECTED_MESSAGE;
   }

   //Check current state
   if(context->state == TLS_STATE_APPLICATION_DATA ||
      context->state == TLS_STATE_CLIENT_FINISHED_ACK ||
      context->state == TLS_STATE_NEW_SESSION_TICKET_ACK ||
      context->state == TLS_STATE_KEY_UPDATE_ACK)
   {
      //Due to the possibility of an ACK message for a KeyUpdate being lost and
      //thereby preventing the sender of the KeyUpdate from updating its keying
      //material, receivers must retain the pre-update keying material until
      //receipt and successful decryption of a message using the new keys
      if(i == 0 && context->decryptionEngine[1].active)
      {
         context->decryptionEngine[1].lifetime = 60000;
         context->decryptionEngine[1].timestamp = osGetSystemTime();
      }
   }

   //The receive window is updated only if the MAC verification succeeds
   dtlsUpdateReplayWindow(decryptionEngine, &seqNum);

   //Debug message
   TRACE_DEBUG("DTLS decrypted record received (%" PRIuSIZE " bytes)...\r\n", headerLen + dataLen);
   TRACE_DEBUG_ARRAY("  ", record, headerLen + dataLen);

   //Save record version
   context->rxRecordVersion = DTLS_VERSION_1_3;
   //Save record type
   context->rxBufferType = (TlsContentType) type;
   //Save record length
   context->rxRecordLen = dataLen;

   //Save record number
   context->rxRecordNum.epoch = decryptionEngine->epoch;
   context->rxRecordNum.seqNum = LOAD48BE(seqNum.b);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Decrypt an incoming DTLS 1.3 record
 * @param[in] context Pointer to the TLS context
 * @param[in] decryptionEngine Pointer to the decryption engine
 * @param[in] nonce Nonce
 * @param[in] nonceLen Length of the nonce, in bytes
 * @param[in] aad Additional authenticated data
 * @param[in] aadLen Length of the additional data
 * @param[in,out] data Payload data
 * @param[in] dataLen Actual length of the payload data
 * @param[out] type Record type
 * @return Error code
 **/

error_t dtls13DecryptRecord(TlsContext *context,
   TlsEncryptionEngine *decryptionEngine, const uint8_t *nonce,
   size_t nonceLen, const uint8_t *aad, size_t aadLen, uint8_t *data,
   size_t *dataLen, uint8_t *type)
{
   error_t error;
   size_t n;
   size_t authTagLen;

   //Get the length of the ciphertext
   n = *dataLen;

   //Debug message
   TRACE_DEBUG("Record to be decrypted (%" PRIuSIZE " bytes):\r\n", n);
   TRACE_DEBUG_ARRAY("  ", data, n);

   //Retrieve the length of the authentication tag
   if(decryptionEngine->hashAlgo != NULL)
   {
      authTagLen = decryptionEngine->hashAlgo->digestSize;
   }
   else
   {
      authTagLen = decryptionEngine->authTagLen;
   }

   //Make sure the message length is acceptable
   if(n < authTagLen)
      return ERROR_BAD_RECORD_MAC;

   //Calculate the length of the ciphertext
   n -= authTagLen;

   //The length must not exceed 2^14 octets + 1 octet for ContentType + the
   //maximum AEAD expansion. An endpoint that receives a record that exceeds
   //this length must terminate the connection with a record_overflow alert
   if(n > (TLS_MAX_RECORD_LENGTH + 1))
      return ERROR_RECORD_OVERFLOW;

#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED || \
   TLS_GCM_CIPHER_SUPPORT == ENABLED || TLS_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //AEAD cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_CCM ||
      decryptionEngine->cipherMode == CIPHER_MODE_GCM ||
      decryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      //Perform authenticated decryption
      error = dtls13DecryptAeadRecord(context, decryptionEngine, nonce,
         nonceLen, aad, aadLen, data, n, data + n);
   }
   else
#endif
#if (TLS_NULL_CIPHER_SUPPORT == ENABLED)
   //NULL cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_NULL)
   {
      //Verify message authentication code
      error = dtls13VerifyMac(context, decryptionEngine, nonce, nonceLen, aad,
         aadLen, data, n, data + n);
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

   //Upon successful decryption of an encrypted record, the receiving
   //implementation scans the field from the end toward the beginning
   //until it finds a non-zero octet
   while(n > 0 && data[n - 1] == 0)
   {
      n--;
   }

   //If a receiving implementation does not find a non-zero octet in the
   //cleartext, it must terminate the connection with an unexpected_message
   //alert
   if(n == 0)
      return ERROR_UNEXPECTED_MESSAGE;

   //Retrieve the length of the plaintext
   n--;

   //The actual content type of the record is found in the type field
   *type = data[n];

   //Debug message
   TRACE_DEBUG("Decrypted record (%" PRIuSIZE " bytes):\r\n", n);
   TRACE_DEBUG_ARRAY("  ", data, n);

   //Return the length of the plaintext
   *dataLen = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Record decryption (AEAD cipher)
 * @param[in] context Pointer to the TLS context
 * @param[in] decryptionEngine Pointer to the decryption engine
 * @param[in] nonce Nonce
 * @param[in] nonceLen Length of the nonce, in bytes
 * @param[in] aad Additional authenticated data
 * @param[in] aadLen Length of the additional data
 * @param[in,out] data Payload data
 * @param[in] dataLen Total number of data bytes to be decrypted
 * @param[out] tag Authentication tag
 * @return Error code
 **/

error_t dtls13DecryptAeadRecord(TlsContext *context,
   TlsEncryptionEngine *decryptionEngine, const uint8_t *nonce,
   size_t nonceLen, const uint8_t *aad, size_t aadLen, uint8_t *data,
   size_t dataLen, uint8_t *tag)
{
   error_t error;

#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED)
   //CCM AEAD cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_CCM)
   {
      //Authenticated decryption using CCM
      error = ccmDecrypt(decryptionEngine->cipherAlgo,
         decryptionEngine->cipherContext, nonce, nonceLen, aad, aadLen,
         data, data, dataLen, tag, decryptionEngine->authTagLen);
   }
   else
#endif
#if (TLS_GCM_CIPHER_SUPPORT == ENABLED)
   //GCM AEAD cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_GCM)
   {
      //Authenticated decryption using GCM
      error = gcmDecrypt(decryptionEngine->gcmContext, nonce, nonceLen,
         aad, aadLen, data, data, dataLen, tag, decryptionEngine->authTagLen);
   }
   else
#endif
#if (TLS_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //ChaCha20Poly1305 AEAD cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      //Authenticated decryption using ChaCha20Poly1305
      error = chacha20Poly1305Decrypt(decryptionEngine->encKey,
         decryptionEngine->encKeyLen, nonce, 12, aad, aadLen, data,
         data, dataLen, tag, decryptionEngine->authTagLen);
   }
   else
#endif
   //Invalid cipher mode?
   {
      //The specified cipher mode is not supported
      error = ERROR_UNSUPPORTED_CIPHER_MODE;
   }

   //Return status code
   return error;
}


/**
 * @brief Check message authentication code
 * @param[in] context Pointer to the TLS context
 * @param[in] decryptionEngine Pointer to the decryption engine
 * @param[in] nonce Nonce
 * @param[in] nonceLen Length of the nonce, in bytes
 * @param[in] aad Additional authenticated data
 * @param[in] aadLen Length of the additional data
 * @param[in] data Payload data
 * @param[in] dataLen Total number of data bytes to be authenticated
 * @param[out] mac Message authentication code
 * @return Error code
 **/

error_t dtls13VerifyMac(TlsContext *context,
   TlsEncryptionEngine *decryptionEngine, const uint8_t *nonce,
   size_t nonceLen, const uint8_t *aad, size_t aadLen, const uint8_t *data,
   size_t dataLen, uint8_t *mac)
{
   size_t i;
   uint8_t mask;
   HmacContext *hmacContext;
   uint8_t temp[MAX_HASH_DIGEST_SIZE];

   //Point to the HMAC context
   hmacContext = decryptionEngine->hmacContext;

   //The protect operation provides the integrity protection using HMAC SHA-256
   //or HMAC SHA-384 (refer to RFC 9150, section 5)
   hmacInit(hmacContext, decryptionEngine->hashAlgo,
      decryptionEngine->encKey, decryptionEngine->encKeyLen);

   //Compute HMAC(write_key, nonce || additional_data || DTLSInnerPlaintext)
   hmacUpdate(hmacContext, nonce, nonceLen);
   hmacUpdate(hmacContext, aad, aadLen);
   hmacUpdate(hmacContext, data, dataLen);

   //Finalize HMAC computation
   hmacFinal(hmacContext, temp);

   //The calculated MAC is bitwise compared to the received message
   //authentication code
   for(mask = 0, i = 0; i < decryptionEngine->hashAlgo->digestSize; i++)
   {
      mask |= mac[i] ^ temp[i];
   }

   //The message is authenticated if and only if the MAC values match
   return (mask == 0) ? NO_ERROR : ERROR_BAD_RECORD_MAC;
}


/**
 * @brief Decrypt sequence number
 * @param[in] decryptionEngine Pointer to the decryption engine
 * @param[in,out] record Pointer to the DTLS 1.3 record
 * @return Error code
 **/

error_t dtls13DecryptSequenceNumber(TlsEncryptionEngine *decryptionEngine,
   uint8_t *record)
{
   error_t error;
   size_t n;
   uint8_t mask[16];

   //Initialize status code
   error = NO_ERROR;

   //The DTLS 1.3 unified header is a structure of variable length
   n = sizeof(uint8_t);

   //The record sequence number is 16 bits if the S bit is set to 1, and 8 bits
   //if the S bit is 0
   if((record[0] & DTLS13_HEADER_FLAG_S) != 0)
   {
      n += sizeof(uint16_t);
   }
   else
   {
      n += sizeof(uint8_t);
   }

   //The length field is present if the L bit is set
   if((record[0] & DTLS13_HEADER_FLAG_L) != 0)
   {
      n += sizeof(uint16_t);
   }

#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED || \
   TLS_GCM_CIPHER_SUPPORT == ENABLED)
   //CCM or GCM AEAD cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_CCM ||
      decryptionEngine->cipherMode == CIPHER_MODE_GCM)
   {
      //When the AEAD is based on AES, then the mask is generated by computing
      //AES-ECB on the first 16 bytes of the ciphertext (refer to RFC 9147,
      //section 4.2.3)
      decryptionEngine->cipherAlgo->encryptBlock(
         decryptionEngine->snCipherContext, record + n, mask);
   }
   else
#endif
#if (TLS_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //ChaCha20Poly1305 AEAD cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      ChachaContext chachaContext;

      //When the AEAD is based on ChaCha20, then the mask is generated by
      //treating the first 4 bytes of the ciphertext as the block counter and
      //the next 12 bytes as the nonce
      error = chachaInit(&chachaContext, 20, decryptionEngine->snKey,
         decryptionEngine->encKeyLen, record + n, 16);

      //Check status code
      if(!error)
      {
         //Invoke ChaCha20 block function
         chachaCipher(&chachaContext, NULL, mask, 2);
      }
   }
   else
#endif
#if (TLS_NULL_CIPHER_SUPPORT == ENABLED)
   //NULL cipher?
   if(decryptionEngine->cipherMode == CIPHER_MODE_NULL)
   {
      //For integrity-only cipher suites, the record sequence numbers are sent
      //unencrypted (refer to RFC 9150, section 9)
      mask[0] = 0;
      mask[1] = 0;
   }
   else
#endif
   //Invalid cipher mode?
   {
      //The specified cipher mode is not supported
      error = ERROR_UNSUPPORTED_CIPHER_MODE;
   }

   //Check status code
   if(!error)
   {
      //The encrypted sequence number is computed by XORing the leading bytes
      //of the mask with the on-the-wire representation of the sequence number
      if((record[0] & DTLS13_HEADER_FLAG_S) != 0)
      {
         record[1] ^= mask[0];
         record[2] ^= mask[1];
      }
      else
      {
         record[1] ^= mask[0];
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Sequence number reconstruction
 * @param[in] decryptionEngine Pointer to the decryption engine
 * @param[in,out] record Pointer to the DTLS 1.3 record
 * @param[out] seqNum Reconstructed sequence number
 **/

void dtls13ReconstructSequenceNumber(TlsEncryptionEngine *decryptionEngine,
   const uint8_t *record, DtlsSequenceNumber *seqNum)
{
   uint64_t n;
   uint64_t n1;
   uint64_t n2;
   uint64_t n3;
   uint64_t delta1;
   uint64_t delta2;
   uint64_t delta3;
   uint64_t mask;
   uint64_t next;

   //The record sequence number is 16 bits if the S bit is set to 1, and 8 bits
   //if the S bit is 0
   if((record[0] & DTLS13_HEADER_FLAG_S) != 0)
   {
      //Retrieve the low-order 16 bits of the record sequence number
      n = LOAD16BE(record + 1);
      mask = 0xFFFF;
   }
   else
   {
      //Retrieve the low-order 8 bits of the record sequence number
      n = record[1];
      mask = 0xFF;
   }

   //Implementations should reconstruct the sequence number by computing the
   //full sequence number which is numerically closest to one plus the
   //sequence number of the highest successfully deprotected record in the
   //current epoch (refer to RFC 9147, section 4.2.2)
   next = LOAD48BE(decryptionEngine->dtlsSeqNum.b) + 1;

   //Compute the 3 possible full sequence numbers
   n1 = ((next & ~mask) - (mask + 1)) | n;
   n2 = (next & ~mask) | n;
   n3 = ((next & ~mask) + (mask + 1)) | n;

   //Enforce the DTLS 1.2 2^48-1 limit
   n1 &= DTLS_MAX_SEQUENCE_NUMBER;
   n2 &= DTLS_MAX_SEQUENCE_NUMBER;
   n3 &= DTLS_MAX_SEQUENCE_NUMBER;

   //Compute the corresponding deltas
   delta1 = (n1 > next) ? (n1 - next) : (next - n1);
   delta2 = (n2 > next) ? (n2 - next) : (next - n2);
   delta3 = (n3 > next) ? (n3 - next) : (next - n3);

   //Determine the full sequence number which is numerically closest
   if(delta3 <= delta1 && delta3 <= delta2)
   {
      STORE48BE(n3, seqNum->b);
   }
   else if(delta2 <= delta1 && delta2 <= delta3)
   {
      STORE48BE(n2, seqNum->b);
   }
   else
   {
      STORE48BE(n1, seqNum->b);
   }
}

#endif
