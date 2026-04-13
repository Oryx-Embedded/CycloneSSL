/**
 * @file dtls13_record_encrypt.c
 * @brief DTLS 1.3 record encryption
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
#include "dtls13/dtls13_record_encrypt.h"
#include "dtls13/dtls13_misc.h"
#include "cipher/cipher_algorithms.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && DTLS_SUPPORT == ENABLED && \
   TLS_MAX_VERSION >= TLS_VERSION_1_3)


/**
 * @brief Encrypt an outgoing DTLS 1.3 record
 * @param[in] context Pointer to the TLS context
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @param[in] type Record type
 * @param[in] data Pointer to the payload data
 * @param[in] dataLen Length of the payload data
 * @param[out] record Buffer where to store the encrypted DTLS record
 * @param[out] recordLen Length of the encrypted DTLS record, in bytes
 * @return Error code
 **/

error_t dtls13EncryptRecord(TlsContext *context,
   TlsEncryptionEngine *encryptionEngine, uint8_t type, const uint8_t *data,
   size_t dataLen, uint8_t *record, size_t *recordLen)
{
   error_t error;
   size_t n;
   size_t authTagLen;
   uint8_t header[5];
   size_t headerLen;
   uint8_t nonce[48];
   size_t nonceLen;

   //Retrieve the length of the authentication tag
   if(encryptionEngine->hashAlgo != NULL)
   {
      authTagLen = encryptionEngine->hashAlgo->digestSize;
   }
   else
   {
      authTagLen = encryptionEngine->authTagLen;
   }

   //The unified header is a structure of variable length
   n = 0;

   //Format the first byte of the unified header
   header[n++] = DTLS13_HEADER_FIXED | DTLS13_HEADER_FLAG_S |
      DTLS13_HEADER_FLAG_L | (encryptionEngine->epoch & DTLS13_HEADER_FLAG_E);

   //The record sequence number is 16 bits if the S bit is set to 1, and 8 bits
   //if the S bit is 0
   if((header[0] & DTLS13_HEADER_FLAG_S) != 0)
   {
      header[n++] = encryptionEngine->dtlsSeqNum.b[4];
      header[n++] = encryptionEngine->dtlsSeqNum.b[5];
   }
   else
   {
      header[n++] = encryptionEngine->dtlsSeqNum.b[5];
   }

   //The length field is present if the L bit is set
   if((header[0] & DTLS13_HEADER_FLAG_L) != 0)
   {
      //The length field is 16 bits
      header[n++] = MSB(dataLen + authTagLen + 1);
      header[n++] = LSB(dataLen + authTagLen + 1);
   }

   //Save the length of the unified header
   headerLen = n;

   //The DTLSCiphertext structure is formed by concatenating the unified_hdr
   //and encrypted_record fields
   osMemmove(record + headerLen, data, dataLen);
   osMemcpy(record, header, headerLen);

   //Debug message
   TRACE_DEBUG("Record to be encrypted (%" PRIuSIZE " bytes):\r\n", headerLen + dataLen);
   TRACE_DEBUG_ARRAY("  ", record, headerLen + dataLen);

   //The type field indicates the higher-level protocol used to process the
   //enclosed fragment
   record[headerLen + dataLen] = type;

   //Adjust the length of the payload data
   dataLen++;

   //Generate the nonce
   dtls13FormatNonce(encryptionEngine, &encryptionEngine->dtlsSeqNum, nonce,
      &nonceLen);

#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED || \
   TLS_GCM_CIPHER_SUPPORT == ENABLED || TLS_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //AEAD cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_CCM ||
      encryptionEngine->cipherMode == CIPHER_MODE_GCM ||
      encryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      //Perform authenticated encryption
      error = dtls13EncryptAeadRecord(context, encryptionEngine, nonce,
         nonceLen, record, headerLen, record + headerLen, dataLen,
         record + headerLen + dataLen);
   }
   else
#endif
#if (TLS_NULL_CIPHER_SUPPORT == ENABLED)
   //NULL cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_NULL)
   {
      //Compute message authentication code
      error = dtls13ComputeMac(context, encryptionEngine, nonce,
         nonceLen, record, headerLen, record + headerLen, dataLen,
         record + headerLen + dataLen);
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
      //In DTLS 1.3, when records are encrypted, record sequence numbers are
      //also encrypted (refer to RFC 9147, section 4.2.3)
      error = dtls13EncryptSequenceNumber(encryptionEngine, record);

   }

   //Check status code
   if(!error)
   {
      //Length of the resulting datagram, in bytes
      *recordLen = headerLen + dataLen + authTagLen;

      //Debug message
      TRACE_DEBUG("Encrypted record (%" PRIuSIZE " bytes):\r\n", *recordLen);
      TRACE_DEBUG_ARRAY("  ", record, *recordLen);
   }

   //Return status code
   return error;
}


/**
 * @brief Record encryption (AEAD cipher)
 * @param[in] context Pointer to the TLS context
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @param[in] nonce Nonce
 * @param[in] nonceLen Length of the nonce, in bytes
 * @param[in] aad Additional authenticated data
 * @param[in] aadLen Length of the additional data
 * @param[in,out] data Payload data
 * @param[in] dataLen Total number of data bytes to be encrypted
 * @param[out] tag Authentication tag
 * @return Error code
 **/

error_t dtls13EncryptAeadRecord(TlsContext *context,
   TlsEncryptionEngine *encryptionEngine, const uint8_t *nonce,
   size_t nonceLen, const uint8_t *aad, size_t aadLen, uint8_t *data,
   size_t dataLen, uint8_t *tag)
{
   error_t error;

#if (TLS_CCM_CIPHER_SUPPORT == ENABLED || TLS_CCM_8_CIPHER_SUPPORT == ENABLED)
   //CCM AEAD cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_CCM)
   {
      //Authenticated encryption using CCM
      error = ccmEncrypt(encryptionEngine->cipherAlgo,
         encryptionEngine->cipherContext, nonce, nonceLen, aad, aadLen,
         data, data, dataLen, tag, encryptionEngine->authTagLen);
   }
   else
#endif
#if (TLS_GCM_CIPHER_SUPPORT == ENABLED)
   //GCM AEAD cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_GCM)
   {
      //Authenticated encryption using GCM
      error = gcmEncrypt(encryptionEngine->gcmContext, nonce, nonceLen,
         aad, aadLen, data, data, dataLen, tag, encryptionEngine->authTagLen);
   }
   else
#endif
#if (TLS_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //ChaCha20Poly1305 AEAD cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      //Authenticated encryption using ChaCha20Poly1305
      error = chacha20Poly1305Encrypt(encryptionEngine->encKey,
         encryptionEngine->encKeyLen, nonce, nonceLen, aad, aadLen,
         data, data, dataLen, tag, encryptionEngine->authTagLen);
   }
   else
#endif
   //Invalid cipher mode?
   {
      //The specified cipher mode is not supported
      error = ERROR_UNSUPPORTED_CIPHER_MODE;
   }

   //Successful processing
   return error;
}


/**
 * @brief Compute message authentication code
 * @param[in] context Pointer to the TLS context
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @param[in] nonce Nonce
 * @param[in] nonceLen Length of the nonce, in bytes
 * @param[in] aad Additional authenticated data
 * @param[in] aadLen Length of the additional data
 * @param[in] data Payload data
 * @param[in] dataLen Total number of data bytes to be authenticated
 * @param[out] mac Message authentication code
 * @return Error code
 **/

error_t dtls13ComputeMac(TlsContext *context,
   TlsEncryptionEngine *encryptionEngine, const uint8_t *nonce,
   size_t nonceLen, const uint8_t *aad, size_t aadLen, const uint8_t *data,
   size_t dataLen, uint8_t *mac)
{
   HmacContext *hmacContext;

   //Point to the HMAC context
   hmacContext = encryptionEngine->hmacContext;

   //The protect operation provides the integrity protection using HMAC SHA-256
   //or HMAC SHA-384 (refer to RFC 9150, section 5)
   hmacInit(hmacContext, encryptionEngine->hashAlgo,
      encryptionEngine->encKey, encryptionEngine->encKeyLen);

   //Compute HMAC(write_key, nonce || additional_data || DTLSInnerPlaintext)
   hmacUpdate(hmacContext, nonce, nonceLen);
   hmacUpdate(hmacContext, aad, aadLen);
   hmacUpdate(hmacContext, data, dataLen);

   //Finalize HMAC computation
   hmacFinal(hmacContext, mac);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Encrypt sequence number
 * @param[in] encryptionEngine Pointer to the encryption engine
 * @param[in,out] record Pointer to the DTLS 1.3 record
 * @return Error code
 **/

error_t dtls13EncryptSequenceNumber(TlsEncryptionEngine *encryptionEngine,
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
   if(encryptionEngine->cipherMode == CIPHER_MODE_CCM ||
      encryptionEngine->cipherMode == CIPHER_MODE_GCM)
   {
      //When the AEAD is based on AES, then the mask is generated by computing
      //AES-ECB on the first 16 bytes of the ciphertext (refer to RFC 9147,
      //section 4.2.3)
      encryptionEngine->cipherAlgo->encryptBlock(
         encryptionEngine->snCipherContext, record + n, mask);
   }
   else
#endif
#if (TLS_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //ChaCha20Poly1305 AEAD cipher?
   if(encryptionEngine->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      ChachaContext chachaContext;

      //When the AEAD is based on ChaCha20, then the mask is generated by
      //treating the first 4 bytes of the ciphertext as the block counter and
      //the next 12 bytes as the nonce
      error = chachaInit(&chachaContext, 20, encryptionEngine->snKey,
         encryptionEngine->encKeyLen, record + n, 16);

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
   if(encryptionEngine->cipherMode == CIPHER_MODE_NULL)
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

#endif
