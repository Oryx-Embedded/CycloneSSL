/**
 * @file ssl_misc.c
 * @brief SSL 3.0 helper functions
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
#include "core/crypto.h"
#include "tls.h"
#include "ssl_misc.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED && TLS_MIN_VERSION <= SSL_VERSION_3_0)

//pad1 pattern
const uint8_t sslPad1[48] =
{
   0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
   0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
   0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
};

//pad2 pattern
const uint8_t sslPad2[48] =
{
   0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
   0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
   0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C
};


/**
 * @brief Key expansion function (SSL 3.0)
 * @param[in] secret Pointer to the secret
 * @param[in] secretLen Length of the secret
 * @param[in] random Pointer to the random bytes
 * @param[in] randomLen Length of the random bytes
 * @param[out] output Pointer to the output
 * @param[in] outputLen Desired output length
 * @return Error code
 **/

error_t sslExpandKey(const uint8_t *secret, size_t secretLen,
   const uint8_t *random, size_t randomLen, uint8_t *output, size_t outputLen)
{
   uint_t i;
   size_t n;
   char_t pad[16];
   Md5Context *md5Context;
   Sha1Context *sha1Context;

   //Output length cannot exceed 256 bytes
   if(outputLen > (sizeof(pad) * MD5_DIGEST_SIZE))
      return ERROR_INVALID_LENGTH;

   //Allocate a memory buffer to hold the MD5 context
   md5Context = tlsAllocMem(sizeof(Md5Context));
   //Allocate a memory buffer to hold the SHA-1 context
   sha1Context = tlsAllocMem(sizeof(Sha1Context));

   //Failed to allocate memory?
   if(md5Context == NULL || sha1Context == NULL)
   {
      //Release previously allocated resources
      tlsFreeMem(md5Context);
      tlsFreeMem(sha1Context);

      //Report an error
      return ERROR_OUT_OF_MEMORY;
   }

   //Loop until enough output has been generated
   for(i = 0; outputLen > 0; i++)
   {
      //Generate pad
      memset(pad, 'A' + i, i + 1);

      //Compute SHA(pad + secret + random)
      sha1Init(sha1Context);
      sha1Update(sha1Context, pad, i + 1);
      sha1Update(sha1Context, secret, secretLen);
      sha1Update(sha1Context, random, randomLen);
      sha1Final(sha1Context, NULL);

      //Then compute MD5(secret + SHA(pad + secret + random))
      md5Init(md5Context);
      md5Update(md5Context, secret, secretLen);
      md5Update(md5Context, sha1Context->digest, SHA1_DIGEST_SIZE);
      md5Final(md5Context, NULL);

      //Calculate the number of bytes to copy
      n = MIN(outputLen, MD5_DIGEST_SIZE);
      //Copy the resulting hash value
      memcpy(output, md5Context->digest, n);

      //Advance data pointer
      output += n;
      //Decrement byte counter
      outputLen -= n;
   }

   //Release previously allocated resources
   tlsFreeMem(md5Context);
   tlsFreeMem(sha1Context);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Compute message authentication code (SSL 3.0)
 * @param[in] encryptionEngine Pointer to the encryption/decryption engine
 * @param[in] record Pointer to the TLS record
 * @param[in] data Pointer to the record data
 * @param[in] dataLen Length of the data
 * @param[out] mac The computed MAC value
 * @return Error code
 **/

error_t sslComputeMac(TlsEncryptionEngine *encryptionEngine,
   const TlsRecord *record, const uint8_t *data, size_t dataLen, uint8_t *mac)
{
   size_t padLen;
   const HashAlgo *hashAlgo;
   HashContext *hashContext;

   //Point to the hash algorithm to be used
   hashAlgo = encryptionEngine->hashAlgo;
   //Point to the hash context
   hashContext = (HashContext *) encryptionEngine->hmacContext->hashContext;

   //The length of pad1 and pad2 depends on hash algorithm
   if(hashAlgo == MD5_HASH_ALGO)
   {
      //48-byte long patterns are used with MD5
      padLen = 48;
   }
   else if(hashAlgo == SHA1_HASH_ALGO)
   {
      //40-byte long patterns are used with SHA-1
      padLen = 40;
   }
   else
   {
      //SSL 3.0 supports only MD5 and SHA-1 hash functions
      return ERROR_INVALID_PARAMETER;
   }

   //Compute hash(secret + pad1 + seqNum + type + length + data)
   hashAlgo->init(hashContext);
   hashAlgo->update(hashContext, encryptionEngine->macKey, encryptionEngine->macKeyLen);
   hashAlgo->update(hashContext, sslPad1, padLen);
   hashAlgo->update(hashContext, &encryptionEngine->seqNum, sizeof(TlsSequenceNumber));
   hashAlgo->update(hashContext, &record->type, sizeof(record->type));
   hashAlgo->update(hashContext, (void *) &record->length, sizeof(record->length));
   hashAlgo->update(hashContext, data, dataLen);
   hashAlgo->final(hashContext, mac);

   //Then compute hash(secret + pad2 + hash(secret + pad1 + seqNum + type + length + data))
   hashAlgo->init(hashContext);
   hashAlgo->update(hashContext, encryptionEngine->macKey, encryptionEngine->macKeyLen);
   hashAlgo->update(hashContext, sslPad2, padLen);
   hashAlgo->update(hashContext, mac, hashAlgo->digestSize);
   hashAlgo->final(hashContext, mac);

   //Successful processing
   return NO_ERROR;
}

#endif
