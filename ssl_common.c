/**
 * @file ssl_common.c
 * @brief Functions common to SSL 3.0 client and server
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
 * @version 1.7.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include <string.h>
#include "crypto.h"
#include "tls.h"
#include "ssl_common.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED)

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
 * @param[in] secretLength Length of the secret
 * @param[in] random Pointer to the random bytes
 * @param[in] randomLength Length of the random bytes
 * @param[out] output Pointer to the output
 * @param[in] outputLength Desired output length
 * @return Error code
 **/

error_t sslExpandKey(const uint8_t *secret, size_t secretLength,
   const uint8_t *random, size_t randomLength, uint8_t *output, size_t outputLength)
{
   uint_t i;
   size_t n;
   char_t pad[16];
   Md5Context *md5Context;
   Sha1Context *sha1Context;

   //Output length cannot exceed 256 bytes
   if(outputLength > (sizeof(pad) * MD5_DIGEST_SIZE))
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
   for(i = 0; outputLength > 0; i++)
   {
      //Generate pad
      memset(pad, 'A' + i, i + 1);

      //Compute SHA(pad + secret + random)
      sha1Init(sha1Context);
      sha1Update(sha1Context, pad, i + 1);
      sha1Update(sha1Context, secret, secretLength);
      sha1Update(sha1Context, random, randomLength);
      sha1Final(sha1Context, NULL);

      //Then compute MD5(secret + SHA(pad + secret + random))
      md5Init(md5Context);
      md5Update(md5Context, secret, secretLength);
      md5Update(md5Context, sha1Context->digest, SHA1_DIGEST_SIZE);
      md5Final(md5Context, NULL);

      //Calculate the number of bytes to copy
      n = MIN(outputLength, MD5_DIGEST_SIZE);
      //Copy the resulting hash value
      memcpy(output, md5Context->digest, n);

      //Advance data pointer
      output += n;
      //Decrement byte counter
      outputLength -= n;
   }

   //Release previously allocated resources
   tlsFreeMem(md5Context);
   tlsFreeMem(sha1Context);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Compute message authentication code (SSL 3.0)
 * @param[in] context Pointer to the TLS context
 * @param[in] secret MAC secret
 * @param[in] seqNum 64-bit sequence number
 * @param[in] record Pointer to the TLS record
 * @param[in] data Pointer to the record data
 * @param[in] length Length of the data
 * @param[out] mac The computed MAC value
 * @return Error code
 **/

error_t sslComputeMac(TlsContext *context, const void *secret, TlsSequenceNumber seqNum,
   const TlsRecord *record, const uint8_t *data, size_t length, uint8_t *mac)
{
   size_t padLength;
   HashContext *hashContext;
   const HashAlgo *hash;

   //Hash function that will be used to compute MAC
   hash = context->hashAlgo;
   //Point to the hash context
   hashContext = (HashContext *) context->hmacContext.hashContext;

   //The length of pad1 and pad2 depends on hash algorithm
   if(hash == MD5_HASH_ALGO)
   {
      //48-byte long patterns are used with MD5
      padLength = 48;
   }
   else if(hash == SHA1_HASH_ALGO)
   {
      //40-byte long patterns are used with SHA-1
      padLength = 40;
   }
   else
   {
      //SSL 3.0 supports only MD5 and SHA-1 hash functions
      return ERROR_INVALID_PARAMETER;
   }

   //Compute hash(secret + pad1 + seqNum + type + length + data)
   hash->init(hashContext);
   hash->update(hashContext, secret, context->macKeyLen);
   hash->update(hashContext, sslPad1, padLength);
   hash->update(hashContext, seqNum, sizeof(TlsSequenceNumber));
   hash->update(hashContext, &record->type, sizeof(record->type));
   hash->update(hashContext, (void *) &record->length, sizeof(record->length));
   hash->update(hashContext, data, length);
   hash->final(hashContext, mac);

   //Then compute hash(secret + pad2 + hash(secret + pad1 + seqNum + type + length + data))
   hash->init(hashContext);
   hash->update(hashContext, secret, context->macKeyLen);
   hash->update(hashContext, sslPad2, padLength);
   hash->update(hashContext, mac, hash->digestSize);
   hash->final(hashContext, mac);

   //Successful processing
   return NO_ERROR;
}

#endif
