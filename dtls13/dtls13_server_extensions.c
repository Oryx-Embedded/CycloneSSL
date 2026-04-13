/**
 * @file dtls13_server_extensions.c
 * @brief Formatting and parsing of extensions (DTLS 1.3 server)
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
#include "tls13/tls13_server_misc.h"
#include "dtls13/dtls13_server_extensions.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && DTLS_SUPPORT == ENABLED && \
   TLS_SERVER_SUPPORT == ENABLED && TLS_MAX_VERSION >= TLS_VERSION_1_3)


/**
 * @brief Format Cookie extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the Cookie extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t dtls13FormatServerCookieExtension(TlsContext *context, uint8_t *p,
   size_t *written)
{
   size_t n;
   TlsExtension *extension;
   Tls13Cookie *cookie;

   //Initialize length field
   n = 0;

   //When sending a HelloRetryRequest, the server may provide a Cookie
   //extension to the client
   if(context->cookieLen > 0)
   {
      //Add the Cookie extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_COOKIE);

      //Point to the extension data field
      cookie = (Tls13Cookie *) extension->value;

      //When sending the new ClientHello, the client must copy the contents
      //of the Cookie extension received in the HelloRetryRequest
      osMemcpy(cookie->value, context->cookie, context->cookieLen);

      //Set the length of the cookie
      cookie->length = ntohs(context->cookieLen);

      //Consider the 2-byte length field that precedes the cookie
      n = sizeof(Tls13Cookie) + context->cookieLen;
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the Cookie extension
      n += sizeof(TlsExtension);
   }

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse Cookie extension
 * @param[in] context Pointer to the TLS context
 * @param[in] cookie Pointer to the Cookie extension
 * @return Error code
 **/

error_t dtls13ParseClientCookieExtension(TlsContext *context,
   const Tls13Cookie *cookie)
{
   error_t error;
   DtlsClientParameters clientParams;

   //Invalid key share?
   if(context->wrongKeyShare)
   {
      //Cookie extension found?
      if(cookie != NULL)
      {
         //If the server has sent a HelloRetryRequest, the client needs to
         //restart the handshake with an appropriate group
         error = ERROR_HANDSHAKE_FAILED;
      }
      else
      {
         //DTLS servers should perform a cookie exchange whenever a new
         //handshake is being performed (refer to RFC 9147, section 5.1)
         if(context->cookieVerifyCallback != NULL &&
            context->cookieGenerateCallback != NULL)
         {
            error = ERROR_WRONG_COOKIE;
         }
         else
         {
            error = NO_ERROR;
         }
      }
   }
   else
   {
      //Any registered callbacks?
      if(context->cookieVerifyCallback != NULL &&
         context->cookieGenerateCallback != NULL)
      {
         //Cookie extension found?
         if(cookie != NULL)
         {
            size_t n;
            const HashAlgo *hashAlgo;

            //The hash function used by HKDF is the cipher suite hash algorithm
            hashAlgo = context->cipherSuite.prfHashAlgo;

            //Make sure the HKDF hash algorithm is valid
            if(hashAlgo != NULL)
            {
               //Retrieve the length of the cookie
               n = ntohs(cookie->length);

               //Check the length of the cookie
               if(n > (hashAlgo->digestSize + 4) && n <= TLS13_MAX_COOKIE_SIZE)
               {
                  //The internal state is covered by the integrity check
                  osMemset(&clientParams, 0, sizeof(DtlsClientParameters));
                  clientParams.state = cookie->value;
                  clientParams.stateLen = hashAlgo->digestSize + 4;

                  //The server proceeds with the handshake only if the cookie is
                  //valid (refer to RFC 9147, section 5.1)
                  error = context->cookieVerifyCallback(context, &clientParams,
                     cookie->value + clientParams.stateLen,
                     n - clientParams.stateLen, context->cookieParam);

                  //Check status code
                  if(!error)
                  {
                     //The cookie allows the server to offload state to the client
                     error = dtls13ParseCookie(context, cookie->value, n);
                  }
               }
               else
               {
                  //Malformed cookie
                  error = ERROR_WRONG_COOKIE;
               }
            }
            else
            {
               //Invalid HKDF hash algorithm
               error = ERROR_FAILURE;
            }
         }
         else
         {
            //The Cookie extension is not present
            error = ERROR_WRONG_COOKIE;
         }
      }
      else
      {
         //The server may be configured not to perform a cookie exchange
         error = NO_ERROR;
      }
   }

   //Invalid cookie?
   if(error == ERROR_WRONG_COOKIE)
   {
      context->wrongCookie = TRUE;
      error = NO_ERROR;
   }

   //Return status code
   return error;
}


/**
 * @brief Cookie generation
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t dtls13GenerateCookie(TlsContext *context)
{
   error_t error;
   size_t n;
   DtlsClientParameters clientParams;

   //Any registered callbacks?
   if(context->cookieVerifyCallback != NULL &&
      context->cookieGenerateCallback != NULL)
   {
      //Release cookie
      if(context->cookie != NULL)
      {
         tlsFreeMem(context->cookie);
      }

      //Set the cookie size limit
      context->cookieLen = TLS13_MAX_COOKIE_SIZE;
      //Allocate a memory block to hold the cookie
      context->cookie = tlsAllocMem(context->cookieLen);

      //Successful memory allocation?
      if(context->cookie != NULL)
      {
         //Store the cipher suite identifier
         STORE16BE(context->cipherSuite.identifier, context->cookie);

         //Store the group identifier
         if(context->wrongKeyShare)
         {
            STORE16BE(context->namedGroup, context->cookie + 2);
         }
         else
         {
            STORE16BE(0, context->cookie + 2);
         }

         //A stateless server-cookie implementation requires the content or hash
         //of the initial ClientHello (and HelloRetryRequest) to be stored in
         //the cookie (refer to RFC 9147, section 5.1)
         osMemcpy(context->cookie + 4, context->clientHelloDigest,
            context->clientHelloDigestLen);

         //The internal state is covered by the integrity check
         osMemset(&clientParams, 0, sizeof(DtlsClientParameters));
         clientParams.state = context->cookie;
         clientParams.stateLen = context->clientHelloDigestLen + 4;

         //Maximum length of the integrity check value
         n = TLS13_MAX_COOKIE_SIZE - clientParams.stateLen;

         //The DTLS server should generate cookies in such a way that
         //they can be verified without retaining any per-client state on
         //the server
         error = context->cookieGenerateCallback(context, &clientParams,
            context->cookie + clientParams.stateLen, &n, context->cookieParam);

         //Check status code
         if(!error)
         {
            //Save the length of the cookie
            context->cookieLen = clientParams.stateLen + n;
         }
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }

      //Check status code
      if(!error)
      {
         //The DTLS 1.3 specification changes how cookies are exchanged
         //compared to DTLS 1.2. DTLS 1.3 reuses the HelloRetryRequest
         //message and conveys the cookie to the client via an extension
         context->wrongCookie = TRUE;
      }
   }
   else
   {
      //The server may be configured not to perform a cookie exchange
      error = NO_ERROR;
   }

   //Return status code
   return error;
}


/**
 * @brief Cookie parsing
 * @param[in] context Pointer to the TLS context
 * @param[in] cookie Pointer to the Cookie extension
 * @param[in] cookieLen Length of the cookie
 * @return Error code
 **/

error_t dtls13ParseCookie(TlsContext *context, const uint8_t *cookie,
   size_t cookieLen)
{
   error_t error;
   uint16_t cipherSuite;
   uint16_t namedGroup;
   const HashAlgo *hashAlgo;

   //The hash function used by HKDF is the cipher suite hash algorithm
   hashAlgo = context->cipherSuite.prfHashAlgo;

   //The cookie allows the server to offload state to the client
   cipherSuite = LOAD16BE(cookie);
   namedGroup = LOAD16BE(cookie + 2);

   //The cookie must allow the server to produce the right handshake transcript
   osMemcpy(context->clientHelloDigest, cookie + 4, hashAlgo->digestSize);

   //Save the length of Hash(ClientHello1)
   context->clientHelloDigestLen = hashAlgo->digestSize;

   //Invalid cipher suite?
   if(context->cipherSuite.identifier != cipherSuite)
      return ERROR_HANDSHAKE_FAILED;

   //Incorrect (EC)DHE share in the initial ClientHello?
   if(context->state == TLS_STATE_CLIENT_HELLO &&
      namedGroup != TLS_GROUP_NONE)
   {
      //Restore state
      context->namedGroup = namedGroup;
      tlsChangeState(context, TLS_STATE_CLIENT_HELLO_2);
   }

   //Release cookie
   if(context->cookie != NULL)
   {
      tlsFreeMem(context->cookie);
   }

   //Save the length of the cookie
   context->cookieLen = cookieLen;
   //Allocate a memory block to store the cookie
   context->cookie = tlsAllocMem(context->cookieLen);

   //Successful memory allocation?
   if(context->cookie != NULL)
   {
      //Save cookie
      osMemcpy(context->cookie, cookie, cookieLen);

      //When the server responds to a ClientHello with a HelloRetryRequest, the
      //value of ClientHello1 is replaced with a special synthetic handshake
      //message of handshake type MessageHash containing Hash(ClientHello1)
      error = tls13DigestClientHello1(context);

      //Check status code
      if(!error)
      {
         //Update the hash value with the contents of the HelloRetryRequest
         //message
         error = tls13DigestHelloRetryRequest(context, namedGroup);
      }
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
}

#endif
