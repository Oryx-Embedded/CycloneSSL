/**
 * @file tls_cache.c
 * @brief Session cache management
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
 * @version 2.6.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include "tls/tls.h"
#include "tls/tls_cache.h"
#include "tls/tls_misc.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Session cache initialization
 * @param[in] size Maximum number of cache entries
 * @return Handle referencing the fully initialized session cache
 **/

TlsCache *tlsInitCache(uint_t size)
{
   size_t n;
   TlsCache *cache;

   //Make sure the parameter is acceptable
   if(size < 1)
      return NULL;

   //Size of the memory required
   n = sizeof(TlsCache) + size * sizeof(TlsSessionState);

   //Allocate a memory buffer to hold the session cache
   cache = tlsAllocMem(n);
   //Failed to allocate memory?
   if(cache == NULL)
      return NULL;

   //Clear memory
   osMemset(cache, 0, n);

   //Create a mutex to prevent simultaneous access to the cache
   if(!osCreateMutex(&cache->mutex))
   {
      //Clean up side effects
      tlsFreeMem(cache);
      //Report an error
      return NULL;
   }

   //Save the maximum number of cache entries
   cache->size = size;

   //Return a pointer to the newly created cache
   return cache;
}


/**
 * @brief Lock session cache
 * @param[in] cache Pointer to the session cache
 **/

void tlsLockCache(TlsCache *cache)
{
   //Valid session cache?
   if(cache != NULL)
   {
      //Acquire exclusive access to the session cache
      osAcquireMutex(&cache->mutex);
   }
}


/**
 * @brief Unlock session cache
 * @param[in] cache Pointer to the session cache
 **/

void tlsUnlockCache(TlsCache *cache)
{
   //Valid session cache?
   if(cache != NULL)
   {
      //Release exclusive access to the session cache
      osReleaseMutex(&cache->mutex);
   }
}


/**
 * @brief Search the session cache for a given session ID
 * @param[in] cache Pointer to the session cache
 * @param[in] sessionId Expected session ID
 * @param[in] sessionIdLen Length of the session ID
 * @return Pointer to the matching session, if any
 **/

TlsSessionState *tlsFindSession(TlsCache *cache, const uint8_t *sessionId,
   size_t sessionIdLen)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   uint_t i;
   systime_t time;
   TlsSessionState *session;

   //Check parameters
   if(cache != NULL && sessionId != NULL && sessionIdLen > 0)
   {
      //Get current time
      time = osGetSystemTime();

      //Flush expired entries
      for(i = 0; i < cache->size; i++)
      {
         //Point to the current entry
         session = &cache->sessions[i];

         //Valid entry?
         if(session->sessionIdLen != 0)
         {
            //Outdated entry?
            if((time - session->timestamp) >= TLS_SESSION_CACHE_LIFETIME)
            {
               tlsFreeSessionState(session);
            }
         }
      }

      //Search the cache for the specified session ID
      for(i = 0; i < cache->size; i++)
      {
         //Point to the current entry
         session = &cache->sessions[i];

         //Matching session?
         if(session->sessionIdLen == sessionIdLen &&
            osMemcmp(session->sessionId, sessionId, sessionIdLen) == 0)
         {
            return session;
         }
      }
   }
#endif

   //No matching session
   return NULL;
}


/**
 * @brief Create a new entry in the session cache
 * @param[in] cache Pointer to the session cache
 * @return Pointer to the newly created session
 **/

TlsSessionState *tlsCreateSession(TlsCache *cache)
{
   uint_t i;
   systime_t time;
   TlsSessionState *session;
   TlsSessionState *oldestSession;

   //Search the cache for a free entry
   for(i = 0; i < cache->size; i++)
   {
      //Point to the current entry
      session = &cache->sessions[i];

      //Check whether the session is a available for use
      if(session->sessionIdLen == 0)
      {
         return session;
      }
   }

   //Get current time
   time = osGetSystemTime();
   //Keep track of the oldest session
   oldestSession = NULL;

   //Search the cache for the oldest entry
   for(i = 0; i < cache->size; i++)
   {
      //Point to the current entry
      session = &cache->sessions[i];

      //Keep track of the oldest entry
      if(oldestSession == NULL)
      {
         oldestSession = session;
      }
      else if((time - session->timestamp) > (time - oldestSession->timestamp))
      {
         oldestSession = session;
      }
      else
      {
      }
   }

   //Release the oldest entry if any
   if(oldestSession != NULL)
   {
      tlsFreeSessionState(oldestSession);
   }

   //Pointer to the newly created session
   return oldestSession;
}


/**
 * @brief Save current session in cache
 * @param[in] context TLS context
 * @return Error code
 **/

error_t tlsSaveToCache(TlsContext *context)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   error_t error;
   TlsSessionState *session;

   //Check parameters
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether session caching is supported
   if(context->cache == NULL)
      return ERROR_FAILURE;

   //Ensure the session ID is valid
   if(context->sessionIdLen == 0)
      return NO_ERROR;

   //Acquire exclusive access to the session cache
   tlsLockCache(context->cache);

   //Search the session cache for a given session ID
   session = tlsFindSession(context->cache, context->sessionId,
      context->sessionIdLen);

   //Matching entry found?
   if(session != NULL)
   {
      //We are done
      error = NO_ERROR;
   }
   else
   {
      //Create a new entry in the session cache
      session = tlsCreateSession(context->cache);

      //Valid entry?
      if(session != NULL)
      {
         //Save session ID
         error = tlsSaveSessionId(context, session);

         //Check status code
         if(error)
         {
            //Clean up side effects
            tlsFreeSessionState(session);
         }
      }
      else
      {
         //Report an error
         error = ERROR_OUT_OF_RESOURCES;
      }
   }

   //Release exclusive access to the session cache
   tlsUnlockCache(context->cache);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Remove current session from cache
 * @param[in] context TLS context
 * @return Error code
 **/

error_t tlsRemoveFromCache(TlsContext *context)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   uint_t i;
   TlsSessionState *session;

   //Check parameters
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether session caching is supported
   if(context->cache == NULL)
      return ERROR_FAILURE;

   //Ensure the session ID is valid
   if(context->sessionIdLen == 0)
      return NO_ERROR;

   //Acquire exclusive access to the session cache
   tlsLockCache(context->cache);

   //Search the cache for the specified session ID
   for(i = 0; i < context->cache->size; i++)
   {
      //Point to the current entry
      session = &context->cache->sessions[i];

      //Check whether the current identifier matches the specified session ID
      if(session->sessionIdLen == context->sessionIdLen &&
         osMemcmp(session->sessionId, context->sessionId, session->sessionIdLen) == 0)
      {
         //Drop current entry
         tlsFreeSessionState(session);
      }
   }

   //Release exclusive access to the session cache
   tlsUnlockCache(context->cache);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Properly dispose a session cache
 * @param[in] cache Pointer to the session cache to be released
 **/

void tlsFreeCache(TlsCache *cache)
{
   uint_t i;

   //Valid session cache?
   if(cache != NULL)
   {
      //Loop through the session cache
      for(i = 0; i < cache->size; i++)
      {
         //Release current entry
         tlsFreeSessionState(&cache->sessions[i]);
      }

      //Release mutex object
      osDeleteMutex(&cache->mutex);

      //Properly dispose the session cache
      tlsFreeMem(cache);
   }
}

#endif
