/**
 * @file tls.c
 * @brief TLS (Transport Layer Security)
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
 * @section Description
 *
 * The TLS protocol provides communications security over the Internet. The
 * protocol allows client/server applications to communicate in a way that
 * is designed to prevent eavesdropping, tampering, or message forgery
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 1.8.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include <string.h>
#include <ctype.h>
#include "tls.h"
#include "tls_handshake.h"
#include "tls_client.h"
#include "tls_server.h"
#include "tls_common.h"
#include "tls_record.h"
#include "tls_certificate.h"
#include "tls_misc.h"
#include "dtls_record.h"
#include "certificate/pem_import.h"
#include "certificate/x509_cert_parse.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief TLS context initialization
 * @return Handle referencing the fully initialized TLS context
 **/

TlsContext *tlsInit(void)
{
   TlsContext *context;

   //Allocate a memory buffer to hold the TLS context
   context = tlsAllocMem(sizeof(TlsContext));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Clear TLS context
      memset(context, 0, sizeof(TlsContext));

      //Default state
      context->state = TLS_STATE_INIT;
      //Default transport protocol
      context->transportProtocol = TLS_TRANSPORT_PROTOCOL_STREAM;
      //Default operation mode
      context->entity = TLS_CONNECTION_END_CLIENT;
      //Default client authentication mode
      context->clientAuthMode = TLS_CLIENT_AUTH_NONE;

      //Minimum version accepted by the implementation
      context->versionMin = TLS_MIN_VERSION;
      //Maximum version accepted by the implementation
      context->versionMax = TLS_MAX_VERSION;

      //Default record layer version number
      context->version = TLS_MIN_VERSION;
      context->encryptionEngine.version = TLS_MIN_VERSION;

#if (DTLS_SUPPORT == ENABLED)
      //Default PMTU
      context->pmtu = DTLS_DEFAULT_PMTU;
      //Default timeout
      context->timeout = INFINITE_DELAY;
#endif

#if (DTLS_SUPPORT == ENABLED && DTLS_REPLAY_DETECTION_SUPPORT == ENABLED)
      //Anti-replay mechanism is enabled by default
      context->replayDetectionEnabled = TRUE;
#endif

#if (TLS_DH_ANON_SUPPORT == ENABLED || TLS_DHE_RSA_SUPPORT == ENABLED || \
   TLS_DHE_DSS_SUPPORT == ENABLED || TLS_DHE_PSK_SUPPORT == ENABLED)
      //Initialize Diffie-Hellman context
      dhInit(&context->dhContext);
#endif

#if (TLS_ECDH_ANON_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
      //Initialize ECDH context
      ecdhInit(&context->ecdhContext);
#endif

#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_SUPPORT == ENABLED || \
   TLS_DHE_RSA_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_RSA_PSK_SUPPORT == ENABLED)
      //Initialize peer's RSA public key
      rsaInitPublicKey(&context->peerRsaPublicKey);
#endif

#if (TLS_DSA_SIGN_SUPPORT == ENABLED || TLS_DHE_DSS_SUPPORT == ENABLED)
      //Initialize peer's DSA public key
      dsaInitPublicKey(&context->peerDsaPublicKey);
#endif

#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED || TLS_ECDHE_ECDSA_SUPPORT == ENABLED)
      //Initialize peer's EC domain parameters
      ecInitDomainParameters(&context->peerEcParams);
      //Initialize peer's EC public key
      ecInit(&context->peerEcPublicKey);
#endif

      //Set the maximum fragment length
      context->maxFragLen = TLS_MAX_RECORD_LENGTH;
      //Maximum number of plaintext data the TX buffer can hold
      context->txBufferMaxLen = TLS_MAX_RECORD_LENGTH;

#if (DTLS_SUPPORT == ENABLED)
      //Calculate the required size for the TX buffer
      context->txBufferSize = TLS_MAX_RECORD_LENGTH + sizeof(DtlsRecord) +
         TLS_MAX_RECORD_OVERHEAD;

      //Calculate the required size for the RX buffer
      context->rxBufferSize = TLS_MAX_RECORD_LENGTH + sizeof(DtlsRecord) +
         TLS_MAX_RECORD_OVERHEAD;
#else
      //Calculate the required size for the TX buffer
      context->txBufferSize = TLS_MAX_RECORD_LENGTH + sizeof(TlsRecord) +
         TLS_MAX_RECORD_OVERHEAD;

      //Calculate the required size for the RX buffer
      context->rxBufferSize = TLS_MAX_RECORD_LENGTH + sizeof(TlsRecord) +
         TLS_MAX_RECORD_OVERHEAD;
#endif
   }

   //Return a pointer to the freshly created TLS context
   return context;
}


/**
 * @brief Set socket send and receive callbacks
 * @param[in] context Pointer to the TLS context
 * @param[in] socketSendCallback Send callback function
 * @param[in] socketReceiveCallback Receive callback function
 * @param[in] handle Socket handle
 * @return Error code
 **/

error_t tlsSetSocketCallbacks(TlsContext *context,
   TlsSocketSendCallback socketSendCallback,
   TlsSocketReceiveCallback socketReceiveCallback, TlsSocketHandle handle)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(socketSendCallback == NULL || socketReceiveCallback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save send and receive callback functions
   context->socketSendCallback = socketSendCallback;
   context->socketReceiveCallback = socketReceiveCallback;

   //This socket handle will be directly passed to the callback functions
   context->socketHandle = handle;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set minimum and maximum versions permitted
 * @param[in] context Pointer to the TLS context
 * @param[in] versionMin Minimum version accepted by the TLS implementation
 * @param[in] versionMax Maximum version accepted by the TLS implementation
 * @return Error code
 **/

error_t tlsSetVersion(TlsContext *context, uint16_t versionMin,
   uint16_t versionMax)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(versionMin < TLS_MIN_VERSION || versionMax > TLS_MAX_VERSION)
      return ERROR_INVALID_PARAMETER;
   if(versionMin > versionMax)
      return ERROR_INVALID_PARAMETER;

   //Minimum version accepted by the implementation
   context->versionMin = versionMin;
   //Maximum version accepted by the implementation
   context->versionMax = versionMax;

   //Default record layer version number
   context->version = context->versionMin;
   context->encryptionEngine.version = context->versionMin;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the transport protocol to be used
 * @param[in] context Pointer to the TLS context
 * @param[in] transportProtocol Transport protocol to be used
 * @return Error code
 **/

error_t tlsSetTransportProtocol(TlsContext *context,
   TlsTransportProtocol transportProtocol)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(transportProtocol != TLS_TRANSPORT_PROTOCOL_STREAM &&
      transportProtocol != TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Set transport protocol
   context->transportProtocol = transportProtocol;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set operation mode (client or server)
 * @param[in] context Pointer to the TLS context
 * @param[in] entity Specifies whether this entity is considered a client or a server
 * @return Error code
 **/

error_t tlsSetConnectionEnd(TlsContext *context, TlsConnectionEnd entity)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(entity != TLS_CONNECTION_END_CLIENT && entity != TLS_CONNECTION_END_SERVER)
      return ERROR_INVALID_PARAMETER;

   //Check whether TLS operates as a client or a server
   context->entity = entity;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the pseudo-random number generator to be used
 * @param[in] context Pointer to the TLS context
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t tlsSetPrng(TlsContext *context, const PrngAlgo *prngAlgo, void *prngContext)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(prngAlgo == NULL || prngContext == NULL)
      return ERROR_INVALID_PARAMETER;

   //PRNG algorithm that will be used to generate random numbers
   context->prngAlgo = prngAlgo;
   //PRNG context
   context->prngContext = prngContext;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the server name
 * @param[in] context Pointer to the TLS context
 * @param[in] serverName Fully qualified domain name of the server
 * @return Error code
 **/

error_t tlsSetServerName(TlsContext *context, const char_t *serverName)
{
   size_t i;
   size_t length;

   //Check parameters
   if(context == NULL || serverName == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the server name
   length = strlen(serverName);

   //Check whether the server name has already been configured
   if(context->serverName != NULL)
   {
      //Release memory
      tlsFreeMem(context->serverName);
      context->serverName = NULL;
   }

   //Valid server name?
   if(length > 0)
   {
      //Allocate a memory block to hold the hostname
      context->serverName = tlsAllocMem(length + 1);
      //Failed to allocate memory?
      if(context->serverName == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Convert the hostname into lowercase
      for(i = 0; i < length; i++)
         context->serverName[i] = tolower((uint8_t) serverName[i]);

      //Properly terminate the string with a NULL character
      context->serverName[length] = '\0';
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the server name
 * @param[in] context Pointer to the TLS context
 * @return Fully qualified domain name of the server
 **/

const char_t *tlsGetServerName(TlsContext *context)
{
   static const char_t defaultServerName[] = "";

   //Valid protocol name?
   if(context != NULL && context->serverName != NULL)
   {
      //Return the fully qualified domain name of the server
      return context->serverName;
   }
   else
   {
      //Return an empty string
      return defaultServerName;
   }
}


/**
 * @brief Set session cache
 * @param[in] context Pointer to the TLS context
 * @param[in] cache Session cache that will be used to save/resume TLS sessions
 * @return Error code
 **/

error_t tlsSetCache(TlsContext *context, TlsCache *cache)
{
   //Check parameters
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The cache will be used to save/resume TLS sessions
   context->cache = cache;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set client authentication mode (for servers only)
 * @param[in] context Pointer to the TLS context
 * @param[in] mode Client authentication mode
 * @return Error code
 **/

error_t tlsSetClientAuthMode(TlsContext *context, TlsClientAuthMode mode)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save client authentication mode
   context->clientAuthMode = mode;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set TLS buffer size
 * @param[in] context Pointer to the TLS context
 * @param[in] txBufferSize TX buffer size
 * @param[in] rxBufferSize RX buffer size
 * @return Error code
 **/

error_t tlsSetBufferSize(TlsContext *context,
   size_t txBufferSize, size_t rxBufferSize)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(txBufferSize < 512 || rxBufferSize < 512)
      return ERROR_INVALID_PARAMETER;

   //Maximum number of plaintext data the TX buffer can hold
   context->txBufferMaxLen = txBufferSize;

#if (DTLS_SUPPORT == ENABLED)
   //Calculate the required size for the TX buffer
   context->txBufferSize = txBufferSize + sizeof(DtlsRecord) +
      TLS_MAX_RECORD_OVERHEAD;

   //Calculate the required size for the RX buffer
   context->rxBufferSize = rxBufferSize + sizeof(DtlsRecord) +
      TLS_MAX_RECORD_OVERHEAD;
#else
   //Calculate the required size for the TX buffer
   context->txBufferSize = txBufferSize + sizeof(TlsRecord) +
      TLS_MAX_RECORD_OVERHEAD;

   //Calculate the required size for the RX buffer
   context->rxBufferSize = rxBufferSize + sizeof(TlsRecord) +
      TLS_MAX_RECORD_OVERHEAD;
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set maximum fragment length
 * @param[in] context Pointer to the TLS context
 * @param[in] maxFragLen Maximum fragment length
 * @return Error code
 **/

error_t tlsSetMaxFragmentLength(TlsContext *context, size_t maxFragLen)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the specified value is acceptable (ref to RFC 6066, section 4)
   if(maxFragLen != 512 && maxFragLen != 1024 &&
      maxFragLen != 2048 && maxFragLen != 4096 &&
      maxFragLen != 16384)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Set maximum fragment length
   context->maxFragLen = maxFragLen;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Specify the list of allowed cipher suites
 * @param[in] context Pointer to the TLS context
 * @param[in] cipherSuites Pointer to the cipher suite list
 * @param[in] length Number of cipher suites in the list
 * @return Error code
 **/

error_t tlsSetCipherSuites(TlsContext *context,
   const uint16_t *cipherSuites, uint_t length)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(cipherSuites == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   //Restrict the cipher suites that can be used
   context->cipherSuites = cipherSuites;
   context->numCipherSuites = length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Import Diffie-Hellman parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] params PEM structure that holds Diffie-Hellman parameters
 * @param[in] length Total length of the DER structure
 * @return Error code
 **/

error_t tlsSetDhParameters(TlsContext *context,
   const char_t *params, size_t length)
{
#if (TLS_DH_ANON_SUPPORT == ENABLED || TLS_DHE_RSA_SUPPORT == ENABLED || \
   TLS_DHE_DSS_SUPPORT == ENABLED || TLS_DHE_PSK_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(params == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   //Decode the PEM structure that holds Diffie-Hellman parameters
   return pemImportDhParameters(params, length, &context->dhContext.params);
#else
   //Diffie-Hellman is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register ECDH key agreement callback function
 * @param[in] context Pointer to the TLS context
 * @param[in] ecdhCallback ECDH callback function
 * @return Error code
 **/

error_t tlsSetEcdhCallback(TlsContext *context, TlsEcdhCallback ecdhCallback)
{
#if (TLS_ECC_CALLBACK_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || ecdhCallback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save the ECDH key agreement callback function
   context->ecdhCallback = ecdhCallback;

   //Successful processing
   return NO_ERROR;
#else
   //PSK key exchange is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ECDSA signature generation callback function
 * @param[in] context Pointer to the TLS context
 * @param[in] ecdsaSignCallback ECDSA signature generation callback function
 * @return Error code
 **/

error_t tlsSetEcdsaSignCallback(TlsContext *context,
   TlsEcdsaSignCallback ecdsaSignCallback)
{
#if (TLS_ECC_CALLBACK_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || ecdsaSignCallback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save the ECDSA signature generation callback function
   context->ecdsaSignCallback = ecdsaSignCallback;

   //Successful processing
   return NO_ERROR;
#else
   //PSK key exchange is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register ECDSA signature verification callback function
 * @param[in] context Pointer to the TLS context
 * @param[in] ecdsaVerifyCallback ECDSA signature verification callback function
 * @return Error code
 **/

error_t tlsSetEcdsaVerifyCallback(TlsContext *context,
   TlsEcdsaVerifyCallback ecdsaVerifyCallback)
{
#if (TLS_ECC_CALLBACK_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || ecdsaVerifyCallback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save the ECDSA signature verification callback function
   context->ecdsaVerifyCallback = ecdsaVerifyCallback;

   //Successful processing
   return NO_ERROR;
#else
   //PSK key exchange is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Allow unknown ALPN protocols
 * @param[in] context Pointer to the TLS context
 * @param[in] allowed Specifies whether unknown ALPN protocols are allowed
 * @return Error code
 **/

error_t tlsAllowUnknownAlpnProtocols(TlsContext *context, bool_t allowed)
{
#if (TLS_ALPN_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Allow or disallow unknown ALPN protocols
   context->unknownProtocolsAllowed = allowed;

   //Successful processing
   return NO_ERROR;
#else
   //ALPN is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set the list of supported ALPN protocols
 * @param[in] context Pointer to the TLS context
 * @param[in] protocolList Comma-delimited list of supported protocols
 * @return Error code
 **/

error_t tlsSetAlpnProtocolList(TlsContext *context, const char_t *protocolList)
{
#if (TLS_ALPN_SUPPORT == ENABLED)
   size_t length;

   //Check parameters
   if(context == NULL || protocolList == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the list
   length = strlen(protocolList);

   //Check whether the list of supported protocols has already been configured
   if(context->protocolList != NULL)
   {
      //Release memory
      tlsFreeMem(context->protocolList);
      context->protocolList = NULL;
   }

   //Check whether the list of protocols is valid
   if(length > 0)
   {
      //Allocate a memory block to hold the list
      context->protocolList = tlsAllocMem(length + 1);
      //Failed to allocate memory?
      if(context->protocolList == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Save the list of supported protocols
      strcpy(context->protocolList, protocolList);
   }

   //Successful processing
   return NO_ERROR;
#else
   //ALPN is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Get the name of the selected ALPN protocol
 * @param[in] context Pointer to the TLS context
 * @return Pointer to the protocol name
 **/

const char_t *tlsGetAlpnProtocol(TlsContext *context)
{
   static const char_t defaultProtocolName[] = "";

#if (TLS_ALPN_SUPPORT == ENABLED)
   //Valid protocol name?
   if(context != NULL && context->selectedProtocol != NULL)
   {
      //Return the name of the selected protocol
      return context->selectedProtocol;
   }
   else
#endif
   {
      //Return an empty string
      return defaultProtocolName;
   }
}


/**
 * @brief Set the pre-shared key to be used
 * @param[in] context Pointer to the TLS context
 * @param[in] psk Pointer to the pre-shared key
 * @param[in] length Length of the pre-shared key, in bytes
 * @return Error code
 **/

error_t tlsSetPsk(TlsContext *context, const uint8_t *psk, size_t length)
{
#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(psk == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   //Check whether the pre-shared key has already been configured
   if(context->psk != NULL)
   {
      //Release memory
      memset(context->psk, 0, context->pskLen);
      tlsFreeMem(context->psk);
      //Re-initialize length
      context->pskLen = 0;
   }

   //Valid PSK?
   if(length > 0)
   {
      //Allocate a memory block to hold the pre-shared key
      context->psk = tlsAllocMem(length);
      //Failed to allocate memory?
      if(context->psk == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Save the pre-shared key
      memcpy(context->psk, psk, length);
      //Save the length of the key
      context->pskLen = length;
   }

   //Successful processing
   return NO_ERROR;
#else
   //PSK key exchange is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set the PSK identity to be used by the client
 * @param[in] context Pointer to the TLS context
 * @param[in] pskIdentity NULL-terminated string that contains the PSK identity
 * @return Error code
 **/

error_t tlsSetPskIdentity(TlsContext *context, const char_t *pskIdentity)
{
#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   size_t length;

   //Check parameters
   if(context == NULL || pskIdentity == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the PSK identity
   length = strlen(pskIdentity);

   //Check whether the PSK identity has already been configured
   if(context->pskIdentity != NULL)
   {
      //Release memory
      tlsFreeMem(context->pskIdentity);
      context->pskIdentity = NULL;
   }

   //Valid PSK identity?
   if(length > 0)
   {
      //Allocate a memory block to hold the PSK identity
      context->pskIdentity = tlsAllocMem(length + 1);
      //Failed to allocate memory?
      if(context->pskIdentity == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Save the PSK identity
      strcpy(context->pskIdentity, pskIdentity);
   }

   //Successful processing
   return NO_ERROR;
#else
   //PSK key exchange is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set the PSK identity hint to be used by the server
 * @param[in] context Pointer to the TLS context
 * @param[in] pskIdentityHint NULL-terminated string that contains the PSK identity hint
 * @return Error code
 **/

error_t tlsSetPskIdentityHint(TlsContext *context, const char_t *pskIdentityHint)
{
#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   size_t length;

   //Check parameters
   if(context == NULL || pskIdentityHint == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the PSK identity hint
   length = strlen(pskIdentityHint);

   //Check whether the PSK identity hint has already been configured
   if(context->pskIdentityHint != NULL)
   {
      //Release memory
      tlsFreeMem(context->pskIdentityHint);
      context->pskIdentityHint = NULL;
   }

   //Valid PSK identity hint?
   if(length > 0)
   {
      //Allocate a memory block to hold the PSK identity hint
      context->pskIdentityHint = tlsAllocMem(length + 1);
      //Failed to allocate memory?
      if(context->pskIdentityHint == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Save the PSK identity hint
      strcpy(context->pskIdentityHint, pskIdentityHint);
   }

   //Successful processing
   return NO_ERROR;
#else
   //PSK key exchange is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register the PSK callback function
 * @param[in] context Pointer to the TLS context
 * @param[in] pskCallback PSK callback function
 * @return Error code
 **/

error_t tlsSetPskCallback(TlsContext *context, TlsPskCallback pskCallback)
{
#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || pskCallback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save the PSK callback function
   context->pskCallback = pskCallback;

   //Successful processing
   return NO_ERROR;
#else
   //PSK key exchange is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Import a trusted CA list
 * @param[in] context Pointer to the TLS context
 * @param[in] trustedCaList List of trusted CA (PEM format)
 * @param[in] length Total length of the list
 * @return Error code
 **/

error_t tlsSetTrustedCaList(TlsContext *context,
   const char_t *trustedCaList, size_t length)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(trustedCaList == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   //Save the list of trusted CA
   context->trustedCaList = trustedCaList;
   context->trustedCaListLen = length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Import a certificate and the corresponding private key
 * @param[in] context Pointer to the TLS context
 * @param[in] certChain Certificate chain (PEM format)
 * @param[in] certChainLen Total length of the certificate chain
 * @param[in] privateKey Private key (PEM format)
 * @param[in] privateKeyLen Total length of the private key
 * @return Error code
 **/

error_t tlsAddCertificate(TlsContext *context, const char_t *certChain,
   size_t certChainLen, const char_t *privateKey, size_t privateKeyLen)
{
   error_t error;
   const char_t *p;
   size_t n;
   uint8_t *derCert;
   size_t derCertSize;
   size_t derCertLen;
   X509CertificateInfo *certInfo;
   TlsCertificateType certType;
   TlsSignatureAlgo certSignAlgo;
   TlsHashAlgo certHashAlgo;
   TlsEcNamedCurve namedCurve;

   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether the certificate chain is valid
   if(certChain == NULL || certChainLen == 0)
      return ERROR_INVALID_PARAMETER;

   //The private key is optional
   if(privateKey == NULL && privateKeyLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Make sure there is enough room to add the certificate
   if(context->numCerts >= TLS_MAX_CERTIFICATES)
      return ERROR_OUT_OF_RESOURCES;

   //Allocate a memory buffer to store X.509 certificate info
   certInfo = tlsAllocMem(sizeof(X509CertificateInfo));
   //Failed to allocate memory?
   if(certInfo == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Point to the beginning of the certificate chain
   p = certChain;
   n = certChainLen;

   //DER encoded certificate
   derCert = NULL;
   derCertSize = 0;
   derCertLen = 0;

   //Start of exception handling block
   do
   {
      //Decode end entity certificate
      error = pemImportCertificate(&p, &n, &derCert, &derCertSize, &derCertLen);
      //Any error to report?
      if(error)
         break;

      //Parse X.509 certificate
      error = x509ParseCertificate(derCert, derCertLen, certInfo);
      //Failed to parse the X.509 certificate?
      if(error)
         break;

      //Retrieve the signature algorithm that has been used to sign the certificate
      error = tlsGetCertificateType(certInfo, &certType,
         &certSignAlgo, &certHashAlgo, &namedCurve);
      //The specified signature algorithm is not supported?
      if(error)
         break;

      //End of exception handling block
   } while(0);

   //Check whether the certificate is acceptable
   if(!error)
   {
      //Point to the structure that describes the certificate
      TlsCertDesc *cert = &context->certs[context->numCerts];

      //Save the certificate chain and the corresponding private key
      cert->certChain = certChain;
      cert->certChainLen = certChainLen;
      cert->privateKey = privateKey;
      cert->privateKeyLen = privateKeyLen;
      cert->type = certType;
      cert->signAlgo = certSignAlgo;
      cert->hashAlgo = certHashAlgo;
      cert->namedCurve = namedCurve;

      //Update the number of certificates
      context->numCerts++;
   }

   //Release previously allocated memory
   tlsFreeMem(derCert);
   tlsFreeMem(certInfo);

   //Return status code
   return error;
}


/**
 * @brief Enable secure renegotiation
 * @param[in] context Pointer to the TLS context
 * @param[in] enabled Specifies whether secure renegotiation is allowed
 * @return Error code
 **/

error_t tlsEnableSecureRenegotiation(TlsContext *context, bool_t enabled)
{
#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Enable or disable secure renegotiation
   context->secureRenegoEnabled = enabled;

   //Successful processing
   return NO_ERROR;
#else
   //Secure renegotiation is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Perform fallback retry (for clients only)
 * @param[in] context Pointer to the TLS context
 * @param[in] enabled Specifies whether FALLBACK_SCSV is enabled
 * @return Error code
 **/

error_t tlsEnableFallbackScsv(TlsContext *context, bool_t enabled)
{
#if (TLS_FALLBACK_SCSV_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Enable or disable support for FALLBACK_SCSV
   context->fallbackScsvEnabled = enabled;

   //Successful processing
   return NO_ERROR;
#else
    //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set PMTU value (for DTLS only)
 * @param[in] context Pointer to the TLS context
 * @param[in] pmtu PMTU value
 * @return Error code
 **/

error_t tlsSetPmtu(TlsContext *context, size_t pmtu)
{
#if (DTLS_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the PMTU value is acceptable
   if(pmtu < DTLS_MIN_PMTU)
      return ERROR_INVALID_PARAMETER;

   //Save PMTU value
   context->pmtu = pmtu;

   //Successful processing
   return NO_ERROR;
#else
   //DTLS is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set timeout for blocking calls (for DTLS only)
 * @param[in] context Pointer to the TLS context
 * @param[in] timeout Maximum time to wait
 * @return Error code
 **/

error_t tlsSetTimeout(TlsContext *context, systime_t timeout)
{
#if (DTLS_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save timeout value
   context->timeout = timeout;

   //Successful processing
   return NO_ERROR;
#else
   //DTLS is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set cookie generation/verification callbacks (for DTLS only)
 * @param[in] context Pointer to the TLS context
 * @param[in] cookieGenerateCallback Cookie generation callback function
 * @param[in] cookieVerifyCallback Cookie verification callback function
 * @param[in] handle An opaque pointer passed to the callback functions
 * @return Error code
 **/

error_t tlsSetCookieCallbacks(TlsContext *context,
   DtlsCookieGenerateCallback cookieGenerateCallback,
   DtlsCookieVerifyCallback cookieVerifyCallback, DtlsCookieHandle handle)
{
#if (DTLS_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(cookieGenerateCallback == NULL || cookieVerifyCallback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save cookie generation/verification callback functions
   context->cookieGenerateCallback = cookieGenerateCallback;
   context->cookieVerifyCallback = cookieVerifyCallback;

   //This opaque pointer will be directly passed to the callback functions
   context->cookieHandle = handle;

   //Successful processing
   return NO_ERROR;
#else
   //DTLS is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Enable anti-replay mechanism (for DTLS only)
 * @param[in] context Pointer to the TLS context
 * @param[in] enabled Specifies whether anti-replay protection is enabled
 * @return Error code
 **/

error_t tlsEnableReplayDetection(TlsContext *context, bool_t enabled)
{
#if (DTLS_SUPPORT == ENABLED && DTLS_REPLAY_DETECTION_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Enable or disable anti-replay mechanism
   context->replayDetectionEnabled = enabled;

   //Successful processing
   return NO_ERROR;
#else
   //Anti-replay mechanism is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

/**
 * @brief Initiate the TLS handshake
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsConnect(TlsContext *context)
{
   error_t error;

   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Ensure the send/receive functions are properly registered
   if(context->socketSendCallback == NULL || context->socketReceiveCallback == NULL)
      return ERROR_NOT_CONFIGURED;

   //Verify that the PRNG is properly set
   if(context->prngAlgo == NULL || context->prngContext == NULL)
      return ERROR_NOT_CONFIGURED;

#if (DTLS_SUPPORT == ENABLED)
   //Save current time
   context->startTime = osGetSystemTime();
#endif

   //Check current state
   if(context->state == TLS_STATE_INIT)
   {
      //Allocate send buffer if necessary
      if(context->txBuffer == NULL)
      {
         //Allocate TX buffer
         context->txBuffer = tlsAllocMem(context->txBufferSize);

         //Failed to allocate memory?
         if(context->txBuffer == NULL)
            return ERROR_OUT_OF_MEMORY;

         //Clear TX buffer
         memset(context->txBuffer, 0, context->txBufferSize);
      }

      //Allocate receive buffer if necessary
      if(context->rxBuffer == NULL)
      {
         //Allocate RX buffer
         context->rxBuffer = tlsAllocMem(context->rxBufferSize);

         //Failed to allocate memory?
         if(context->rxBuffer == NULL)
         {
            //Clean up side effects
            tlsFreeMem(context->txBuffer);
            context->txBuffer = NULL;
            //Report an error
            return ERROR_OUT_OF_MEMORY;
         }

         //Clear RX buffer
         memset(context->rxBuffer, 0, context->rxBufferSize);
      }
   }

   //Perform TLS handshake
   error = tlsHandshake(context);
   //Return status code
   return error;
}


/**
 * @brief Send application data to the remote host using TLS
 * @param[in] context Pointer to the TLS context
 * @param[in] data Pointer to a buffer containing the data to be transmitted
 * @param[in] length Number of bytes to be transmitted
 * @param[out] written Actual number of bytes written (optional parameter)
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return Error code
 **/

error_t tlsWrite(TlsContext *context, const void *data,
   size_t length, size_t *written, uint_t flags)
{
   error_t error;
   size_t n;
   size_t totalLength;

   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(data == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   //Ensure the send/receive functions are properly registered
   if(context->socketSendCallback == NULL || context->socketReceiveCallback == NULL)
      return ERROR_NOT_CONFIGURED;

#if (DTLS_SUPPORT == ENABLED)
   //Save current time
   context->startTime = osGetSystemTime();
#endif

   //Initialize status code
   error = NO_ERROR;

   //Actual number of bytes written
   totalLength = 0;

   //Send as much data as possible
   while(totalLength < length)
   {
      //Check current state
      if(context->state < TLS_STATE_APPLICATION_DATA)
      {
         //Perform TLS handshake
         error = tlsConnect(context);
      }
      else if(context->state == TLS_STATE_APPLICATION_DATA)
      {
#if (DTLS_SUPPORT == ENABLED)
         //DTLS protocol?
         if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
         {
            //Length of the payload data
            n = length;

            //Send a datagram
            error = dtlsWriteProtocolData(context, data, n,
               TLS_TYPE_APPLICATION_DATA);
         }
         else
#endif
         //TLS protocol?
         {
            //Calculate the number of bytes to write at a time
            n = MIN(length - totalLength, context->txBufferMaxLen);

            //The record length must not exceed 16384 bytes
            n = MIN(n, TLS_MAX_RECORD_LENGTH);
            //Do not exceed the negotiated maximum fragment length
            n = MIN(n, context->maxFragLen);

            //Send application data
            error = tlsWriteProtocolData(context, data, n,
               TLS_TYPE_APPLICATION_DATA);
         }

         //Check status code
         if(!error)
         {
            //Advance data pointer
            data = (uint8_t *) data + n;
            //Update byte counter
            totalLength += n;
         }
         else
         {
            //Send an alert message to the peer, if applicable
            tlsProcessError(context, error);
         }
      }
      else
      {
         //The connection has not yet been established
         error = ERROR_NOT_CONNECTED;
      }

      //Any error to report?
      if(error)
         break;
   }

   //Total number of data that have been written
   if(written != NULL)
      *written = totalLength;

   //Return status code
   return error;
}


/**
 * @brief Receive application data from a the remote host using TLS
 * @param[in] context Pointer to the TLS context
 * @param[out] data Buffer into which received data will be placed
 * @param[in] size Maximum number of bytes that can be received
 * @param[out] received Number of bytes that have been received
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return Error code
 **/

error_t tlsRead(TlsContext *context, void *data,
   size_t size, size_t *received, uint_t flags)
{
   error_t error;
   size_t i;
   size_t n;
   uint8_t *p;
   TlsContentType contentType;

   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(data == NULL || received == NULL)
      return ERROR_INVALID_PARAMETER;

   //Ensure the send/receive functions are properly registered
   if(context->socketSendCallback == NULL || context->socketReceiveCallback == NULL)
      return ERROR_NOT_CONFIGURED;

#if (DTLS_SUPPORT == ENABLED)
   //Save current time
   context->startTime = osGetSystemTime();
#endif

   //Initialize status code
   error = NO_ERROR;

   //No data has been read yet
   *received = 0;

   //Read as much data as possible
   while(*received < size)
   {
      //Check current state
      if(context->state < TLS_STATE_APPLICATION_DATA)
      {
         //Perform TLS handshake
         error = tlsConnect(context);
      }
      else if(context->state == TLS_STATE_APPLICATION_DATA)
      {
#if (DTLS_SUPPORT == ENABLED)
         //DTLS protocol?
         if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
         {
            //Receive a datagram
            error = dtlsReadProtocolData(context, &p, &n, &contentType);
         }
         else
#endif
         //TLS protocol?
         {
            //The record layer receives uninterpreted data from higher layers
            error = tlsReadProtocolData(context, &p, &n, &contentType);
         }

         //Check status code
         if(!error)
         {
            //Application data received?
            if(contentType == TLS_TYPE_APPLICATION_DATA)
            {
#if (DTLS_SUPPORT == ENABLED)
               //DTLS protocol?
               if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
               {
                  //Make sure the user buffer is large enough to hold the whole
                  //datagram
                  if(n > size)
                  {
                     //Report an error
                     error = ERROR_BUFFER_OVERFLOW;
                  }
                  else
                  {
                     //Copy data to user buffer
                     memcpy(data, p, n);
                     //Total number of data that have been read
                     *received = n;
                  }

                  //If the TLS_FLAG_PEEK flag is set, the data is copied into
                  //the buffer but is not removed from the receive queue
                  if(!(flags & TLS_FLAG_PEEK))
                  {
                     //Flush receive buffer
                     context->rxBufferPos = 0;
                     context->rxBufferLen = 0;
                  }

                  //We are done
                  break;
               }
               else
#endif
               //TLS protocol?
               {
                  //Limit the number of bytes to read at a time
                  n = MIN(n, size - *received);

                  //The TLS_FLAG_BREAK_CHAR flag causes the function to stop reading
                  //data as soon as the specified break character is encountered
                  if(flags & TLS_FLAG_BREAK_CHAR)
                  {
                     //Retrieve the break character code
                     char_t c = LSB(flags);

                     //Search for the specified break character
                     for(i = 0; i < n && p[i] != c; i++);
                     //Adjust the number of data to read
                     n = MIN(n, i + 1);

                     //Copy data to user buffer
                     memcpy(data, p, n);
                     //Total number of data that have been read
                     *received += n;

                     //Advance data pointer
                     context->rxBufferPos += n;
                     //Number of bytes still pending in the receive buffer
                     context->rxBufferLen -= n;

                     //Check whether a break character has been found
                     if(n > 0 && p[n - 1] == c)
                        break;
                  }
                  else
                  {
                     //Copy data to user buffer
                     memcpy(data, p, n);
                     //Total number of data that have been read
                     *received += n;

                     //Advance data pointer
                     context->rxBufferPos += n;
                     //Number of bytes still pending in the receive buffer
                     context->rxBufferLen -= n;

                     //The TLS_FLAG_WAIT_ALL flag causes the function to return
                     //only when the requested number of bytes have been read
                     if(!(flags & TLS_FLAG_WAIT_ALL))
                        break;
                  }

                  //Advance data pointer
                  data = (uint8_t *) data + n;
               }
            }
            //Handshake message received?
            else if(contentType == TLS_TYPE_HANDSHAKE)
            {
#if (TLS_CLIENT_SUPPORT == ENABLED)
               //TLS operates as a client?
               if(context->entity == TLS_CONNECTION_END_CLIENT)
               {
                  //Parse incoming handshake message
                  error = tlsParseServerMessage(context);
               }
               else
#endif
#if (TLS_SERVER_SUPPORT == ENABLED)
               //TLS operates as a server?
               if(context->entity == TLS_CONNECTION_END_SERVER)
               {
                  //Parse incoming handshake message
                  error = tlsParseClientMessage(context);
               }
               else
#endif
               //Unsupported mode of operation?
               {
                  //Report an error
                  error = ERROR_FAILURE;
               }
            }
            //Alert message received?
            else if(contentType == TLS_TYPE_ALERT)
            {
               //Parse Alert message
               error = tlsParseAlert(context, (TlsAlert *) p, n);

               //Advance data pointer
               context->rxBufferPos += n;
               //Number of bytes still pending in the receive buffer
               context->rxBufferLen -= n;
            }
            //An inappropriate message was received?
            else
            {
               //Report an error
               error = ERROR_UNEXPECTED_MESSAGE;
            }
         }

         //Any error to report?
         if(error)
         {
            //Send an alert message to the peer, if applicable
            tlsProcessError(context, error);
         }
      }
      else if(context->state == TLS_STATE_CLOSING ||
         context->state == TLS_STATE_CLOSED)
      {
         //Check whether a fatal alert message has been sent or received
         if(context->fatalAlertSent || context->fatalAlertReceived)
         {
            //Alert messages with a level of fatal result in the immediate
            //termination of the connection
            error = ERROR_FAILURE;
         }
         else
         {
            //The user must be satisfied with data already on hand
            if(*received > 0)
            {
               //Some data are pending in the receive buffer
               error = NO_ERROR;
               break;
            }
            else
            {
               //The receive buffer is empty
               error = ERROR_END_OF_STREAM;
            }
         }
      }
      else
      {
         //The connection has not yet been established
         error = ERROR_NOT_CONNECTED;
      }

      //Any error to report?
      if(error)
         break;
   }

   //Return status code
   return error;
}


/**
 * @brief Gracefully close TLS session
 * @param[in] context Pointer to the TLS context
 **/

error_t tlsShutdown(TlsContext *context)
{
   //Either party may initiate a close by sending a close_notify alert
   return tlsShutdownEx(context, FALSE);
}


/**
 * @brief Gracefully close TLS session
 * @param[in] context Pointer to the TLS context
 * @param[in] waitForCloseNotify Wait for the close notify alert from the peer
 **/

error_t tlsShutdownEx(TlsContext *context, bool_t waitForCloseNotify)
{
   error_t error;
   size_t n;
   uint8_t *p;
   TlsContentType contentType;

   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Ensure the send/receive functions are properly registered
   if(context->socketSendCallback == NULL || context->socketReceiveCallback == NULL)
      return ERROR_NOT_CONFIGURED;

#if (DTLS_SUPPORT == ENABLED)
   //Save current time
   context->startTime = osGetSystemTime();
#endif

   //Initialize status code
   error = NO_ERROR;

   //Wait for the TLS session to be closed
   while(context->state != TLS_STATE_CLOSED)
   {
      //Check current state
      if(context->state == TLS_STATE_APPLICATION_DATA)
      {
         //TLS protocol?
         if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
         {
            //Flush send buffer
            error = tlsWriteProtocolData(context, NULL, 0, TLS_TYPE_NONE);
         }

         //Check status code
         if(!error)
         {
            //Either party may initiate a close by sending a close_notify alert
            context->state = TLS_STATE_CLOSING;
         }
      }
      else if(context->state == TLS_STATE_CLOSING)
      {
         //TLS protocol?
         if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
         {
            //Flush send buffer
            error = tlsWriteProtocolData(context, NULL, 0, TLS_TYPE_NONE);
         }

         //Check status code
         if(!error)
         {
            //Unless some other fatal alert has been transmitted, each party
            //is required to send a close_notify alert before closing the
            //write side of the connection
            if(context->fatalAlertSent || context->fatalAlertReceived)
            {
               //Close the connection immediately
               context->state = TLS_STATE_CLOSED;
            }
            else if(!context->closeNotifySent)
            {
               //Notifies the recipient that the sender will not send any
               //more messages on this connection
               error = tlsSendAlert(context, TLS_ALERT_LEVEL_WARNING,
                  TLS_ALERT_CLOSE_NOTIFY);
            }
            else if(!context->closeNotifyReceived && waitForCloseNotify)
            {
#if (DTLS_SUPPORT == ENABLED)
               //DTLS protocol?
               if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
               {
                  //Wait for the responding close_notify alert
                  error = dtlsReadProtocolData(context, &p, &n, &contentType);
               }
               else
#endif
               //TLS protocol?
               {
                  //Wait for the responding close_notify alert
                  error = tlsReadProtocolData(context, &p, &n, &contentType);
               }

               //Check status code
               if(!error)
               {
                  //Application data received?
                  if(contentType == TLS_TYPE_APPLICATION_DATA)
                  {
                     //Advance data pointer
                     context->rxBufferPos += n;
                     //Number of bytes still pending in the receive buffer
                     context->rxBufferLen -= n;
                  }
                  //Alert message received?
                  else if(contentType == TLS_TYPE_ALERT)
                  {
                     //Parse Alert message
                     error = tlsParseAlert(context, (TlsAlert *) p, n);

                     //Advance data pointer
                     context->rxBufferPos += n;
                     //Number of bytes still pending in the receive buffer
                     context->rxBufferLen -= n;
                  }
                  //An inappropriate message was received?
                  else
                  {
                     //Report an error
                     error = ERROR_UNEXPECTED_MESSAGE;
                  }
               }
            }
            else
            {
               //The connection is closed
               context->state = TLS_STATE_CLOSED;
            }
         }
      }
      else
      {
         //Report an error
         error = ERROR_NOT_CONNECTED;
      }

      //Any error to report?
      if(error)
         break;
   }

   //Return status code
   return error;
}


/**
 * @brief Release TLS context
 * @param[in] context Pointer to the TLS context
 **/

void tlsFree(TlsContext *context)
{
   //Valid TLS context?
   if(context != NULL)
   {
      //Release server name
      if(context->serverName != NULL)
      {
         tlsFreeMem(context->serverName);
      }

      //Release send buffer
      if(context->txBuffer != NULL)
      {
         memset(context->txBuffer, 0, context->txBufferSize);
         tlsFreeMem(context->txBuffer);
      }

      //Release receive buffer
      if(context->rxBuffer != NULL)
      {
         memset(context->rxBuffer, 0, context->rxBufferSize);
         tlsFreeMem(context->rxBuffer);
      }

      //Release the SHA-1 context used to compute verify data
      if(context->handshakeSha1Context != NULL)
      {
         memset(context->handshakeSha1Context, 0, sizeof(Sha1Context));
         tlsFreeMem(context->handshakeSha1Context);
      }

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
      //Release the MD5 context used to compute verify data
      if(context->handshakeMd5Context != NULL)
      {
         memset(context->handshakeMd5Context, 0, sizeof(Md5Context));
         tlsFreeMem(context->handshakeMd5Context);
      }
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
      //Release the hash context used to compute verify data (TLS 1.2)
      if(context->handshakeHashContext != NULL)
      {
         tlsFreeMem(context->handshakeHashContext);
      }
#endif

#if (TLS_DH_ANON_SUPPORT == ENABLED || TLS_DHE_RSA_SUPPORT == ENABLED || \
   TLS_DHE_DSS_SUPPORT == ENABLED || TLS_DHE_PSK_SUPPORT == ENABLED)
      //Release Diffie-Hellman context
      dhFree(&context->dhContext);
#endif

#if (TLS_ECDH_ANON_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
      //Release ECDH context
      ecdhFree(&context->ecdhContext);
#endif

#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_SUPPORT == ENABLED || \
   TLS_DHE_RSA_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_RSA_PSK_SUPPORT == ENABLED)
      //Release peer's RSA public key
      rsaFreePublicKey(&context->peerRsaPublicKey);
#endif

#if (TLS_DSA_SIGN_SUPPORT == ENABLED || TLS_DHE_DSS_SUPPORT == ENABLED)
      //Release peer's DSA public key
      dsaFreePublicKey(&context->peerDsaPublicKey);
#endif

#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED || TLS_ECDHE_ECDSA_SUPPORT == ENABLED)
      //Release peer's EC domain parameters
      ecFreeDomainParameters(&context->peerEcParams);
      //Release peer's EC public key
      ecFree(&context->peerEcPublicKey);
#endif

#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
      //Release the pre-shared key
      if(context->psk != NULL)
      {
         memset(context->psk, 0, context->pskLen);
         tlsFreeMem(context->psk);
      }

      //Release the PSK identity
      if(context->pskIdentity != NULL)
      {
         tlsFreeMem(context->pskIdentity);
      }

      //Release the PSK identity hint
      if(context->pskIdentityHint != NULL)
      {
         tlsFreeMem(context->pskIdentityHint);
      }
#endif

#if (TLS_ALPN_SUPPORT == ENABLED)
      //Release the list of supported protocols
      if(context->protocolList != NULL)
      {
         tlsFreeMem(context->protocolList);
      }

      //Release the selected protocol name
      if(context->selectedProtocol != NULL)
      {
         tlsFreeMem(context->selectedProtocol);
      }
#endif

      //Release encryption engine
      tlsFreeEncryptionEngine(&context->encryptionEngine);
      //Release decryption engine
      tlsFreeEncryptionEngine(&context->decryptionEngine);

#if (DTLS_SUPPORT == ENABLED)
      //Release previous encryption engine
      tlsFreeEncryptionEngine(&context->prevEncryptionEngine);
#endif

      //Clear the TLS context before freeing memory
      memset(context, 0, sizeof(TlsContext));
      tlsFreeMem(context);
   }
}


/**
 * @brief Save TLS session
 * @param[in] context Pointer to the TLS context
 * @param[out] session Buffer where to store the current session parameters
 * @return Error code
 **/

error_t tlsSaveSession(const TlsContext *context, TlsSession *session)
{
   //Check parameters
   if(context == NULL || session == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid session parameters?
   if(context->sessionIdLen == 0 || context->cipherSuite.identifier == 0)
      return ERROR_FAILURE;

   //Save session identifier
   memcpy(session->id, context->sessionId, context->sessionIdLen);
   session->idLength = context->sessionIdLen;

   //Get current time
   session->timestamp = osGetSystemTime();

   //Save session parameters
   session->version = context->version;
   session->cipherSuite = context->cipherSuite.identifier;
   session->compressMethod = context->compressMethod;

   //Save master secret
   memcpy(session->masterSecret, context->masterSecret,
      TLS_MASTER_SECRET_SIZE);

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //Extended master secret computation
   session->extendedMasterSecret = context->extendedMasterSecretExtReceived;
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Restore TLS session
 * @param[in] context Pointer to the TLS context
 * @param[in] session Pointer to the session to be restored
 * @return Error code
 **/

error_t tlsRestoreSession(TlsContext *context, const TlsSession *session)
{
   //Check parameters
   if(context == NULL || session == NULL)
      return ERROR_INVALID_PARAMETER;

   //Restore session identifier
   memcpy(context->sessionId, session->id, session->idLength);
   context->sessionIdLen = session->idLength;

   //Restore session parameters
   context->version = session->version;
   context->cipherSuite.identifier = session->cipherSuite;
   context->compressMethod = session->compressMethod;

   //Restore master secret
   memcpy(context->masterSecret, session->masterSecret,
      TLS_MASTER_SECRET_SIZE);

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //Extended master secret computation
   context->extendedMasterSecretExtReceived = session->extendedMasterSecret;
#endif

   //Successful processing
   return NO_ERROR;
}

#endif
