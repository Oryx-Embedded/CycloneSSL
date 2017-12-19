/**
 * @file tls_server.c
 * @brief Handshake message processing (TLS server)
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
#include "tls.h"
#include "tls_cipher_suites.h"
#include "tls_handshake_hash.h"
#include "tls_handshake_misc.h"
#include "tls_server.h"
#include "tls_server_misc.h"
#include "tls_common.h"
#include "tls_record.h"
#include "tls_signature.h"
#include "tls_certificate.h"
#include "tls_key_material.h"
#include "tls_cache.h"
#include "tls_misc.h"
#include "dtls_record.h"
#include "dtls_misc.h"
#include "certificate/pem_import.h"
#include "certificate/x509_cert_parse.h"
#include "date_time.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED && TLS_SERVER_SUPPORT == ENABLED)


/**
 * @brief Send ServerHello message
 *
 * The server will send this message in response to a ClientHello
 * message when it was able to find an acceptable set of algorithms.
 * If it cannot find such a match, it will respond with a handshake
 * failure alert
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendServerHello(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsServerHello *message;

   //Point to the buffer where to format the message
   message = (TlsServerHello *) (context->txBuffer + context->txBufferLen);

   //Generate the server random value using a cryptographically-safe
   //pseudorandom number generator
   error = tlsGenerateRandomValue(context, &context->serverRandom);

   //Check status code
   if(!error)
   {
      //Format ServerHello message
      error = tlsFormatServerHello(context, message, &length);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending ServerHello message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsSendHandshakeMessage(context, message, length,
         TLS_TYPE_SERVER_HELLO);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
#if (TLS_SESSION_RESUME_SUPPORT == ENABLED)
      //Use abbreviated handshake?
      if(context->resume)
      {
         //Derive session keys from the master secret
         error = tlsGenerateSessionKeys(context);

         //Key material successfully generated?
         if(!error)
         {
            //At this point, both client and server must send ChangeCipherSpec
            //messages and proceed directly to Finished messages
            context->state = TLS_STATE_SERVER_CHANGE_CIPHER_SPEC;
         }
      }
      else
#endif
      {
         //Perform a full handshake
         context->state = TLS_STATE_SERVER_CERTIFICATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send ServerKeyExchange message
 *
 * The ServerKeyExchange message is sent by the server only when the
 * server Certificate message does not contain enough data to allow
 * the client to exchange a premaster secret
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendServerKeyExchange(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsServerKeyExchange *message;

   //Initialize status code
   error = NO_ERROR;

   //Point to the buffer where to format the message
   message = (TlsServerKeyExchange *) (context->txBuffer + context->txBufferLen);
   //Initialize length
   length = 0;

   //The ServerKeyExchange message is sent by the server only when the server
   //Certificate message (if sent) does not contain enough data to allow the
   //client to exchange a premaster secret
   if(context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //Format ServerKeyExchange message
      error = tlsFormatServerKeyExchange(context, message, &length);
   }
   else if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
   {
#if (TLS_PSK_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED || \
   TLS_DHE_PSK_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
      //If no PSK identity hint is provided by the server, the
      //ServerKeyExchange message is omitted...
      if(context->pskIdentityHint != NULL)
      {
         //Format ServerKeyExchange message
         error = tlsFormatServerKeyExchange(context, message, &length);
      }
#endif
   }

   //Check status code
   if(!error)
   {
      //Any message to send?
      if(length > 0)
      {
         //Debug message
         TRACE_INFO("Sending ServerKeyExchange message (%" PRIuSIZE " bytes)...\r\n", length);
         TRACE_DEBUG_ARRAY("  ", message, length);

         //Send handshake message
         error = tlsSendHandshakeMessage(context, message, length,
            TLS_TYPE_SERVER_KEY_EXCHANGE);
      }
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Prepare to send a CertificateRequest message...
      context->state = TLS_STATE_CERTIFICATE_REQUEST;
   }

   //Return status code
   return error;
}


/**
 * @brief Send CertificateRequest message
 *
 * A server can optionally request a certificate from the client, if
 * appropriate for the selected cipher suite. This message will
 * immediately follow the ServerKeyExchange message
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendCertificateRequest(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsCertificateRequest *message;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_DSA_SIGN_SUPPORT == ENABLED || TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   //A server can optionally request a certificate from the client
   if(context->clientAuthMode != TLS_CLIENT_AUTH_NONE)
   {
      //Non-anonymous key exchange?
      if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
         context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
      {
         //Point to the buffer where to format the message
         message = (TlsCertificateRequest *) (context->txBuffer + context->txBufferLen);

         //Format CertificateRequest message
         error = tlsFormatCertificateRequest(context, message, &length);

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_INFO("Sending CertificateRequest message (%" PRIuSIZE " bytes)...\r\n", length);
            TRACE_DEBUG_ARRAY("  ", message, length);

            //Send handshake message
            error = tlsSendHandshakeMessage(context, message, length,
               TLS_TYPE_CERTIFICATE_REQUEST);
         }
      }
   }
#endif

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Prepare to send a ServerHelloDone message...
      context->state = TLS_STATE_SERVER_HELLO_DONE;
   }

   //Return status code
   return error;
}


/**
 * @brief Send ServerHelloDone message
 *
 * The ServerHelloDone message is sent by the server to indicate the
 * end of the ServerHello and associated messages. After sending this
 * message, the server will wait for a client response
 *
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsSendServerHelloDone(TlsContext *context)
{
   error_t error;
   size_t length;
   TlsServerHelloDone *message;

   //Point to the buffer where to format the message
   message = (TlsServerHelloDone *) (context->txBuffer + context->txBufferLen);

   //Format ServerHelloDone message
   error = tlsFormatServerHelloDone(context, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending ServerHelloDone message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_DEBUG_ARRAY("  ", message, length);

      //Send handshake message
      error = tlsSendHandshakeMessage(context, message, length,
         TLS_TYPE_SERVER_HELLO_DONE);
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //The client must send a Certificate message if the server requests it
      if(context->clientAuthMode != TLS_CLIENT_AUTH_NONE)
         context->state = TLS_STATE_CLIENT_CERTIFICATE;
      else
         context->state = TLS_STATE_CLIENT_KEY_EXCHANGE;
   }

   //Return status code
   return error;
}


/**
 * @brief Format ServerHello message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the ServerHello message
 * @param[out] length Length of the resulting ServerHello message
 * @return Error code
 **/

error_t tlsFormatServerHello(TlsContext *context,
   TlsServerHello *message, size_t *length)
{
   error_t error;
   uint16_t version;
   size_t n;
   uint8_t *p;
   TlsExtensionList *extensionList;

   //Retrieve the TLS version that has been negotiated
   version = context->version;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Get the corresponding DTLS version
      version = dtlsTranslateVersion(version);
   }
#endif

   //This field contains the lower of the version suggested by the client
   //in the ClientHello and the highest supported by the server
   message->serverVersion = htons(version);

   //Server random value
   message->random = context->serverRandom;

   //Point to the session ID
   p = message->sessionId;
   //Length of the handshake message
   *length = sizeof(TlsServerHello);

#if (TLS_SESSION_RESUME_SUPPORT == ENABLED)
   //The SessionID uniquely identifies the current session
   message->sessionIdLen = (uint8_t)context->sessionIdLen;
   memcpy(message->sessionId, context->sessionId, context->sessionIdLen);
#else
   //The server may return an empty session ID to indicate that the session
   //will not be cached and therefore cannot be resumed
   message->sessionIdLen = 0;
#endif

   //Debug message
   TRACE_INFO("Session ID (%" PRIu8 " bytes):\r\n", message->sessionIdLen);
   TRACE_INFO_ARRAY("  ", message->sessionId, message->sessionIdLen);

   //Advance data pointer
   p += message->sessionIdLen;
   //Adjust the length of the message
   *length += message->sessionIdLen;

   //The single cipher suite selected by the server
   STORE16BE(context->cipherSuite.identifier, p);
   //Advance data pointer
   p += sizeof(TlsCipherSuite);
   //Adjust the length of the message
   *length += sizeof(TlsCipherSuite);

   //The single compression algorithm selected by the server
   *p = context->compressMethod;
   //Advance data pointer
   p += sizeof(TlsCompressMethod);
   //Adjust the length of the message
   *length += sizeof(TlsCompressMethod);

   //Only extensions offered by the client can appear in the server's list
   extensionList = (TlsExtensionList *) p;
   //Total length of the extension list
   extensionList->length = 0;

   //Point to the first extension of the list
   p += sizeof(TlsExtensionList);

#if (TLS_SNI_SUPPORT == ENABLED)
   //The server may include a SNI extension in the ServerHello
   error = tlsFormatServerSniExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;
#endif

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   //Servers that receive an ClientHello containing a MaxFragmentLength
   //extension may accept the requested maximum fragment length by including
   //an extension of type MaxFragmentLength in the ServerHello
   error = tlsFormatServerMaxFragLenExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;
#endif

   //A server that selects an ECC cipher suite in response to a ClientHello
   //message including an EcPointFormats extension appends this extension
   //to its ServerHello message
   error = tlsFormatServerEcPointFormatsExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;

#if (TLS_ALPN_SUPPORT == ENABLED)
   //The ALPN extension contains the name of the selected protocol
   error = tlsFormatServerAlpnExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;
#endif

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //If a server implementing RFC 7627 receives the ExtendedMasterSecret
   //extension, it must include the extension in its ServerHello message
   error = tlsFormatServerEmsExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;
#endif

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //During secure renegotiation, the server must include a renegotiation_info
   //extension containing the saved client_verify_data and server_verify_data
   error = tlsFormatServerRenegoInfoExtension(context, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Fix the length of the extension list
   extensionList->length += (uint16_t) n;
   //Point to the next field
   p += n;
   //Adjust the length of the message
   *length += n;
#endif

   //Any extensions included in the ServerHello message?
   if(extensionList->length > 0)
   {
      //Convert the length of the extension list to network byte order
      extensionList->length = htons(extensionList->length);
      //Total length of the message
      *length += sizeof(TlsExtensionList);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format ServerKeyExchange message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the ServerKeyExchange message
 * @param[out] length Length of the resulting ServerKeyExchange message
 * @return Error code
 **/

error_t tlsFormatServerKeyExchange(TlsContext *context,
   TlsServerKeyExchange *message, size_t *length)
{
   error_t error;
   size_t n;
   size_t paramsLen;
   uint8_t *p;
   uint8_t *params;

   //Point to the beginning of the handshake message
   p = message;
   //Length of the handshake message
   *length = 0;

   //PSK key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //To help the client in selecting which identity to use, the server
      //can provide a PSK identity hint in the ServerKeyExchange message
      error = tlsFormatPskIdentityHint(context, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += n;
      //Adjust the length of the message
      *length += n;
   }

   //Diffie-Hellman or ECDH key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_DH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //Point to the server's key exchange parameters
      params = p;

      //Format server's key exchange parameters
      error = tlsFormatServerKeyParams(context, p, &paramsLen);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += paramsLen;
      //Adjust the length of the message
      *length += paramsLen;
   }

   //For non-anonymous Diffie-Hellman and ECDH key exchanges, a signature
   //over the server's key exchange parameters shall be generated
   if(context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
   {
      //Sign server's key exchange parameters
      error = tlsGenerateServerKeySignature(context, p, params, paramsLen, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += n;
      //Adjust the length of the message
      *length += n;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format CertificateRequest message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the CertificateRequest message
 * @param[out] length Length of the resulting CertificateRequest message
 * @return Error code
 **/

error_t tlsFormatCertificateRequest(TlsContext *context,
   TlsCertificateRequest *message, size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *p;
   const char_t *pemCert;
   size_t pemCertLen;
   uint8_t *derCert;
   size_t derCertSize;
   size_t derCertLen;
   X509CertificateInfo *certInfo;
   TlsCertAuthorities *certAuthorities;

   //Initialize status code
   error = NO_ERROR;

   //Enumerate the types of certificate types that the client may offer
   n = 0;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
   //Accept certificates that contain a RSA public key
   message->certificateTypes[n++] = TLS_CERT_RSA_SIGN;
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
   //Accept certificates that contain a DSA public key
   message->certificateTypes[n++] = TLS_CERT_DSS_SIGN;
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   //Accept certificates that contain an ECDSA public key
   message->certificateTypes[n++] = TLS_CERT_ECDSA_SIGN;
#endif

   //Fix the length of the list
   message->certificateTypesLength = (uint8_t) n;
   //Length of the handshake message
   *length = sizeof(TlsCertificateRequest) + n;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      TlsSignHashAlgos *supportedSignAlgos;

      //Point to the list of the hash/signature algorithm pairs that the server
      //is able to verify. Servers can minimize the computation cost by offering
      //a restricted set of digest algorithms
      supportedSignAlgos = PTR_OFFSET(message, *length);

      //Enumerate the hash/signature algorithm pairs in descending
      //order of preference
      n = 0;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
#if (TLS_SHA1_SUPPORT == ENABLED)
      //SHA-1 with RSA is supported
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;
#endif
#if (TLS_SHA256_SUPPORT == ENABLED)
      //The hash algorithm used for PRF operations can also be used for signing
      if(context->cipherSuite.prfHashAlgo == SHA256_HASH_ALGO)
      {
         //SHA-256 with RSA is supported
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
      }
#endif
#if (TLS_SHA384_SUPPORT == ENABLED)
      //The hash algorithm used for PRF operations can also be used for signing
      if(context->cipherSuite.prfHashAlgo == SHA384_HASH_ALGO)
      {
         //SHA-384 with RSA is supported
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_RSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA384;
      }
#endif
#endif

#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
#if (TLS_SHA1_SUPPORT == ENABLED)
      //DSA with SHA-1 is supported
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_DSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;
#endif
#if (TLS_SHA256_SUPPORT == ENABLED)
      //The hash algorithm used for PRF operations can also be used for signing
      if(context->cipherSuite.prfHashAlgo == SHA256_HASH_ALGO)
      {
         //DSA with SHA-256 is supported
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_DSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
      }
#endif
#endif

#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
#if (TLS_SHA1_SUPPORT == ENABLED)
      //ECDSA with SHA-1 is supported
      supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
      supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA1;
#endif
#if (TLS_SHA256_SUPPORT == ENABLED)
      //The hash algorithm used for PRF operations can also be used for signing
      if(context->cipherSuite.prfHashAlgo == SHA256_HASH_ALGO)
      {
         //ECDSA with SHA-256 is supported
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA256;
      }
#endif
#if (TLS_SHA384_SUPPORT == ENABLED)
      //The hash algorithm used for PRF operations can also be used for signing
      if(context->cipherSuite.prfHashAlgo == SHA384_HASH_ALGO)
      {
         //ECDSA with SHA-384 is supported
         supportedSignAlgos->value[n].signature = TLS_SIGN_ALGO_ECDSA;
         supportedSignAlgos->value[n++].hash = TLS_HASH_ALGO_SHA384;
      }
#endif
#endif

      //Fix the length of the list
      supportedSignAlgos->length = htons(n * sizeof(TlsSignHashAlgo));
      //Adjust the length of the message
      *length += sizeof(TlsSignHashAlgos) + n * sizeof(TlsSignHashAlgo);
   }
#endif

   //Point to the list of the distinguished names of acceptable
   //certificate authorities
   certAuthorities = PTR_OFFSET(message, *length);
   //Adjust the length of the message
   *length += sizeof(TlsCertAuthorities);

   //Point to the first certificate authority
   p = certAuthorities->value;
   //Length of the list in bytes
   n = 0;

   //Point to the first trusted CA certificate
   pemCert = context->trustedCaList;
   //Get the total length, in bytes, of the trusted CA list
   pemCertLen = context->trustedCaListLen;

   //DER encoded certificate
   derCert = NULL;
   derCertSize = 0;
   derCertLen = 0;

   //Allocate a memory buffer to store X.509 certificate info
   certInfo = tlsAllocMem(sizeof(X509CertificateInfo));

   //Successful memory allocation?
   if(certInfo != NULL)
   {
      //Loop through the list of trusted CA certificates
      while(pemCertLen > 0)
      {
         //Decode PEM certificate
         error = pemImportCertificate(&pemCert, &pemCertLen,
            &derCert, &derCertSize, &derCertLen);

         //Any error to report?
         if(error)
         {
            //End of file detected
            error = NO_ERROR;
            break;
         }

         //Parse X.509 certificate
         error = x509ParseCertificate(derCert, derCertLen, certInfo);
         //Failed to parse the X.509 certificate?
         if(error)
            break;

         //Adjust the length of the message
         *length += certInfo->subject.rawDataLen + 2;

         //Prevent the buffer from overflowing
         if(*length > context->txBufferMaxLen)
         {
            //Report an error
            error = ERROR_MESSAGE_TOO_LONG;
            break;
         }

         //Each distinguished name is preceded by a 2-byte length field
         STORE16BE(certInfo->subject.rawDataLen, p);
         //The distinguished name shall be DER encoded
         memcpy(p + 2, certInfo->subject.rawData, certInfo->subject.rawDataLen);

         //Advance data pointer
         p += certInfo->subject.rawDataLen + 2;
         //Adjust the length of the list
         n += certInfo->subject.rawDataLen + 2;
      }

      //Free previously allocated memory
      tlsFreeMem(derCert);
      tlsFreeMem(certInfo);

      //Fix the length of the list
      certAuthorities->length = htons(n);
   }
   else
   {
      //Report an error
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
}


/**
 * @brief Format ServerHelloDone message
 * @param[in] context Pointer to the TLS context
 * @param[out] message Buffer where to format the ServerHelloDone message
 * @param[out] length Length of the resulting ServerHelloDone message
 * @return Error code
 **/

error_t tlsFormatServerHelloDone(TlsContext *context,
   TlsServerHelloDone *message, size_t *length)
{
   //The ServerHelloDone message does not contain any data
   *length = 0;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ClientHello message
 *
 * When a client first connects to a server, it is required to send
 * the ClientHello as its first message. The client can also send a
 * ClientHello in response to a HelloRequest or on its own initiative
 * in order to renegotiate the security parameters in an existing
 * connection
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming ClientHello message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseClientHello(TlsContext *context,
   const TlsClientHello *message, size_t length)
{
   error_t error;
   size_t i;
   size_t j;
   size_t n;
   bool_t acceptable;
   uint8_t certType;
   uint16_t serverVersion;
   const uint8_t *p;
   const TlsCipherSuites *cipherSuites;
   const TlsCompressMethods *compressMethods;
   TlsHelloExtensions extensions;
#if (DTLS_SUPPORT == ENABLED)
   const DtlsCookie *cookie;
#endif

   //Debug message
   TRACE_INFO("ClientHello message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check the length of the ClientHello message
   if(length < sizeof(TlsClientHello))
      return ERROR_DECODING_FAILED;

   //Check current state
   if(context->state == TLS_STATE_CLIENT_HELLO)
   {
      //When a client first connects to a server, it is required to send
      //the ClientHello as its first message
   }
#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   else if(context->state == TLS_STATE_APPLICATION_DATA)
   {
      //Check whether secure renegotiation is enabled
      if(context->secureRenegoEnabled)
      {
         //Make sure the secure_renegociation flag is set
         if(!context->secureRenegoFlag)
         {
            //If the connection's secure_renegotiation flag is set to FALSE, it is
            //recommended that servers do not permit legacy renegotiation (refer
            //to RFC 5746, section 4.4)
            return ERROR_HANDSHAKE_FAILED;
         }
      }
      else
      {
         //Secure renegotiation is disabled
         return ERROR_HANDSHAKE_FAILED;
      }
   }
#endif
   else
   {
      //Report an error
      return ERROR_UNEXPECTED_MESSAGE;
   }

   //Get the highest version supported by the implementation
   serverVersion = context->versionMax;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Translate TLS version into DTLS version
      serverVersion = dtlsTranslateVersion(serverVersion);
   }
#endif

   //Get the version the client wishes to use during this session
   context->clientVersion = ntohs(message->clientVersion);

   //Point to the session ID
   p = message->sessionId;
   //Remaining bytes to process
   length -= sizeof(TlsClientHello);

   //Check the length of the session ID
   if(message->sessionIdLen > length)
      return ERROR_DECODING_FAILED;
   if(message->sessionIdLen > 32)
      return ERROR_DECODING_FAILED;

   //Debug message
   TRACE_INFO("Session ID (%" PRIu8 " bytes):\r\n", message->sessionIdLen);
   TRACE_INFO_ARRAY("  ", message->sessionId, message->sessionIdLen);

   //Point to the next field
   p += message->sessionIdLen;
   //Remaining bytes to process
   length -= message->sessionIdLen;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Malformed ClientHello message?
      if(length < sizeof(DtlsCookie))
         return ERROR_DECODING_FAILED;

      //Point to the Cookie field
      cookie = (DtlsCookie *) p;
      //Remaining bytes to process
      length -= sizeof(DtlsCookie);

      //Check the length of the cookie
      if(cookie->length > length)
         return ERROR_DECODING_FAILED;
      if(cookie->length > 32)
         return ERROR_ILLEGAL_PARAMETER;

      //Point to the next field
      p += sizeof(DtlsCookie) + cookie->length;
      //Remaining bytes to process
      length -= cookie->length;
   }
#endif

   //List of cryptographic algorithms supported by the client
   cipherSuites = (TlsCipherSuites *) p;

   //Malformed ClientHello message?
   if(length < sizeof(TlsCipherSuites))
      return ERROR_DECODING_FAILED;
   if(length < (sizeof(TlsCipherSuites) + ntohs(cipherSuites->length)))
      return ERROR_DECODING_FAILED;

   //Check the length of the list
   if(ntohs(cipherSuites->length) == 0)
      return ERROR_DECODING_FAILED;
   if((ntohs(cipherSuites->length) % 2) != 0)
      return ERROR_DECODING_FAILED;

   //Get the number of cipher suite identifiers present in the list
   n = ntohs(cipherSuites->length) / 2;

   //Debug message
   TRACE_DEBUG("Cipher suites:\r\n");

   //Loop through the list of cipher suite identifiers
   for(i = 0; i < n; i++)
   {
      //Debug message
      TRACE_DEBUG("  0x%04" PRIX16 " (%s)\r\n", ntohs(cipherSuites->value[i]),
         tlsGetCipherSuiteName(ntohs(cipherSuites->value[i])));

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
      //TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite?
      if(ntohs(cipherSuites->value[i]) == TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
      {
         //Initial handshake?
         if(context->clientVerifyDataLen == 0)
         {
            //Set the secure_renegotiation flag to TRUE
            context->secureRenegoFlag = TRUE;
         }
         //Secure renegotiation?
         else
         {
            //When a ClientHello is received, the server must verify that it
            //does not contain the TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV. If
            //the SCSV is present, the server must abort the handshake
            return ERROR_HANDSHAKE_FAILED;
         }
      }
      else
#endif
      //TLS_FALLBACK_SCSV signaling cipher suite?
      if(ntohs(cipherSuites->value[i]) == TLS_FALLBACK_SCSV)
      {
#if (DTLS_SUPPORT == ENABLED)
         //DTLS protocol?
         if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
         {
            //Test whether the highest protocol version supported by the server
            //is higher than the version indicated by the client
            if(serverVersion < context->clientVersion)
            {
               //The server must respond with a fatal inappropriate_fallback alert
               return ERROR_INAPPROPRIATE_FALLBACK;
            }
         }
         else
#endif
         //TLS protocol?
         {
            //Test whether the highest protocol version supported by the server
            //is higher than the version indicated by the client
            if(serverVersion > context->clientVersion)
            {
               //The server must respond with a fatal inappropriate_fallback alert
               return ERROR_INAPPROPRIATE_FALLBACK;
            }
         }
      }
   }

   //Point to the next field
   p += sizeof(TlsCipherSuites) + ntohs(cipherSuites->length);
   //Remaining bytes to process
   length -= sizeof(TlsCipherSuites) + ntohs(cipherSuites->length);

   //List of compression algorithms supported by the client
   compressMethods = (TlsCompressMethods *) p;

   //Malformed ClientHello message?
   if(length < sizeof(TlsCompressMethods))
      return ERROR_DECODING_FAILED;
   if(length < (sizeof(TlsCompressMethods) + compressMethods->length))
      return ERROR_DECODING_FAILED;

   //Check the length of the list
   if(compressMethods->length == 0)
      return ERROR_DECODING_FAILED;

   //Point to the next field
   p += sizeof(TlsCompressMethods) + compressMethods->length;
   //Remaining bytes to process
   length -= sizeof(TlsCompressMethods) + compressMethods->length;

   //Parse the list of extensions offered by the client
   error = tlsParseHelloExtensions(context, p, length, &extensions);
   //Any error to report?
   if(error)
      return error;

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //RenegotiationInfo extension found?
   if(extensions.renegoInfo != NULL)
   {
      //Initial handshake?
      if(context->clientVerifyDataLen == 0)
      {
         //Set the secure_renegotiation flag to TRUE
         context->secureRenegoFlag = TRUE;

         //The server must then verify that the length of the
         //renegotiated_connection field is zero
         if(extensions.renegoInfo->length != 0)
         {
            //If it is not, the server must abort the handshake
            return ERROR_HANDSHAKE_FAILED;
         }
      }
      //Secure renegotiation?
      else
      {
         //Check the length of the renegotiated_connection field
         if(extensions.renegoInfo->length != context->clientVerifyDataLen)
         {
            //The server must abort the handshake
            return ERROR_HANDSHAKE_FAILED;
         }

         //The server must verify that the value of the renegotiated_connection
         //field is equal to the saved client_verify_data value
         if(memcmp(extensions.renegoInfo->value, context->clientVerifyData,
            context->clientVerifyDataLen))
         {
            //If it is not, the server must abort the handshake
            return ERROR_HANDSHAKE_FAILED;
         }
      }
   }
   else
   {
      //Secure renegotiation?
      if(context->clientVerifyDataLen != 0 || context->serverVerifyDataLen != 0)
      {
         //The server must verify that the renegotiation_info extension is
         //present. If it is not, the server must abort the handshake
         return ERROR_HANDSHAKE_FAILED;
      }
   }
#endif

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Any registered callbacks?
      if(context->cookieVerifyCallback != NULL &&
         context->cookieGenerateCallback != NULL)
      {
         DtlsClientParameters params;

         //The server should use client parameters (version, random, session_id,
         //cipher_suites, compression_method) to generate its cookie
         params.version = ntohs(message->clientVersion);
         params.random = (const uint8_t *) &message->random;
         params.randomLen = sizeof(TlsRandom);
         params.sessionId = message->sessionId;
         params.sessionIdLen = message->sessionIdLen;
         params.cipherSuites = (const uint8_t *) cipherSuites->value;
         params.cipherSuitesLen = ntohs(cipherSuites->length);
         params.compressMethods = compressMethods->value;
         params.compressMethodsLen = compressMethods->length;

         //Verify that the cookie is valid
         error = context->cookieVerifyCallback(context->cookieHandle,
            &params, cookie->value, cookie->length);

         //Invalid cookie?
         if(error == ERROR_WRONG_COOKIE)
         {
            //Set the cookie size limit (32 or 255 bytes depending on DTLS version)
            context->cookieLen = DTLS_MAX_COOKIE_SIZE;

            //The DTLS server should generate cookies in such a way that they can
            //be verified without retaining any per-client state on the server
            error = context->cookieGenerateCallback(context->cookieHandle,
               &params, context->cookie, &context->cookieLen);

            //Check status code
            if(!error)
            {
               //Send a HelloVerifyRequest message to the DTLS client
               context->state = TLS_STATE_HELLO_VERIFY_REQUEST;
               //Exit immediately
               return NO_ERROR;
            }
         }
      }
      else
      {
         //The server may be configured not to perform a cookie exchange
         error = NO_ERROR;
      }

      //Cookie verification failed?
      if(error)
         return error;

      //If a DTLS server receives a ClientHello containing a version number
      //greater than the highest version supported by the server, it must
      //reply according to the highest version supported by the server
      serverVersion = MAX(serverVersion, context->clientVersion);

      //Set the DTLS version to be used
      error = dtlsSelectVersion(context, serverVersion);
   }
   else
#endif
   //TLS protocol?
   {
      //If a TLS server receives a ClientHello containing a version number
      //greater than the highest version supported by the server, it must
      //reply according to the highest version supported by the server
      serverVersion = MIN(serverVersion, context->clientVersion);

      //Set the TLS version to be used
      error = tlsSelectVersion(context, serverVersion);
   }

   //Specified TLS/DTLS version not supported?
   if(error)
      return error;

   //Save client random value
   context->clientRandom = message->random;

#if (TLS_SESSION_RESUME_SUPPORT == ENABLED)
   //Check whether session caching is supported
   if(context->cache != NULL)
   {
      TlsSession *session;

      //If the session ID was non-empty, the server will look in its
      //session cache for a match
      session = tlsFindCache(context->cache, message->sessionId,
         message->sessionIdLen);

      //Matching session found?
      if(session != NULL)
      {
         //Whenever a client already knows the highest protocol version known
         //to a server (for example, when resuming a session), it should
         //initiate the connection in that native protocol
         if(session->version != context->version)
            session = NULL;
      }

      //Matching session found?
      if(session != NULL)
      {
         //Get the total number of cipher suites offered by the client
         n = ntohs(cipherSuites->length) / 2;

         //Loop through the list of cipher suite identifiers
         for(i = 0; i < n; i++)
         {
            //Matching cipher suite?
            if(ntohs(cipherSuites->value[i]) == session->cipherSuite)
               break;
         }

         //If the cipher suite is not present in the list cipher suites offered
         //by the client, the server must not perform the abbreviated handshake
         if(i >= n)
            session = NULL;
      }

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
      //Matching session found?
      if(session != NULL)
      {
         //ExtendedMasterSecret extension found?
         if(extensions.extendedMasterSecret != NULL)
         {
            //If the original session did not use the ExtendedMasterSecret
            //extension but the new ClientHello contains the extension, then
            //the server must not perform the abbreviated handshake
            if(!session->extendedMasterSecret)
               session = NULL;
         }
      }
#endif

      //Matching session found?
      if(session != NULL)
      {
         //Restore session parameters
         tlsRestoreSession(context, session);

         //Select the relevant cipher suite
         error = tlsSelectCipherSuite(context, session->cipherSuite);
         //Any error to report?
         if(error)
            return error;

         //Perform abbreviated handshake
         context->resume = TRUE;
      }
      else
      {
         //Generate a new random ID
         error = context->prngAlgo->read(context->prngContext,
            context->sessionId, 32);
         //Any error to report?
         if(error)
            return error;

         //Session ID is limited to 32 bytes
         context->sessionIdLen = 32;
         //Perform a full handshake
         context->resume = FALSE;
      }
   }
   else
#endif
   {
      //This session cannot be resumed
      context->sessionIdLen = 0;
      //Perform a full handshake
      context->resume = FALSE;
   }

   //Full handshake?
   if(!context->resume)
   {
      //Get the total number of cipher suites offered by the client
      n = ntohs(cipherSuites->length) / 2;

      //The cipher suite list contains the combinations of cryptographic
      //algorithms supported by the client in order of the client's
      //preference
      for(i = 0; i < n; i++)
      {
         //Check whether the current cipher suite is supported
         error = tlsSelectCipherSuite(context, ntohs(cipherSuites->value[i]));

         //Successful processing?
         if(!error)
         {
            //ECC cipher suite?
            if(context->keyExchMethod == TLS_KEY_EXCH_ECDH_ANON ||
               context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
               context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
               context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
            {
               //One of the proposed ECC cipher suites must be negotiated only
               //if the server can successfully complete the handshake while
               //using the curves and point formats supported by the client
               error = tlsSelectNamedCurve(context, extensions.ellipticCurveList);
            }
         }

         //Successful processing?
         if(!error)
         {
            //The server requires a valid certificate whenever the agreed-upon
            //key exchange method uses certificates for authentication
            if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
               context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
               context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
               context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
            {
               //RSA, DHE_RSA, ECDHE_RSA and RAS_PSK key exchange methods
               //require a RSA certificate
               certType = TLS_CERT_RSA_SIGN;
            }
            else if(context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS)
            {
               //DHE_DSS key exchange method requires a DSA certificate
               certType = TLS_CERT_DSS_SIGN;
            }
            else if(context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
            {
               //ECDHE_ECDSA key exchange method requires an ECDSA certificate
               certType = TLS_CERT_ECDSA_SIGN;
            }
            else
            {
               //DH_anon and ECDH_anon key exchange methods do not require any certificate
               certType = TLS_CERT_NONE;
            }

            //Check whether a certificate is required
            if(certType != TLS_CERT_NONE)
            {
               //Do not accept the specified cipher suite unless a suitable
               //certificate has been previously loaded by the user
               error = ERROR_NO_CERTIFICATE;

               //Loop through the list of available certificates
               for(j = 0; j < context->numCerts; j++)
               {
                  //Check whether the current certificate is acceptable
                  acceptable = tlsIsCertificateAcceptable(&context->certs[j],
                     &certType, 1, extensions.signAlgoList,
                     extensions.ellipticCurveList, NULL);

                  //Is the certificate suitable for the selected cipher suite?
                  if(acceptable)
                  {
                     //The hash algorithm to be used when generating signatures
                     //must be one of those present in the SignatureAlgorithms
                     //extension
                     error = tlsSelectSignHashAlgo(context,
                        context->certs[j].signAlgo, extensions.signAlgoList);

                     //If all the requirements were met, the certificate can be
                     //used in conjunction with the selected cipher suite
                     if(!error)
                     {
                        context->cert = &context->certs[j];
                        break;
                     }
                  }
               }
            }
         }

         //If the list contains cipher suites the server does not recognize,
         //support, or wish to use, the server must ignore those cipher
         //suites, and process the remaining ones as usual
         if(!error)
            break;
      }

      //If no acceptable choices are presented, return a handshake failure
      //alert and close the connection
      if(error)
         return ERROR_HANDSHAKE_FAILED;

      //The list of the compression methods supported by the client
      //is sorted by client preference
      for(i = 0; i < compressMethods->length; i++)
      {
         //Check whether the algorithm to be used for data compression is supported
         error = tlsSelectCompressMethod(context, compressMethods->value[i]);
         //If the compression method is not supported, process the remaining ones
         if(!error)
            break;
      }

      //If no compression algorithm is acceptable, return a handshake failure
      //alert and close the connection
      if(error)
         return ERROR_ILLEGAL_PARAMETER;
   }

#if (TLS_SNI_SUPPORT == ENABLED)
   //SNI extension found?
   if(extensions.serverNameList != NULL)
   {
      //In order to provide the server name, clients may include a ServerName
      //extension
      error = tlsParseClientSniExtension(context, extensions.serverNameList);
      //Any error to report?
      if(error)
         return error;
   }
#endif

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   //MaxFragmentLength extension found?
   if(extensions.maxFragLen != NULL)
   {
      //In order to negotiate smaller maximum fragment lengths, clients may
      //include a MaxFragmentLength extension
      error = tlsParseClientMaxFragLenExtension(context, extensions.maxFragLen);
      //Any error to report?
      if(error)
         return error;

      //A valid MaxFragmentLength extension has been received
      context->maxFragLenExtReceived = TRUE;
   }
   else
   {
      //The ClientHello does not contain any MaxFragmentLength extension
      context->maxFragLenExtReceived = FALSE;
   }
#endif

#if (TLS_ECDH_ANON_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_SUPPORT == ENABLED || TLS_ECDHE_PSK_SUPPORT == ENABLED)
   //EcPointFormats extension found?
   if(extensions.ecPointFormatList != NULL)
   {
      //A client that proposes ECC cipher suites in its ClientHello message
      //may send the EcPointFormats extension
      error = tlsParseClientEcPointFormatsExtension(context,
         extensions.ecPointFormatList);
      //Any error to report?
      if(error)
         return error;

      //A valid EcPointFormats extension has been received
      context->ecPointFormatsExtReceived = TRUE;
   }
   else
   {
      //The ClientHello does not contain any EcPointFormats extension
      context->ecPointFormatsExtReceived = FALSE;
   }
#endif

#if (TLS_ALPN_SUPPORT == ENABLED)
   //ALPN extension found?
   if(extensions.protocolNameList != NULL)
   {
      //Parse ALPN extension
      error = tlsParseClientAlpnExtension(context, extensions.protocolNameList);
      //Any error to report?
      if(error)
         return error;
   }
#endif

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //ExtendedMasterSecret extension found?
   if(extensions.extendedMasterSecret != NULL)
   {
      //SSL 3.0 currently selected?
      if(context->version == SSL_VERSION_3_0)
      {
         //If the client chooses to support SSL 3.0, the resulting session
         //must use the legacy master secret computation
         context->extendedMasterSecretExtReceived = FALSE;
      }
      else
      {
         //Use the extended master secret computation
         context->extendedMasterSecretExtReceived = TRUE;
      }
   }
   else
   {
      //Abbreviated handshake?
      if(context->resume)
      {
         //If the original session used the ExtendedMasterSecret extension but
         //the new ClientHello does not contain it, the server must abort the
         //abbreviated handshake
         if(context->extendedMasterSecretExtReceived)
            return ERROR_HANDSHAKE_FAILED;
      }

      //If the client and server choose to continue a full handshake without
      //the extension, they must use the standard master secret derivation
      //for the new session
      context->extendedMasterSecretExtReceived = FALSE;
   }
#endif

   //Initialize handshake message hashing
   error = tlsInitHandshakeHash(context);
   //Any error to report?
   if(error)
      return error;

   //Prepare to send ServerHello message...
   context->state = TLS_STATE_SERVER_HELLO;
   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ClientKeyExchange message
 *
 * This message is always sent by the client. It must immediately
 * follow the client Certificate message, if it is sent. Otherwise,
 * it must be the first message sent by the client after it receives
 * the ServerHelloDone message
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming ClientKeyExchange message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseClientKeyExchange(TlsContext *context,
   const TlsClientKeyExchange *message, size_t length)
{
   error_t error;
   size_t n;
   const uint8_t *p;

   //Debug message
   TRACE_INFO("ClientKeyExchange message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check current state
   if(context->state == TLS_STATE_CLIENT_CERTIFICATE)
   {
      //A an non-anonymous server can optionally request a certificate from the client
      if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
         context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA ||
         context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
      {
         //If client authentication is required by the server for the handshake
         //to continue, it may respond with a fatal handshake failure alert
         if(context->clientAuthMode == TLS_CLIENT_AUTH_REQUIRED)
            return ERROR_HANDSHAKE_FAILED;
      }
   }
   else if(context->state != TLS_STATE_CLIENT_KEY_EXCHANGE)
   {
      //Send a fatal alert to the client
      return ERROR_UNEXPECTED_MESSAGE;
   }

   //Point to the beginning of the handshake message
   p = message;

   //PSK key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //The PSK identity is sent in cleartext
      error = tlsParsePskIdentity(context, p, length, &n);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += n;
      //Remaining bytes to process
      length -= n;
   }

   //RSA, Diffie-Hellman or ECDH key exchange method?
   if(context->keyExchMethod != TLS_KEY_EXCH_PSK)
   {
      //Parse client's key exchange parameters
      error = tlsParseClientKeyParams(context, p, length, &n);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      p += n;
      //Remaining bytes to process
      length -= n;
   }

   //If the amount of data in the message does not precisely match the format
   //of the ClientKeyExchange message, then send a fatal alert
   if(length != 0)
      return ERROR_DECODING_FAILED;

   //PSK key exchange method?
   if(context->keyExchMethod == TLS_KEY_EXCH_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_DHE_PSK ||
      context->keyExchMethod == TLS_KEY_EXCH_ECDHE_PSK)
   {
      //Generate premaster secret
      error = tlsGeneratePskPremasterSecret(context);
      //Any error to report?
      if(error)
         return error;
   }

   //Derive session keys from the premaster secret
   error = tlsGenerateSessionKeys(context);
   //Unable to generate key material?
   if(error)
      return error;

   //Update FSM state
   if(context->peerCertType != TLS_CERT_NONE)
      context->state = TLS_STATE_CERTIFICATE_VERIFY;
   else
      context->state = TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse CertificateVerify message
 *
 * The CertificateVerify message is used to provide explicit verification
 * of a client certificate. This message is only sent following a client
 * certificate that has signing capability
 *
 * @param[in] context Pointer to the TLS context
 * @param[in] message Incoming CertificateVerify message to parse
 * @param[in] length Message length
 * @return Error code
 **/

error_t tlsParseCertificateVerify(TlsContext *context,
   const TlsCertificateVerify *message, size_t length)
{
   error_t error;

   //Debug message
   TRACE_INFO("CertificateVerify message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_DEBUG_ARRAY("  ", message, length);

   //Check current state
   if(context->state != TLS_STATE_CERTIFICATE_VERIFY)
      return ERROR_UNEXPECTED_MESSAGE;

#if (TLS_MAX_VERSION >= SSL_VERSION_3_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //SSL 3.0, TLS 1.0 or TLS 1.1 currently selected?
   if(context->version <= TLS_VERSION_1_1)
   {
      TlsDigitalSignature *signature;

      //Point to the digitally-signed element
      signature = (TlsDigitalSignature *) message;

      //Check the length of the digitally-signed element
      if(length < sizeof(TlsDigitalSignature))
         return ERROR_DECODING_FAILED;
      if(length != (sizeof(TlsDigitalSignature) + ntohs(signature->length)))
         return ERROR_DECODING_FAILED;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
      //The client's certificate contains a valid RSA public key?
      if(context->peerCertType == TLS_CERT_RSA_SIGN)
      {
         //Digest all the handshake messages starting at ClientHello (using MD5)
         error = tlsFinalizeHandshakeHash(context, MD5_HASH_ALGO,
            context->handshakeMd5Context, "", context->clientVerifyData);
         //Any error to report?
         if(error)
            return error;

         //Digest all the handshake messages starting at ClientHello (using SHA-1)
         error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
            context->handshakeSha1Context, "", context->clientVerifyData + MD5_DIGEST_SIZE);
         //Any error to report?
         if(error)
            return error;

         //Verify RSA signature using client's public key
         error = tlsVerifyRsaSignature(&context->peerRsaPublicKey,
            context->clientVerifyData, signature->value, ntohs(signature->length));
      }
      else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
      //The client's certificate contains a valid DSA public key?
      if(context->peerCertType == TLS_CERT_DSS_SIGN)
      {
         //Digest all the handshake messages starting at ClientHello
         error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
            context->handshakeSha1Context, "", context->clientVerifyData);
         //Any error to report?
         if(error)
            return error;

         //Verify DSA signature using client's public key
         error = tlsVerifyDsaSignature(context, context->clientVerifyData,
            SHA1_DIGEST_SIZE, signature->value, ntohs(signature->length));
      }
      else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
      //The client's certificate contains a valid ECDSA public key?
      if(context->peerCertType == TLS_CERT_ECDSA_SIGN)
      {
         //Digest all the handshake messages starting at ClientHello
         error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
            context->handshakeSha1Context, "", context->clientVerifyData);
         //Any error to report?
         if(error)
            return error;

         //Verify ECDSA signature using client's public key
         error = tlsVerifyEcdsaSignature(context, context->clientVerifyData,
            SHA1_DIGEST_SIZE, signature->value, ntohs(signature->length));
      }
      else
#endif
      //Invalid signature algorithm?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.2 currently selected?
   if(context->version == TLS_VERSION_1_2)
   {
      TlsDigitalSignature2 *signature;
      const HashAlgo *hashAlgo;

      //Point to the digitally-signed element
      signature = (TlsDigitalSignature2 *) message;

      //Check the length of the digitally-signed element
      if(length < sizeof(TlsDigitalSignature2))
         return ERROR_DECODING_FAILED;
      if(length != (sizeof(TlsDigitalSignature2) + ntohs(signature->length)))
         return ERROR_DECODING_FAILED;

      //Retrieve the hash algorithm used for signing
      hashAlgo = tlsGetHashAlgo(signature->algorithm.hash);

      //Digest all the handshake messages starting at ClientHello
      if(hashAlgo == SHA1_HASH_ALGO)
      {
         //Use SHA-1 hash algorithm
         error = tlsFinalizeHandshakeHash(context, SHA1_HASH_ALGO,
            context->handshakeSha1Context, "", context->clientVerifyData);
      }
      else if(hashAlgo == context->cipherSuite.prfHashAlgo)
      {
         //Use PRF hash algorithm (SHA-256 or SHA-384)
         error = tlsFinalizeHandshakeHash(context, hashAlgo,
            context->handshakeHashContext, "", context->clientVerifyData);
      }
      else
      {
         //The specified hash algorithm is not supported
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }

      //Any error to report?
      if(error)
         return error;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
      //The client's certificate contains a valid RSA public key?
      if(signature->algorithm.signature == TLS_SIGN_ALGO_RSA)
      {
         //Use the signature verification algorithm defined in PKCS #1 v1.5
         error = rsassaPkcs1v15Verify(&context->peerRsaPublicKey, hashAlgo,
            context->clientVerifyData, signature->value, ntohs(signature->length));
      }
      else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
      //The client's certificate contains a valid DSA public key?
      if(signature->algorithm.signature == TLS_SIGN_ALGO_DSA)
      {
         //Verify DSA signature using client's public key
         error = tlsVerifyDsaSignature(context, context->clientVerifyData,
            hashAlgo->digestSize, signature->value, ntohs(signature->length));
      }
      else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
      //The client's certificate contains a valid ECDSA public key?
      if(signature->algorithm.signature == TLS_SIGN_ALGO_ECDSA)
      {
         //Verify ECDSA signature using client's public key
         error = tlsVerifyEcdsaSignature(context, context->clientVerifyData,
            hashAlgo->digestSize, signature->value, ntohs(signature->length));
      }
      else
#endif
      //Invalid signature algorithm?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }
   else
#endif
   //Invalid TLS version?
   {
      //Report an error
      error = ERROR_INVALID_VERSION;
   }

   //Prepare to receive a ChangeCipherSpec message...
   context->state = TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC;
   //Return status code
   return error;
}

#endif
