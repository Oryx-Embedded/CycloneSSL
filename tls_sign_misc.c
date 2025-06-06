/**
 * @file tls_sign_misc.c
 * @brief Helper functions for signature generation and verification
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2022-2025 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneIPSEC Open.
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
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include "tls.h"
#include "tls_cipher_suites.h"
#include "tls_sign_misc.h"
#include "tls_misc.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)

//List of supported signature algorithms
const uint16_t tlsSupportedSignAlgos[] =
{
   TLS_SIGN_SCHEME_ED25519,
   TLS_SIGN_SCHEME_ED448,
   TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256,
   TLS_SIGN_SCHEME_ECDSA_SECP384R1_SHA384,
   TLS_SIGN_SCHEME_ECDSA_SECP521R1_SHA512,
   TLS_SIGN_SCHEME_ECDSA_BP256R1_TLS13_SHA256,
   TLS_SIGN_SCHEME_ECDSA_BP384R1_TLS13_SHA384,
   TLS_SIGN_SCHEME_ECDSA_BP512R1_TLS13_SHA512,
   TLS_SIGN_SCHEME_SM2SIG_SM3,
   TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA256,
   TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA384,
   TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA512,
   TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA256,
   TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA384,
   TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA512,
   TLS_SIGN_SCHEME_RSA_PKCS1_SHA256,
   TLS_SIGN_SCHEME_RSA_PKCS1_SHA384,
   TLS_SIGN_SCHEME_RSA_PKCS1_SHA512,
   TLS_SIGN_SCHEME(TLS_SIGN_ALGO_DSA, TLS_HASH_ALGO_SHA256),
   TLS_SIGN_SCHEME(TLS_SIGN_ALGO_ECDSA, TLS_HASH_ALGO_SHA224),
   TLS_SIGN_SCHEME(TLS_SIGN_ALGO_RSA, TLS_HASH_ALGO_SHA224),
   TLS_SIGN_SCHEME(TLS_SIGN_ALGO_DSA, TLS_HASH_ALGO_SHA224),
   TLS_SIGN_SCHEME_ECDSA_SHA1,
   TLS_SIGN_SCHEME_RSA_PKCS1_SHA1,
   TLS_SIGN_SCHEME(TLS_SIGN_ALGO_DSA, TLS_HASH_ALGO_SHA1),
   TLS_SIGN_SCHEME(TLS_SIGN_ALGO_RSA, TLS_HASH_ALGO_MD5)
};


/**
 * @brief Select the algorithm to be used when generating digital signatures
 * @param[in] context Pointer to the TLS context
 * @param[in] cert End entity certificate
 * @param[in] signAlgoList List of signature/hash algorithm pairs offered by
 *   the peer
 * @return Error code
 **/

error_t tlsSelectSignAlgo(TlsContext *context, const TlsCertDesc *cert,
   const TlsSignSchemeList *signAlgoList)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;
   //Default signature algorithm
   context->signScheme = TLS_SIGN_SCHEME_NONE;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   //TLS 1.0 or TLS 1.1 currently selected?
   if(context->version <= TLS_VERSION_1_1)
   {
      //Check certificate type
      if(cert->type != TLS_CERT_RSA_SIGN &&
         cert->type != TLS_CERT_DSS_SIGN &&
         cert->type != TLS_CERT_ECDSA_SIGN)
      {
         error = ERROR_HANDSHAKE_FAILED;
      }
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.2 or TLS 1.3 currently selected?
   if(context->version >= TLS_VERSION_1_2)
   {
      uint_t i;
      uint_t n;
      uint16_t signScheme;

      //Check whether the peer has provided a list of supported signature
      //algorithms
      if(signAlgoList != NULL)
      {
         //Any preferred preferred signature algorithms?
         if(context->numSupportedSignAlgos > 0)
         {
            //Loop through the list of allowed signature algorithms (most
            //preferred first)
            for(i = 0; i < context->numSupportedSignAlgos; i++)
            {
               //Get current signature algorithm
               signScheme = context->supportedSignAlgos[i];

               //Check whether the signature algorithm is offered by the peer
               if(tlsIsSignAlgoOffered(signScheme, signAlgoList))
               {
                  //The signature algorithm must be compatible with the key in
                  //the end-entity certificate (refer to RFC 5246, section 7.4.3)
                  if(tlsIsSignAlgoAcceptable(context, signScheme, cert))
                  {
                     //Check whether the signature algorithm is supported
                     if(tlsIsSignAlgoSupported(context, signScheme))
                     {
                        context->signScheme = (TlsSignatureScheme) signScheme;
                        break;
                     }
                  }
               }
            }
         }
         else
         {
            //Retrieve the number of items in the list
            n = ntohs(signAlgoList->length) / sizeof(uint16_t);

            //Loop through the list of signature algorithms offered by the peer
            for(i = 0; i < n; i++)
            {
               //Each SignatureScheme value lists a single signature algorithm
               signScheme = ntohs(signAlgoList->value[i]);

               //The signature algorithm must be compatible with the key in the
               //end-entity certificate (refer to RFC 5246, section 7.4.3)
               if(tlsIsSignAlgoAcceptable(context, signScheme, cert))
               {
                  //Check whether the signature algorithm is supported
                  if(tlsIsSignAlgoSupported(context, signScheme))
                  {
                     context->signScheme = (TlsSignatureScheme) signScheme;
                     break;
                  }
               }
            }
         }
      }
      else
      {
         //TLS 1.2 clients may omit the SignatureAlgorithms extension
         if(context->version == TLS_VERSION_1_2)
         {
            //Check certificate type
            if(cert->type == TLS_CERT_RSA_SIGN)
            {
               //If the negotiated key exchange algorithm is one of RSA,
               //DHE_RSA, DH_RSA, RSA_PSK, ECDH_RSA, ECDHE_RSA, behave as if
               //client had sent the value {sha1,rsa}
               signScheme = TLS_SIGN_SCHEME(TLS_SIGN_ALGO_RSA,
                  TLS_HASH_ALGO_SHA1);
            }
            else if(cert->type == TLS_CERT_DSS_SIGN)
            {
               //If the negotiated key exchange algorithm is one of DHE_DSS,
               //DH_DSS, behave as if the client had sent the value {sha1,dsa}
               signScheme = TLS_SIGN_SCHEME(TLS_SIGN_ALGO_DSA,
                  TLS_HASH_ALGO_SHA1);
            }
            else if(cert->type == TLS_CERT_ECDSA_SIGN)
            {
               //If the negotiated key exchange algorithm is one of ECDH_ECDSA,
               //ECDHE_ECDSA, behave as if the client had sent value {sha1,ecdsa}
               signScheme = TLS_SIGN_SCHEME(TLS_SIGN_ALGO_ECDSA,
                  TLS_HASH_ALGO_SHA1);
            }
            else
            {
               //Unknown certificate type
               signScheme = TLS_SIGN_SCHEME_NONE;
            }

            //Check whether the signature algorithm is supported
            if(tlsIsSignAlgoSupported(context, signScheme))
            {
               context->signScheme = (TlsSignatureScheme) signScheme;
            }
         }
      }

      //If no acceptable choices are presented, return an error
      if(context->signScheme == TLS_SIGN_SCHEME_NONE)
      {
         error = ERROR_HANDSHAKE_FAILED;
      }
   }
   else
#endif
   //Invalid TLS version?
   {
      //Report an error
      error = ERROR_INVALID_VERSION;
   }

   //Return status code
   return error;
}


/**
 * @brief Format SignatureAlgorithms extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the SignatureAlgorithms extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatSignAlgosExtension(TlsContext *context, uint8_t *p,
   size_t *written)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //Check whether TLS 1.2 or TLS 1.3 is supported
   if(context->versionMax >= TLS_VERSION_1_2)
   {
      TlsExtension *extension;

      //Add the SignatureAlgorithms extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_SIGNATURE_ALGORITHMS);

      //The SignatureAlgorithms extension indicates which signature/hash
      //algorithm pairs may be used in digital signatures
      error = tlsFormatSupportedSignAlgos(context, extension->value, &n);

      //Check status code
      if(!error)
      {
         //Fix the length of the extension
         extension->length = htons(n);

         //Compute the length, in bytes, of the SignatureAlgorithms extension
         n += sizeof(TlsExtension);
      }
   }
   else
#endif
   {
      //This extension is not meaningful for TLS versions prior to 1.2.
      //Clients must not offer it if they are offering prior versions (refer
      //to RFC 5246, section 7.4.1.4.1)
      n = 0;
   }

   //Check status code
   if(!error)
   {
      //Total number of bytes that have been written
      *written = n;
   }

   //Return status code
   return error;
}


/**
 * @brief Format SignatureAlgorithmsCert extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the SignatureAlgorithmsCert extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatSignAlgosCertExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.2 implementations should also process this extension
   if(context->versionMax >= TLS_VERSION_1_2)
   {
      uint_t i;
      TlsExtension *extension;
      TlsSignSchemeList *signAlgoList;

      //Add the SignatureAlgorithmsCert extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_SIGNATURE_ALGORITHMS_CERT);

      //The SignatureAlgorithmsCert extension allows an implementation to
      //indicate which signature algorithms it can validate in X.509
      //certificates
      signAlgoList = (TlsSignSchemeList *) extension->value;

      //Enumerate the hash/signature algorithm pairs in descending order
      //of preference
      n = 0;

      //Loop through the list of supported signature algorithms
      for(i = 0; i < arraysize(tlsSupportedSignAlgos); i++)
      {
         //Check whether the signature algorithm can be used for X.509
         //certificate validation
         if(tlsIsCertSignAlgoSupported(tlsSupportedSignAlgos[i]))
         {
            //Add the current signature algorithm to the list
            signAlgoList->value[n++] = htons(tlsSupportedSignAlgos[i]);
         }
      }

      //Compute the length, in bytes, of the list
      n *= sizeof(uint16_t);
      //Fix the length of the list
      signAlgoList->length = htons(n);

      //Consider the 2-byte length field that precedes the list
      n += sizeof(TlsSignSchemeList);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the SignatureAlgorithmsCert extension
      n += sizeof(TlsExtension);
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format the list of supported signature algorithms
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the list of signature algorithms
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatSupportedSignAlgos(TlsContext *context, uint8_t *p,
   size_t *written)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   uint_t i;
   size_t n;
   uint_t numSupportedSignAlgos;
   const uint16_t *supportedSignAlgos;
   TlsSignSchemeList *signAlgoList;

   //The list contains the hash/signature algorithm pairs that the
   //implementation is able to verify
   signAlgoList = (TlsSignSchemeList *) p;

   //Any preferred preferred signature algorithms?
   if(context->numSupportedSignAlgos > 0)
   {
      //Point to the list of preferred signature algorithms
      supportedSignAlgos = context->supportedSignAlgos;
      numSupportedSignAlgos = context->numSupportedSignAlgos;
   }
   else
   {
      //Point to the list of default signature algorithms
      supportedSignAlgos = tlsSupportedSignAlgos;
      numSupportedSignAlgos = arraysize(tlsSupportedSignAlgos);
   }

   //Enumerate the hash/signature algorithm pairs in descending order of
   //preference
   n = 0;

   //Loop through the list of signature algorithms
   for(i = 0; i < numSupportedSignAlgos; i++)
   {
      //Check whether the signature algorithm can be used in digital signature
      if(tlsIsSignAlgoSupported(context, supportedSignAlgos[i]))
      {
         //Add the current signature algorithm to the list
         signAlgoList->value[n++] = htons(supportedSignAlgos[i]);
      }
   }

   //Compute the length, in bytes, of the list
   n *= sizeof(uint16_t);
   //Fix the length of the list
   signAlgoList->length = htons(n);

   //Total number of bytes that have been written
   *written = n + sizeof(TlsSignSchemeList);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Check whether a signature algorithm is offered in the
 *   SignatureAlgorithms extension
 * @param[in] signScheme Signature scheme
 * @param[in] signSchemeList List of signature schemes
 * @return TRUE if the signature algorithm is offered in the
 *   SignatureAlgorithms extension, else FALSE
 **/

bool_t tlsIsSignAlgoOffered(uint16_t signScheme,
   const TlsSignSchemeList *signSchemeList)
{
   uint_t i;
   uint_t n;
   bool_t found;

   //Initialize flag
   found = FALSE;

   //Valid SignatureAlgorithms extension?
   if(signSchemeList != NULL)
   {
      //Get the number of signature algorithms present in the list
      n = ntohs(signSchemeList->length) / sizeof(uint16_t);

      //Loop through the list of signature algorithms offered in the
      //SignatureAlgorithms extension
      for(i = 0; i < n && !found; i++)
      {
         //Matching signature algorithm?
         if(ntohs(signSchemeList->value[i]) == signScheme)
         {
            found = TRUE;
         }
      }
   }

   //Return TRUE if the signature algorithm is offered in the
   //SignatureAlgorithms extension
   return found;
}


/**
 * @brief Check whether a signature algorithm is compatible with the specified
 *   end-entity certificate
 * @param[in] context Pointer to the TLS context
 * @param[in] signScheme Signature scheme
 * @param[in] cert End entity certificate
 * @return TRUE if the signature algorithm is compatible, else FALSE
 **/

bool_t tlsIsSignAlgoAcceptable(TlsContext *context, uint16_t signScheme,
   const TlsCertDesc *cert)
{
   bool_t acceptable;

   //Initialize flag
   acceptable = FALSE;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
   //RSA certificate?
   if(cert->type == TLS_CERT_RSA_SIGN)
   {
      //Check signature scheme
      if(TLS_SIGN_ALGO(signScheme) == TLS_SIGN_ALGO_RSA)
      {
         //In TLS 1.3, RSASSA-PKCS1-v1_5 signature algorithms refer solely to
         //signatures which appear in certificates and are not defined for use
         //in signed TLS handshake messages
         if(context->version <= TLS_VERSION_1_2)
         {
            acceptable = TRUE;
         }
      }
      else if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA256 ||
         signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA384 ||
         signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA512)
      {
         //TLS 1.2 or TLS 1.3 currently selected?
         if(context->version >= TLS_VERSION_1_2)
         {
            acceptable = TRUE;
         }
      }
      else
      {
         //Just for sanity
      }
   }
   else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
   //RSA-PSS certificate?
   if(cert->type == TLS_CERT_RSA_PSS_SIGN)
   {
      //TLS 1.2 or TLS 1.3 currently selected?
      if(context->version >= TLS_VERSION_1_2)
      {
         //Check signature scheme
         if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA256 ||
            signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA384 ||
            signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA512)
         {
            acceptable = TRUE;
         }
      }
   }
   else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
   //DSA certificate?
   if(cert->type == TLS_CERT_DSS_SIGN)
   {
      //TLS 1.3 removes support for DSA certificates
      if(context->version <= TLS_VERSION_1_2)
      {
         //Check signature scheme
         if(TLS_SIGN_ALGO(signScheme) == TLS_SIGN_ALGO_DSA)
         {
            acceptable = TRUE;
         }
      }
   }
   else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   //ECDSA certificate?
   if(cert->type == TLS_CERT_ECDSA_SIGN)
   {
      //Version of TLS prior to TLS 1.3?
      if(context->version <= TLS_VERSION_1_2)
      {
         //Check signature scheme
         if(TLS_SIGN_ALGO(signScheme) == TLS_SIGN_ALGO_ECDSA)
         {
            acceptable = TRUE;
         }
      }
      else
      {
         //Check signature scheme against elliptic curve
         if(signScheme == TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256 &&
            cert->namedCurve == TLS_GROUP_SECP256R1)
         {
            acceptable = TRUE;
         }
         else if(signScheme == TLS_SIGN_SCHEME_ECDSA_SECP384R1_SHA384 &&
            cert->namedCurve == TLS_GROUP_SECP384R1)
         {
            acceptable = TRUE;
         }
         else if(signScheme == TLS_SIGN_SCHEME_ECDSA_SECP521R1_SHA512 &&
            cert->namedCurve == TLS_GROUP_SECP521R1)
         {
            acceptable = TRUE;
         }
         else if(signScheme == TLS_SIGN_SCHEME_ECDSA_BP256R1_TLS13_SHA256 &&
            cert->namedCurve == TLS_GROUP_BRAINPOOLP256R1)
         {
            acceptable = TRUE;
         }
         else if(signScheme == TLS_SIGN_SCHEME_ECDSA_BP384R1_TLS13_SHA384 &&
            cert->namedCurve == TLS_GROUP_BRAINPOOLP384R1)
         {
            acceptable = TRUE;
         }
         else if(signScheme == TLS_SIGN_SCHEME_ECDSA_BP512R1_TLS13_SHA512 &&
            cert->namedCurve == TLS_GROUP_BRAINPOOLP512R1)
         {
            acceptable = TRUE;
         }
         else
         {
         }
      }
   }
   else
#endif
#if (TLS_SM2_SIGN_SUPPORT == ENABLED)
   //SM2 certificate?
   if(cert->type == TLS_CERT_SM2_SIGN)
   {
      //TLS 1.3 currently selected?
      if(context->version >= TLS_VERSION_1_3)
      {
         //Check signature scheme
         if(signScheme == TLS_SIGN_SCHEME_SM2SIG_SM3)
         {
            acceptable = TRUE;
         }
      }
   }
   else
#endif
#if (TLS_ED25519_SIGN_SUPPORT == ENABLED)
   //Ed25519 certificate?
   if(cert->type == TLS_CERT_ED25519_SIGN)
   {
      //TLS 1.2 or TLS 1.3 currently selected?
      if(context->version >= TLS_VERSION_1_2)
      {
         //Check signature scheme
         if(signScheme == TLS_SIGN_SCHEME_ED25519)
         {
            acceptable = TRUE;
         }
      }
   }
   else
#endif
#if (TLS_ED448_SIGN_SUPPORT == ENABLED)
   //Ed448 certificate?
   if(cert->type == TLS_CERT_ED448_SIGN)
   {
      //TLS 1.2 or TLS 1.3 currently selected?
      if(context->version >= TLS_VERSION_1_2)
      {
         //Check signature scheme
         if(signScheme == TLS_SIGN_SCHEME_ED448)
         {
            acceptable = TRUE;
         }
      }
   }
   else
#endif
   //Unsupported certificate type?
   {
      //Just for sanity
   }

   //Return TRUE is the signature algorithm is compatible with the key in the
   //end-entity certificate
   return acceptable;
}


/**
 * @brief Check whether a signature algorithm can be used for digital signatures
 * @param[in] context Pointer to the TLS context
 * @param[in] signScheme Signature scheme
 * @return TRUE if the signature algorithm is supported, else FALSE
 **/

bool_t tlsIsSignAlgoSupported(TlsContext *context, uint16_t signScheme)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   uint_t i;
   uint_t cipherSuiteTypes;
   TlsHashAlgo hashAlgoId;
   const HashAlgo *hashAlgo;

   //Hash algorithm used by the signature scheme
   hashAlgoId = TLS_HASH_ALGO_NONE;

   //Check TLS version
   if(context->version <= TLS_VERSION_1_2)
   {
      //Check current state
      if(context->state == TLS_STATE_CERTIFICATE_REQUEST ||
         context->state == TLS_STATE_CLIENT_CERTIFICATE_VERIFY)
      {
         cipherSuiteTypes = TLS_CIPHER_SUITE_TYPE_RSA |
            TLS_CIPHER_SUITE_TYPE_DSA | TLS_CIPHER_SUITE_TYPE_ECDSA;
      }
      else
      {
         cipherSuiteTypes = context->cipherSuiteTypes;
      }
   }
   else
   {
      cipherSuiteTypes = context->cipherSuiteTypes;
   }

#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
   //RSASSA-PKCS1-v1_5 signature algorithm?
   if(TLS_SIGN_ALGO(signScheme) == TLS_SIGN_ALGO_RSA)
   {
      //Any RSA cipher suite proposed by the client?
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_RSA) != 0 ||
         (cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         //Filter out hash algorithm
         if(TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_MD5 ||
            TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA1 ||
            TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA224 ||
            TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA256 ||
            TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA384 ||
            TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA512)
         {
            //Check whether the hash algorithm is supported
            if(tlsGetHashAlgo(TLS_HASH_ALGO(signScheme)) != NULL)
            {
               hashAlgoId = TLS_HASH_ALGO(signScheme);
            }
         }
      }
   }
   else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
   //DSA signature algorithm?
   if(TLS_SIGN_ALGO(signScheme) == TLS_SIGN_ALGO_DSA)
   {
      //Any DSA cipher suite proposed by the client?
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_DSA) != 0 ||
         (cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         //Filter out hash algorithm
         if(TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA1 ||
            TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA224 ||
            TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA256)
         {
            //Check whether the hash algorithm is supported
            if(tlsGetHashAlgo(TLS_HASH_ALGO(signScheme)) != NULL)
            {
               hashAlgoId = TLS_HASH_ALGO(signScheme);
            }
         }
      }
   }
   else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   //ECDSA signature algorithm?
   if(TLS_SIGN_ALGO(signScheme) == TLS_SIGN_ALGO_ECDSA)
   {
      //Any ECC cipher suite proposed by the client?
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_ECDSA) != 0 ||
         (cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         //Filter out hash algorithm
         if(TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA1 ||
            TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA224 ||
            TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA256 ||
            TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA384 ||
            TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA512)
         {
            //Check whether the hash algorithm is supported
            if(tlsGetHashAlgo(TLS_HASH_ALGO(signScheme)) != NULL)
            {
               hashAlgoId = TLS_HASH_ALGO(signScheme);
            }
         }
      }
   }
   else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED && TLS_SHA256_SUPPORT == ENABLED)
   //RSASSA-PSS RSAE signature algorithm with SHA-256?
   if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA256)
   {
      //Any RSA cipher suite proposed by the client?
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_RSA) != 0 ||
         (cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         hashAlgoId = TLS_HASH_ALGO_SHA256;
      }
   }
   else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED && TLS_SHA384_SUPPORT == ENABLED)
   //RSASSA-PSS RSAE signature algorithm with SHA-384?
   if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA384)
   {
      //Any RSA cipher suite proposed by the client?
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_RSA) != 0 ||
         (cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         hashAlgoId = TLS_HASH_ALGO_SHA384;
      }
   }
   else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED && TLS_SHA512_SUPPORT == ENABLED)
   //RSASSA-PSS RSAE signature algorithm with SHA-512?
   if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA512)
   {
      //Any RSA cipher suite proposed by the client?
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_RSA) != 0 ||
         (cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         hashAlgoId = TLS_HASH_ALGO_SHA512;
      }
   }
   else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED && TLS_SHA256_SUPPORT == ENABLED)
   //RSASSA-PSS PSS signature algorithm with SHA-256?
   if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA256)
   {
      //Any RSA cipher suite proposed by the client?
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_RSA) != 0 ||
         (cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         //Check whether the X.509 library can parse RSA-PSS certificates
         if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA_PSS))
         {
            hashAlgoId = TLS_HASH_ALGO_SHA256;
         }
      }
   }
   else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED && TLS_SHA384_SUPPORT == ENABLED)
   //RSASSA-PSS PSS signature algorithm with SHA-384?
   if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA384)
   {
      //Any RSA cipher suite proposed by the client?
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_RSA) != 0 ||
         (cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         //Check whether the X.509 library can parse RSA-PSS certificates
         if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA_PSS))
         {
            hashAlgoId = TLS_HASH_ALGO_SHA384;
         }
      }
   }
   else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED && TLS_SHA512_SUPPORT == ENABLED)
   //RSASSA-PSS PSS signature algorithm with SHA-512?
   if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA512)
   {
      //Any RSA cipher suite proposed by the client?
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_RSA) != 0 ||
         (cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         //Check whether the X.509 library can parse RSA-PSS certificates
         if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA_PSS))
         {
            hashAlgoId = TLS_HASH_ALGO_SHA512;
         }
      }
   }
   else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED && TLS_SHA256_SUPPORT == ENABLED && \
   TLS_BRAINPOOLP256R1_SUPPORT == ENABLED)
   //ECDSA signature algorithm with brainpoolP256 curve and SHA-256?
   if(signScheme == TLS_SIGN_SCHEME_ECDSA_BP256R1_TLS13_SHA256)
   {
      //Any TLS 1.3 cipher suite proposed by the client?
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         hashAlgoId = TLS_HASH_ALGO_SHA256;
      }
   }
   else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED && TLS_SHA384_SUPPORT == ENABLED && \
   TLS_BRAINPOOLP384R1_SUPPORT == ENABLED)
   //ECDSA signature algorithm with brainpoolP384 curve and SHA-384?
   if(signScheme == TLS_SIGN_SCHEME_ECDSA_BP384R1_TLS13_SHA384)
   {
      //Any TLS 1.3 cipher suite proposed by the client?
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         hashAlgoId = TLS_HASH_ALGO_SHA384;
      }
   }
   else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED && TLS_SHA512_SUPPORT == ENABLED && \
   TLS_BRAINPOOLP512R1_SUPPORT == ENABLED)
   //ECDSA signature algorithm with brainpoolP512 curve and SHA-512?
   if(signScheme == TLS_SIGN_SCHEME_ECDSA_BP512R1_TLS13_SHA512)
   {
      //Any TLS 1.3 cipher suite proposed by the client?
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         hashAlgoId = TLS_HASH_ALGO_SHA512;
      }
   }
   else
#endif
#if (TLS_SM2_SIGN_SUPPORT == ENABLED)
   //SM2 signature algorithm?
   if(signScheme == TLS_SIGN_SCHEME_SM2SIG_SM3)
   {
      //Any ShangMi cipher suite proposed by the client?
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_SM) != 0)
      {
         hashAlgoId = TLS_HASH_ALGO_INTRINSIC;
      }
   }
   else
#endif
#if (TLS_ED25519_SIGN_SUPPORT == ENABLED)
   //Ed25519 signature algorithm?
   if(signScheme == TLS_SIGN_SCHEME_ED25519)
   {
      //Any ECC cipher suite proposed by the client?
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_ECDSA) != 0 ||
         (cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         hashAlgoId = TLS_HASH_ALGO_INTRINSIC;
      }
   }
   else
#endif
#if (TLS_ED448_SIGN_SUPPORT == ENABLED)
   //Ed448 signature algorithm?
   if(signScheme == TLS_SIGN_SCHEME_ED448)
   {
      //Any ECC cipher suite proposed by the client?
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_ECDSA) != 0 ||
         (cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
      {
         hashAlgoId = TLS_HASH_ALGO_INTRINSIC;
      }
   }
   else
#endif
   {
      //Unknown signature algorithm
   }

   //Check TLS version
   if(context->version <= TLS_VERSION_1_2)
   {
      //Check current state
      if(context->state == TLS_STATE_CERTIFICATE_REQUEST ||
         context->state == TLS_STATE_CLIENT_CERTIFICATE_VERIFY)
      {
         //Get the hash algorithm that matches the specified identifier
         hashAlgo = tlsGetHashAlgo(hashAlgoId);

         //Check whether the hash algorithm is supported
         if(hashAlgo != NULL)
         {
            //In TLS versions prior to 1.3, the client implementation can only
            //generate a CertificateVerify using SHA-1 or the hash used by
            //the PRF. Supporting all hash algorithms would require the client
            //to maintain hashes for every possible signature algorithm that
            //the server may request...
            if(hashAlgoId != TLS_HASH_ALGO_SHA1 &&
               hashAlgo != context->cipherSuite.prfHashAlgo)
            {
               hashAlgoId = TLS_HASH_ALGO_NONE;
            }
         }
         else
         {
            hashAlgoId = TLS_HASH_ALGO_NONE;
         }
      }
   }

   //Restrict the use of certain signature algorithms
   if(context->numSupportedSignAlgos > 0)
   {
      //Loop through the list of allowed signature algorithms
      for(i = 0; i < context->numSupportedSignAlgos; i++)
      {
         //Compare signature schemes
         if(context->supportedSignAlgos[i] == signScheme)
            break;
      }

      //Check whether the use of the signature algorithm is restricted
      if(i >= context->numSupportedSignAlgos)
      {
         hashAlgoId = TLS_HASH_ALGO_NONE;
      }
   }

   //Return TRUE is the signature algorithm is supported
   return (hashAlgoId != TLS_HASH_ALGO_NONE) ? TRUE : FALSE;
#else
   //Not implemented
   return FALSE;
#endif
}


/**
 * @brief Check whether a signature algorithm can be used for X.509
 *   certificate validation
 * @param[in] signScheme Signature scheme
 * @return TRUE if the signature algorithm is supported, else FALSE
 **/

bool_t tlsIsCertSignAlgoSupported(uint16_t signScheme)
{
   bool_t acceptable;

   //Check signature scheme
   if(TLS_SIGN_ALGO(signScheme) == TLS_SIGN_ALGO_RSA)
   {
      //Check whether RSA signature algorithm is supported
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA))
      {
         //Check hash algorithm
         if(TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_MD5)
         {
            //RSASSA-PKCS1-v1_5 signature algorithm with MD5
            acceptable = x509IsHashAlgoSupported(X509_HASH_ALGO_MD5);
         }
         else if(TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA1)
         {
            //RSASSA-PKCS1-v1_5 signature algorithm with SHA-1
            acceptable = x509IsHashAlgoSupported(X509_HASH_ALGO_SHA1);
         }
         else if(TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA224)
         {
            //RSASSA-PKCS1-v1_5 signature algorithm with SHA-224
            acceptable = x509IsHashAlgoSupported(X509_HASH_ALGO_SHA224);
         }
         else if(TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA256)
         {
            //RSASSA-PKCS1-v1_5 signature algorithm with SHA-256
            acceptable = x509IsHashAlgoSupported(X509_HASH_ALGO_SHA256);
         }
         else if(TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA384)
         {
            //RSASSA-PKCS1-v1_5 signature algorithm with SHA-384
            acceptable = x509IsHashAlgoSupported(X509_HASH_ALGO_SHA384);
         }
         else if(TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA512)
         {
            //RSASSA-PKCS1-v1_5 signature algorithm with SHA-512
            acceptable = x509IsHashAlgoSupported(X509_HASH_ALGO_SHA512);
         }
         else
         {
            //Unknown hash algorithm
            acceptable = FALSE;
         }
      }
      else
      {
         //RSASSA-PKCS1-v1_5 signature algorithm is not supported
         acceptable = FALSE;
      }
   }
   else if(TLS_SIGN_ALGO(signScheme) == TLS_SIGN_ALGO_DSA)
   {
      //Check whether DSA signature algorithm is supported
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_DSA))
      {
         //Check hash algorithm
         if(TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA1)
         {
            //DSA signature algorithm with SHA-1
            acceptable = x509IsHashAlgoSupported(X509_HASH_ALGO_SHA1);
         }
         else if(TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA224)
         {
            //DSA signature algorithm with SHA-224
            acceptable = x509IsHashAlgoSupported(X509_HASH_ALGO_SHA224);
         }
         else if(TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA256)
         {
            //DSA signature algorithm with SHA-256
            acceptable = x509IsHashAlgoSupported(X509_HASH_ALGO_SHA256);
         }
         else
         {
            //Unknown hash algorithm
            acceptable = FALSE;
         }
      }
      else
      {
         //DSA signature algorithm is not supported
         acceptable = FALSE;
      }
   }
   else if(TLS_SIGN_ALGO(signScheme) == TLS_SIGN_ALGO_ECDSA)
   {
      //Check whether ECDSA signature algorithm is supported
      if(x509IsSignAlgoSupported(X509_SIGN_ALGO_ECDSA))
      {
         //Check hash algorithm
         if(TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA1)
         {
            //ECDSA signature algorithm with SHA-1
            acceptable = x509IsHashAlgoSupported(X509_HASH_ALGO_SHA1);
         }
         else if(TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA224)
         {
            //ECDSA signature algorithm with SHA-224
            acceptable = x509IsHashAlgoSupported(X509_HASH_ALGO_SHA224);
         }
         else if(TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA256)
         {
            //ECDSA signature algorithm with SHA-256
            acceptable = x509IsHashAlgoSupported(X509_HASH_ALGO_SHA256);
         }
         else if(TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA384)
         {
            //ECDSA signature algorithm with SHA-384
            acceptable = x509IsHashAlgoSupported(X509_HASH_ALGO_SHA384);
         }
         else if(TLS_HASH_ALGO(signScheme) == TLS_HASH_ALGO_SHA512)
         {
            //ECDSA signature algorithm with SHA-512
            acceptable = x509IsHashAlgoSupported(X509_HASH_ALGO_SHA512);
         }
         else
         {
            //Unknown hash algorithm
            acceptable = FALSE;
         }
      }
      else
      {
         //ECDSA signature algorithm is not supported
         acceptable = FALSE;
      }
   }
   else if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA256 ||
      signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA256)
   {
      //RSASSA-PSS signature algorithm with SHA-256
      acceptable = x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA_PSS) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA256);
   }
   else if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA384 ||
      signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA384)
   {
      //RSASSA-PSS signature algorithm with SHA-384
      acceptable = x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA_PSS) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA384);
   }
   else if(signScheme == TLS_SIGN_SCHEME_RSA_PSS_RSAE_SHA512 ||
      signScheme == TLS_SIGN_SCHEME_RSA_PSS_PSS_SHA512)
   {
      //RSASSA-PSS signature algorithm with SHA-512
      acceptable = x509IsSignAlgoSupported(X509_SIGN_ALGO_RSA_PSS) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA512);
   }
#if (EC_SUPPORT == ENABLED)
   else if(signScheme == TLS_SIGN_SCHEME_ECDSA_BP256R1_TLS13_SHA256)
   {
      //ECDSA signature algorithm with brainpoolP256 curve and SHA-256
      acceptable = x509IsSignAlgoSupported(X509_SIGN_ALGO_ECDSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA256) &&
         x509IsCurveSupported(BRAINPOOLP256R1_OID, sizeof(BRAINPOOLP256R1_OID));
   }
   else if(signScheme == TLS_SIGN_SCHEME_ECDSA_BP384R1_TLS13_SHA384)
   {
      //ECDSA signature algorithm with brainpoolP384 curve and SHA-384
      acceptable = x509IsSignAlgoSupported(X509_SIGN_ALGO_ECDSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA384) &&
         x509IsCurveSupported(BRAINPOOLP384R1_OID, sizeof(BRAINPOOLP384R1_OID));
   }
   else if(signScheme == TLS_SIGN_SCHEME_ECDSA_BP512R1_TLS13_SHA512)
   {
      //ECDSA signature algorithm with brainpoolP512 curve and SHA-512
      acceptable = x509IsSignAlgoSupported(X509_SIGN_ALGO_ECDSA) &&
         x509IsHashAlgoSupported(X509_HASH_ALGO_SHA512) &&
         x509IsCurveSupported(BRAINPOOLP512R1_OID, sizeof(BRAINPOOLP512R1_OID));
   }
#endif
   else if(signScheme == TLS_SIGN_SCHEME_SM2SIG_SM3)
   {
      //SM2 signature algorithm
      acceptable = x509IsSignAlgoSupported(X509_SIGN_ALGO_SM2);
   }
   else if(signScheme == TLS_SIGN_SCHEME_ED25519)
   {
      //Ed25519 signature algorithm (PureEdDSA mode)
      acceptable = x509IsSignAlgoSupported(X509_SIGN_ALGO_ED25519);
   }
   else if(signScheme == TLS_SIGN_SCHEME_ED448)
   {
      //Ed448 signature algorithm (PureEdDSA mode)
      acceptable = x509IsSignAlgoSupported(X509_SIGN_ALGO_ED448);
   }
   else
   {
      //Unknown signature algorithm
      acceptable = FALSE;
   }

   //Return TRUE is the signature algorithm is supported
   return acceptable;
}

#endif
