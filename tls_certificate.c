/**
 * @file tls_certificate.c
 * @brief Certificate handling
 *
 * @section License
 *
 * Copyright (C) 2010-2018 Oryx Embedded SARL. All rights reserved.
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
 * @version 1.8.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include <string.h>
#include <ctype.h>
#include "tls.h"
#include "tls_certificate.h"
#include "tls_misc.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "certificate/pem_import.h"
#include "certificate/x509_cert_parse.h"
#include "certificate/x509_cert_validate.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Format certificate chain
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the certificate chain
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatCertificateList(TlsContext *context, uint8_t *p,
   size_t *written)
{
   error_t error;
   size_t n;
   const char_t *pemCert;
   size_t pemCertLen;
   uint8_t *derCert;
   size_t derCertSize;
   size_t derCertLen;

   //Initialize status code
   error = NO_ERROR;

   //Length of the certificate list in bytes
   n = 0;

   //Check whether a certificate is available
   if(context->cert != NULL)
   {
      //Point to the certificate chain
      pemCert = context->cert->certChain;
      //Get the total length, in bytes, of the certificate chain
      pemCertLen = context->cert->certChainLen;
   }
   else
   {
      //If no suitable certificate is available, the message contains
      //an empty certificate list
      pemCert = NULL;
      pemCertLen = 0;
   }

   //DER encoded certificate
   derCert = NULL;
   derCertSize = 0;
   derCertLen = 0;

   //Parse the certificate chain
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

      //Total length of the certificate list
      n += derCertLen + 3;

      //Prevent the buffer from overflowing
      if((n + sizeof(TlsCertificate)) > context->txBufferMaxLen)
      {
         //Report an error
         error = ERROR_MESSAGE_TOO_LONG;
         break;
      }

      //Each certificate is preceded by a 3-byte length field
      STORE24BE(derCertLen, p);
      //Copy the current certificate
      memcpy(p + 3, derCert, derCertLen);

      //Advance data pointer
      p += derCertLen + 3;
   }

   //Free previously allocated memory
   tlsFreeMem(derCert);

   //Total number of bytes that have been written
   *written = n;

   //Return status code
   return error;
}


/**
 * @brief Format raw public key
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the raw public key
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatRawPublicKey(TlsContext *context, uint8_t *p,
   size_t *written)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //Check whether a certificate is available
   if(context->cert != NULL)
   {
      const char_t *pemCert;
      size_t pemCertLen;
      uint8_t *derCert;
      size_t derCertSize;
      size_t derCertLen;
      X509CertificateInfo *certInfo;

      //Point to the certificate chain
      pemCert = context->cert->certChain;
      //Get the total length, in bytes, of the certificate chain
      pemCertLen = context->cert->certChainLen;

      //DER encoded certificate
      derCert = NULL;
      derCertSize = 0;
      derCertLen = 0;

      //Start of exception handling block
      do
      {
         //Allocate a memory buffer to store X.509 certificate info
         certInfo = tlsAllocMem(sizeof(X509CertificateInfo));
         //Failed to allocate memory?
         if(certInfo == NULL)
         {
            error = ERROR_OUT_OF_MEMORY;
            break;
         }

         //Decode end entity certificate
         error = pemImportCertificate(&pemCert, &pemCertLen,
            &derCert, &derCertSize, &derCertLen);
         //Any error to report?
         if(error)
            break;

         //Parse X.509 certificate
         error = x509ParseCertificate(derCert, derCertLen, certInfo);
         //Failed to parse the X.509 certificate?
         if(error)
            break;

         //Copy the raw public key
         memcpy(p, certInfo->subjectPublicKeyInfo.rawData,
            certInfo->subjectPublicKeyInfo.rawDataLen);

         //Total number of bytes that have been written
         *written = certInfo->subjectPublicKeyInfo.rawDataLen;

         //End of exception handling block
      } while(0);

      //Release previously allocated memory
      tlsFreeMem(derCert);
      tlsFreeMem(certInfo);
   }
   else
#endif
   {
      //If no suitable certificate is available, the message contains
      //an empty certificate list
      *written = 0;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse certificate chain
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the certificate chain
 * @param[in] length Number of bytes available in the input stream
 * @return Error code
 **/

error_t tlsParseCertificateList(TlsContext *context, const uint8_t *p,
   size_t length)
{
   error_t error;
   uint_t i;
   size_t n;
   bool_t validCertChain;
   const char_t *subjectName;
   X509CertificateInfo *certInfo;
   X509CertificateInfo *issuerCertInfo;

   //Initialize X.509 certificates
   certInfo = NULL;
   issuerCertInfo = NULL;

   //Start of exception handling block
   do
   {
      //Assume an error...
      error = ERROR_OUT_OF_MEMORY;

      //Allocate a memory buffer to store X.509 certificate info
      certInfo = tlsAllocMem(sizeof(X509CertificateInfo));
      //Failed to allocate memory?
      if(certInfo == NULL)
         break;

      //Allocate a memory buffer to store the parent certificate
      issuerCertInfo = tlsAllocMem(sizeof(X509CertificateInfo));
      //Failed to allocate memory?
      if(issuerCertInfo == NULL)
         break;

      //The end-user certificate is preceded by a 3-byte length field
      if(length < 3)
      {
         //Report an error
         error = ERROR_DECODING_FAILED;
         break;
      }

      //Get the size occupied by the certificate
      n = LOAD24BE(p);
      //Jump to the beginning of the DER encoded certificate
      p += 3;
      length -= 3;

      //Malformed Certificate message?
      if(n > length)
      {
         //Report an error
         error = ERROR_DECODING_FAILED;
         break;
      }

      //Display ASN.1 structure
      error = asn1DumpObject(p, n, 0);
      //Any error to report?
      if(error)
         break;

      //Parse end-user certificate
      error = x509ParseCertificate(p, n, certInfo);
      //Failed to parse the X.509 certificate?
      if(error)
      {
         //Report an error
         error = ERROR_DECODING_FAILED;
         break;
      }

      //Check certificate key usage
      error = tlsCheckKeyUsage(certInfo, context->entity,
         context->keyExchMethod);
      //Any error to report?
      if(error)
         break;

      //Extract the public key from the end-user certificate
      error = tlsReadSubjectPublicKey(context, &certInfo->subjectPublicKeyInfo);
      //Any error to report?
      if(error)
         break;

#if (TLS_CLIENT_SUPPORT == ENABLED)
      //TLS operates as a client?
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //Point to the subject name
         subjectName = context->serverName;

         //Check the subject name in the server certificate against the actual
         //FQDN name that is being requested
         error = x509CheckSubjectName(certInfo, subjectName);
         //Any error to report?
         if(error)
         {
            //Debug message
            TRACE_WARNING("Server name mismatch!\r\n");

            //Report an error
            error = ERROR_BAD_CERTIFICATE;
            break;
         }
      }
      else
#endif
      //TLS operates as a server?
      {
         //Do not check name constraints
         subjectName = NULL;
      }

      //Test if the end-user certificate matches a trusted CA
      validCertChain = tlsIsCertificateValid(certInfo, context->trustedCaList,
         context->trustedCaListLen, 0, subjectName);

      //Next certificate
      p += n;
      length -= n;

      //PKIX path validation
      for(i = 0; length > 0; i++)
      {
         //Each intermediate certificate is preceded by a 3-byte length field
         if(length < 3)
         {
            //Report an error
            error = ERROR_DECODING_FAILED;
            break;
         }

         //Get the size occupied by the certificate
         n = LOAD24BE(p);
         //Jump to the beginning of the DER encoded certificate
         p += 3;
         length -= 3;

         //Malformed Certificate message?
         if(n > length)
         {
            //Report an error
            error = ERROR_DECODING_FAILED;
            break;
         }

         //Display ASN.1 structure
         error = asn1DumpObject(p, n, 0);
         //Any error to report?
         if(error)
            break;

         //Parse intermediate certificate
         error = x509ParseCertificate(p, n, issuerCertInfo);
         //Failed to parse the X.509 certificate?
         if(error)
         {
            //Report an error
            error = ERROR_DECODING_FAILED;
            break;
         }

         //Certificate chain validation in progress?
         if(!validCertChain)
         {
            //Validate current certificate
            error = x509ValidateCertificate(certInfo, issuerCertInfo, i);
            //Certificate validation failed?
            if(error)
               break;

            //Check name constraints
            error = x509CheckNameConstraints(subjectName, issuerCertInfo);
            //Should the application reject the certificate?
            if(error)
               return ERROR_BAD_CERTIFICATE;

            //Check the version of the certificate
            if(issuerCertInfo->version < X509_VERSION_3)
            {
               //Conforming implementations may choose to reject all version 1
               //and version 2 intermediate certificates (refer to RFC 5280,
               //section 6.1.4)
               error = ERROR_BAD_CERTIFICATE;
               break;
            }

            //Test if the intermediate certificate matches a trusted CA
            validCertChain = tlsIsCertificateValid(issuerCertInfo,
               context->trustedCaList, context->trustedCaListLen, i, subjectName);
         }

         //Keep track of the issuer certificate
         *certInfo = *issuerCertInfo;

         //Next certificate
         p += n;
         length -= n;
      }

      //Check status code
      if(!error)
      {
         //Certificate chain validation failed?
         if(!validCertChain)
         {
            //A valid certificate chain or partial chain was received, but the
            //certificate was not accepted because the CA certificate could not
            //be matched with a known, trusted CA
            error = ERROR_UNKNOWN_CA;
         }
      }

      //End of exception handling block
   } while(0);

   //Free previously allocated memory
   tlsFreeMem(certInfo);
   tlsFreeMem(issuerCertInfo);

   //Return status code
   return error;
}


/**
 * @brief Parse raw public key
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the raw public key
 * @param[in] length Number of bytes available in the input stream
 * @return Error code
 **/

error_t tlsParseRawPublicKey(TlsContext *context, const uint8_t *p,
   size_t length)
{
   error_t error;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //Any registered callback?
   if(context->rpkVerifyCallback != NULL)
   {
      size_t n;
      X509SubjectPublicKeyInfo subjectPublicKeyInfo;

      //The payload of the Certificate message contains a SubjectPublicKeyInfo
      //structure
      error = x509ParseSubjectPublicKeyInfo(p, length, &n, &subjectPublicKeyInfo);

      //Check status code
      if(!error)
      {
         //Extract the public key from the SubjectPublicKeyInfo structure
         error = tlsReadSubjectPublicKey(context, &subjectPublicKeyInfo);
      }

      //Check status code
      if(!error)
      {
         //When raw public keys are used, authentication of the peer
         //is supported only through authentication of the received
         //SubjectPublicKeyInfo via an out-of-band method
         error = context->rpkVerifyCallback(context, p, length);
      }
   }
   else
#endif
   {
      //Report an error
      error = ERROR_BAD_CERTIFICATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Check whether a certificate is acceptable
 * @param[in] cert End entity certificate
 * @param[in] certTypes List of supported certificate types
 * @param[in] numCertTypes Size of the list that contains the supported certificate types
 * @param[in] signHashAlgos List of supported signature algorithms
 * @param[in] curveList List of supported elliptic curves
 * @param[in] certAuthorities List of trusted CA
 * @return TRUE if the specified certificate conforms to the requirements, else FALSE
 **/

bool_t tlsIsCertificateAcceptable(const TlsCertDesc *cert,
   const uint8_t *certTypes, size_t numCertTypes, const TlsSignHashAlgos *signHashAlgos,
   const TlsSupportedGroupList *curveList, const TlsCertAuthorities *certAuthorities)
{
   size_t i;
   size_t n;
   size_t length;
   bool_t acceptable;

   //Make sure that a valid certificate has been loaded
   if(cert->certChain == NULL || cert->certChainLen == 0)
      return FALSE;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
   //RSA certificate?
   if(cert->type == TLS_CERT_RSA_SIGN)
   {
      //This flag tells whether the certificate is acceptable
      acceptable = TRUE;

      //Filter out certificates with unsupported type
      if(numCertTypes > 0)
      {
         //Loop through the list of supported certificate types
         for(acceptable = FALSE, i = 0; i < numCertTypes; i++)
         {
            //Check whether the certificate type is acceptable
            if(certTypes[i] == TLS_CERT_RSA_SIGN)
            {
               acceptable = TRUE;
               break;
            }
         }
      }

      //Filter out certificates that are signed with an unsupported
      //hash/signature algorithm
      if(acceptable && signHashAlgos != NULL)
      {
         //Retrieve the number of items in the list
         n = ntohs(signHashAlgos->length) / sizeof(TlsSignHashAlgo);

         //Loop through the list of supported hash/signature algorithm pairs
         for(acceptable = FALSE, i = 0; i < n; i++)
         {
#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
            //RSASSA-PKCS1-v1_5 signature scheme?
            if(signHashAlgos->value[i].signature == TLS_SIGN_ALGO_RSA &&
               signHashAlgos->value[i].hash == cert->hashAlgo)
            {
               acceptable = TRUE;
               break;
            }
            else
#endif
#if (TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
            //RSASSA-PSS RSAE signature scheme with SHA-256?
            if(signHashAlgos->value[i].signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256 &&
               signHashAlgos->value[i].hash == TLS_HASH_ALGO_INTRINSIC)
            {
               acceptable = TRUE;
               break;
            }
            //RSASSA-PSS RSAE signature scheme with SHA-384?
            else if(signHashAlgos->value[i].signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384 &&
               signHashAlgos->value[i].hash == TLS_HASH_ALGO_INTRINSIC)
            {
               acceptable = TRUE;
               break;
            }
            //RSASSA-PSS RSAE signature scheme with SHA-512?
            else if(signHashAlgos->value[i].signature == TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512 &&
               signHashAlgos->value[i].hash == TLS_HASH_ALGO_INTRINSIC)
            {
               acceptable = TRUE;
               break;
            }
            else
#endif
            //Unknown RSA signature scheme?
            {
               //Just for sanity
               acceptable = FALSE;
            }
         }
      }
   }
   else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
   //DSA certificate?
   if(cert->type == TLS_CERT_DSS_SIGN)
   {
      //This flag tells whether the certificate is acceptable
      acceptable = TRUE;

      //Filter out certificates with unsupported type
      if(numCertTypes > 0)
      {
         //Loop through the list of supported certificate types
         for(acceptable = FALSE, i = 0; i < numCertTypes; i++)
         {
            //Check whether the certificate type is acceptable
            if(certTypes[i] == TLS_CERT_DSS_SIGN)
            {
               acceptable = TRUE;
               break;
            }
         }
      }

      //Filter out certificates that are signed with an unsupported
      //hash/signature algorithm
      if(acceptable && signHashAlgos != NULL)
      {
         //Retrieve the number of items in the list
         n = ntohs(signHashAlgos->length) / sizeof(TlsSignHashAlgo);

         //Loop through the list of supported hash/signature algorithm pairs
         for(acceptable = FALSE, i = 0; i < n; i++)
         {
            //The certificate must be signed using a valid hash algorithm
            if(signHashAlgos->value[i].signature == TLS_SIGN_ALGO_DSA &&
               signHashAlgos->value[i].hash == cert->hashAlgo)
            {
               acceptable = TRUE;
               break;
            }
         }
      }
   }
   else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   //ECDSA certificate?
   if(cert->type == TLS_CERT_ECDSA_SIGN)
   {
      //This flag tells whether the certificate is acceptable
      acceptable = TRUE;

      //Filter out certificates with unsupported type
      if(numCertTypes > 0)
      {
         //Loop through the list of supported certificate types
         for(acceptable = FALSE, i = 0; i < numCertTypes; i++)
         {
            //Check whether the certificate type is acceptable
            if(certTypes[i] == TLS_CERT_ECDSA_SIGN)
            {
               acceptable = TRUE;
               break;
            }
         }
      }

      //Filter out ECDSA certificates that use an unsupported elliptic curve
      if(acceptable && curveList != NULL)
      {
         //Retrieve the number of items in the list
         n = ntohs(curveList->length) / sizeof(uint16_t);

         //Loop through the list of supported elliptic curves
         for(acceptable = FALSE, i = 0; i < n; i++)
         {
            //Check whether the elliptic curve is supported
            if(ntohs(curveList->value[i]) == cert->namedCurve)
            {
               acceptable = TRUE;
               break;
            }
         }
      }

      //Filter out certificates that are signed with an unsupported
      //hash/signature algorithm
      if(acceptable && signHashAlgos != NULL)
      {
         //Retrieve the number of items in the list
         n = ntohs(signHashAlgos->length) / sizeof(TlsSignHashAlgo);

         //Loop through the list of supported hash/signature algorithm pairs
         for(acceptable = FALSE, i = 0; i < n; i++)
         {
            //The certificate must be signed using a valid hash algorithm
            if(signHashAlgos->value[i].signature == TLS_SIGN_ALGO_ECDSA &&
               signHashAlgos->value[i].hash == cert->hashAlgo)
            {
               acceptable = TRUE;
               break;
            }
         }
      }
   }
   else
#endif
#if (TLS_ED25519_SUPPORT == ENABLED || TLS_ED448_SUPPORT == ENABLED)
   //EdDSA certificate?
   if(cert->type == TLS_CERT_ED25519_SIGN ||
      cert->type == TLS_CERT_ED448_SIGN)
   {
      //Filter out certificates with unsupported type
      for(acceptable = FALSE, i = 0; i < numCertTypes; i++)
      {
         //Check whether the certificate type is acceptable
         if(certTypes[i] == TLS_CERT_ECDSA_SIGN)
         {
            acceptable = TRUE;
            break;
         }
      }

      //Make sure EdDSA signature scheme is supported
      if(acceptable && signHashAlgos != NULL)
      {
         //Retrieve the number of items in the list
         n = ntohs(signHashAlgos->length) / sizeof(TlsSignHashAlgo);

         //Loop through the list of supported signature schemes
         for(acceptable = FALSE, i = 0; i < n; i++)
         {
            //Ed25519 certificate?
            if(cert->type == TLS_CERT_ED25519_SIGN)
            {
               //Check whether Ed25519 signature scheme is supported
               if(signHashAlgos->value[i].signature == TLS_SIGN_ALGO_ED25519 &&
                  signHashAlgos->value[i].hash == TLS_HASH_ALGO_INTRINSIC)
               {
                  acceptable = TRUE;
                  break;
               }
            }
            //Ed448 certificate?
            else if(cert->type == TLS_CERT_ED448_SIGN)
            {
               //Check whether Ed448 signature scheme is supported
               if(signHashAlgos->value[i].signature == TLS_SIGN_ALGO_ED448 &&
                  signHashAlgos->value[i].hash == TLS_HASH_ALGO_INTRINSIC)
               {
                  acceptable = TRUE;
                  break;
               }
            }
         }
      }
      else
      {
         //The certificate is not acceptable
         acceptable = FALSE;
      }
   }
   else
#endif
   //Unsupported certificate type?
   {
      //The certificate is not acceptable
      acceptable = FALSE;
   }

   //Filter out certificates that are issued by a non trusted CA
   if(acceptable && certAuthorities != NULL)
   {
      //Retrieve the length of the list
      length = ntohs(certAuthorities->length);

      //If the certificate authorities list is empty, then the client
      //may send any certificate of the appropriate type
      if(length > 0)
      {
         error_t error;
         const uint8_t *p;
         const char_t *pemCert;
         size_t pemCertLen;
         uint8_t *derCert;
         size_t derCertSize;
         size_t derCertLen;
         X509CertificateInfo *certInfo;

         //The list of acceptable certificate authorities describes the
         //known roots CA
         acceptable = FALSE;

         //Point to the first distinguished name
         p = certAuthorities->value;

         //Point to the end entity certificate
         pemCert = cert->certChain;
         //Get the total length, in bytes, of the certificate chain
         pemCertLen = cert->certChainLen;

         //DER encoded certificate
         derCert = NULL;
         derCertSize = 0;
         derCertLen = 0;

         //Start of exception handling block
         do
         {
            //Allocate a memory buffer to store X.509 certificate info
            certInfo = tlsAllocMem(sizeof(X509CertificateInfo));
            //Failed to allocate memory?
            if(certInfo == NULL)
               break;

            //Point to the last certificate of the chain
            do
            {
               //Read PEM certificates, one by one
               error = pemImportCertificate(&pemCert, &pemCertLen,
                  &derCert, &derCertSize, &derCertLen);

               //Loop as long as necessary
            } while(!error);

            //Any error to report?
            if(error != ERROR_END_OF_FILE)
               break;

            //Parse the last certificate of the chain
            error = x509ParseCertificate(derCert, derCertLen, certInfo);
            //Failed to parse the X.509 certificate?
            if(error)
               break;

            //Parse each distinguished name of the list
            while(length > 0)
            {
               //Sanity check
               if(length < 2)
                  break;

               //Each distinguished name is preceded by a 2-byte length field
               n = LOAD16BE(p);

               //Make sure the length field is valid
               if(length < (n + 2))
                  break;

               //Check if the distinguished name matches the root CA
               if(x509CompareName(p + 2, n, certInfo->issuer.rawData,
                  certInfo->issuer.rawDataLen))
               {
                  acceptable = TRUE;
                  break;
               }

               //Advance data pointer
               p += n + 2;
               //Number of bytes left in the list
               length -= n + 2;
            }

            //End of exception handling block
         } while(0);

         //Release previously allocated memory
         tlsFreeMem(derCert);
         tlsFreeMem(certInfo);
      }
   }

   //The return value specifies whether all the criteria were matched
   return acceptable;
}


/**
 * @brief Verify certificate against root CAs
 * @param[in] certInfo X.509 certificate to be verified
 * @param[in] trustedCaList List of trusted CA (PEM format)
 * @param[in] trustedCaListLen Total length of the list
 * @param[in] pathLength Certificate path length
 * @param[in] subjectName Subject name (optional parameter)
 * @return TRUE if the certificate is issued by a trusted CA, else FALSE
 **/

bool_t tlsIsCertificateValid(const X509CertificateInfo *certInfo,
   const char_t *trustedCaList, size_t trustedCaListLen,
   uint_t pathLength, const char_t *subjectName)
{
   error_t error;
   bool_t valid;
   uint8_t *derCert;
   size_t derCertSize;
   size_t derCertLen;
   X509CertificateInfo *caCertInfo;

   //DER encoded certificate
   derCert = NULL;
   derCertSize = 0;
   derCertLen = 0;

   //Allocate a memory buffer to store the root CA
   caCertInfo = tlsAllocMem(sizeof(X509CertificateInfo));
   //Failed to allocate memory?
   if(caCertInfo == NULL)
      return FALSE;

   //Check whether certificates should be checked against root CAs
   if(trustedCaListLen > 0)
   {
      //Initialize flag
      valid = FALSE;

      //Loop through the root CAs
      while(trustedCaListLen > 0)
      {
         //Decode PEM certificate
         error = pemImportCertificate(&trustedCaList, &trustedCaListLen,
            &derCert, &derCertSize, &derCertLen);
         //Any error to report?
         if(error)
            break;

         //Parse X.509 certificate
         error = x509ParseCertificate(derCert, derCertLen, caCertInfo);
         //Failed to parse the X.509 certificate?
         if(error)
            break;

         //Validate the certificate with the current CA
         error = x509ValidateCertificate(certInfo, caCertInfo, pathLength);

         //Certificate validation succeeded?
         if(!error)
         {
            //Check name constraints
            error = x509CheckNameConstraints(subjectName, caCertInfo);
         }

         //Acceptable name constraints?
         if(!error)
         {
            //The certificate is issued by a trusted CA
            valid = TRUE;
            //We are done
            break;
         }
      }
   }
   else
   {
      //Do not check certificates against root CAs
      valid = TRUE;
   }

   //Free previously allocated memory
   tlsFreeMem(derCert);
   tlsFreeMem(caCertInfo);

   //The return value specifies whether the certificate is issued by a
   //trusted CA
   return valid;
}


/**
 * @brief Retrieve the certificate type
 * @param[in] certInfo X.509 certificate
 * @param[out] certType Certificate type
 * @param[out] certSignAlgo Signature algorithm that has been used to sign the certificate
 * @param[out] certHashAlgo Hash algorithm that has been used to sign the certificate
 * @param[out] namedCurve Elliptic curve (only for ECDSA certificates)
 * @return Error code
 **/

error_t tlsGetCertificateType(const X509CertificateInfo *certInfo,
   TlsCertificateType *certType, TlsSignatureAlgo *certSignAlgo,
   TlsHashAlgo *certHashAlgo, TlsNamedGroup *namedCurve)
{
   size_t oidLen;
   const uint8_t *oid;

   //Check parameters
   if(certInfo == NULL || certType == NULL || certSignAlgo == NULL ||
      certHashAlgo == NULL || namedCurve == NULL)
   {
      //Report an error
      return ERROR_INVALID_PARAMETER;
   }

   //Point to the public key identifier
   oid = certInfo->subjectPublicKeyInfo.oid;
   oidLen = certInfo->subjectPublicKeyInfo.oidLen;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_PSS_SIGN_SUPPORT == ENABLED || \
   TLS_RSA_SUPPORT == ENABLED || TLS_DHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_RSA_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED)
   //RSA public key?
   if(!oidComp(oid, oidLen, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)))
   {
      //Save certificate type
      *certType = TLS_CERT_RSA_SIGN;
      //Elliptic curve cryptography is not used
      *namedCurve = TLS_GROUP_NONE;
   }
   else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED || TLS_DHE_DSS_SUPPORT == ENABLED)
   //DSA public key?
   if(!oidComp(oid, oidLen, DSA_OID, sizeof(DSA_OID)))
   {
      //Save certificate type
      *certType = TLS_CERT_DSS_SIGN;
      //Elliptic curve cryptography is not used
      *namedCurve = TLS_GROUP_NONE;
   }
   else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED || TLS_ECDHE_ECDSA_SUPPORT == ENABLED)
   //EC public key?
   if(!oidComp(oid, oidLen, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      const X509EcParameters *params;

      //Point to the EC parameters
      params = &certInfo->subjectPublicKeyInfo.ecParams;

      //Save certificate type
      *certType = TLS_CERT_ECDSA_SIGN;
      //Retrieve the named curve that has been used to generate the EC public key
      *namedCurve = tlsGetNamedCurve(params->namedCurve, params->namedCurveLen);
   }
   else
#endif
#if (TLS_ED25519_SUPPORT == ENABLED)
   //Ed25519 public key?
   if(!oidComp(oid, oidLen, ED25519_OID, sizeof(ED25519_OID)))
   {
      //Save certificate type
      *certType = TLS_CERT_ED25519_SIGN;
      //No named curve applicable
      *namedCurve = TLS_GROUP_NONE;
   }
   else
#endif
#if (TLS_ED448_SUPPORT == ENABLED)
   //Ed448 public key?
   if(!oidComp(oid, oidLen, ED448_OID, sizeof(ED448_OID)))
   {
      //Save certificate type
      *certType = TLS_CERT_ED448_SIGN;
      //No named curve applicable
      *namedCurve = TLS_GROUP_NONE;
   }
   else
#endif
   //Invalid public key?
   {
      //The certificate does not contain any valid public key
      return ERROR_BAD_CERTIFICATE;
   }

   //Point to the signature algorithm
   oid = certInfo->signatureAlgo.data;
   oidLen = certInfo->signatureAlgo.length;

   //Retrieve the signature algorithm that has been used to sign the certificate
   if(oid == NULL || oidLen == 0)
   {
      //Invalid certificate
      return ERROR_BAD_CERTIFICATE;
   }
#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_PSS_SIGN_SUPPORT == ENABLED)
   else if(!oidComp(oid, oidLen, MD5_WITH_RSA_ENCRYPTION_OID,
      sizeof(MD5_WITH_RSA_ENCRYPTION_OID)))
   {
      //MD5 with RSA signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_RSA;
      *certHashAlgo = TLS_HASH_ALGO_MD5;
   }
   else if(!oidComp(oid, oidLen, SHA1_WITH_RSA_ENCRYPTION_OID,
      sizeof(SHA1_WITH_RSA_ENCRYPTION_OID)))
   {
      //SHA-1 with RSA signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_RSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA1;
   }
   else if(!oidComp(oid, oidLen, SHA256_WITH_RSA_ENCRYPTION_OID,
      sizeof(SHA256_WITH_RSA_ENCRYPTION_OID)))
   {
      //SHA-256 with RSA signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_RSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA256;
   }
   else if(!oidComp(oid, oidLen, SHA384_WITH_RSA_ENCRYPTION_OID,
      sizeof(SHA384_WITH_RSA_ENCRYPTION_OID)))
   {
      //SHA-384 with RSA signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_RSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA384;
   }
   else if(!oidComp(oid, oidLen, SHA512_WITH_RSA_ENCRYPTION_OID,
      sizeof(SHA512_WITH_RSA_ENCRYPTION_OID)))
   {
      //SHA-512 with RSA signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_RSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA512;
   }
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
   else if(!oidComp(oid, oidLen, DSA_WITH_SHA1_OID,
      sizeof(DSA_WITH_SHA1_OID)))
   {
      //DSA with SHA-1 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_DSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA1;
   }
   else if(!oidComp(oid, oidLen, DSA_WITH_SHA224_OID,
      sizeof(DSA_WITH_SHA224_OID)))
   {
      //DSA with SHA-224 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_DSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA224;
   }
   else if(!oidComp(oid, oidLen, DSA_WITH_SHA256_OID,
      sizeof(DSA_WITH_SHA256_OID)))
   {
      //DSA with SHA-256 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_DSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA256;
   }
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   else if(!oidComp(oid, oidLen, ECDSA_WITH_SHA1_OID,
      sizeof(ECDSA_WITH_SHA1_OID)))
   {
      //ECDSA with SHA-1 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_ECDSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA1;
   }
   else if(!oidComp(oid, oidLen, ECDSA_WITH_SHA224_OID,
      sizeof(ECDSA_WITH_SHA224_OID)))
   {
      //ECDSA with SHA-224 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_ECDSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA224;
   }
   else if(!oidComp(oid, oidLen, ECDSA_WITH_SHA256_OID,
      sizeof(ECDSA_WITH_SHA256_OID)))
   {
      //ECDSA with SHA-256 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_ECDSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA256;
   }
   else if(!oidComp(oid, oidLen, ECDSA_WITH_SHA384_OID,
      sizeof(ECDSA_WITH_SHA384_OID)))
   {
      //ECDSA with SHA-384 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_ECDSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA384;
   }
   else if(!oidComp(oid, oidLen, ECDSA_WITH_SHA512_OID,
      sizeof(ECDSA_WITH_SHA512_OID)))
   {
      //ECDSA with SHA-512 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_ECDSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA512;
   }
#endif
#if (TLS_ED25519_SUPPORT == ENABLED)
   else if(!oidComp(oid, oidLen, ED25519_OID, sizeof(ED25519_OID)))
   {
      //Ed25519 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_ED25519;
      *certHashAlgo = TLS_HASH_ALGO_INTRINSIC;
   }
#endif
#if (TLS_ED448_SUPPORT == ENABLED)
   else if(!oidComp(oid, oidLen, ED448_OID, sizeof(ED448_OID)))
   {
      //Ed448 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_ED448;
      *certHashAlgo = TLS_HASH_ALGO_INTRINSIC;
   }
#endif
   else
   {
      //The signature algorithm is not supported...
      return ERROR_BAD_CERTIFICATE;
   }

   //X.509 certificate successfully parsed
   return NO_ERROR;
}


/**
 * @brief Extract the subject public key from the received certificate
 * @param[in] context Pointer to the TLS context
 * @param[in] subjectPublicKeyInfo Pointer to the subject's public key
 * @return Error code
 **/

error_t tlsReadSubjectPublicKey(TlsContext *context,
   const X509SubjectPublicKeyInfo *subjectPublicKeyInfo)
{
   error_t error;
   size_t oidLen;
   const uint8_t *oid;

   //Retrieve public key identifier
   oid = subjectPublicKeyInfo->oid;
   oidLen = subjectPublicKeyInfo->oidLen;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_PSS_SIGN_SUPPORT == ENABLED || \
   TLS_RSA_SUPPORT == ENABLED || TLS_DHE_RSA_SUPPORT == ENABLED || \
   TLS_ECDHE_RSA_SUPPORT == ENABLED || TLS_RSA_PSK_SUPPORT == ENABLED)
   //RSA public key?
   if(!oidComp(oid, oidLen, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)))
   {
      uint_t k;

      //Retrieve the RSA public key
      error = x509ReadRsaPublicKey(subjectPublicKeyInfo,
         &context->peerRsaPublicKey);

      //Check status code
      if(!error)
      {
         //Get the length of the modulus, in bits
         k = mpiGetBitLength(&context->peerRsaPublicKey.n);

         //Make sure the modulus is acceptable
         if(k < TLS_MIN_RSA_MODULUS_SIZE || k > TLS_MAX_RSA_MODULUS_SIZE)
         {
            //Report an error
            error = ERROR_BAD_CERTIFICATE;
         }
      }

      //Check status code
      if(!error)
      {
         //The certificate contains a valid RSA public key
         context->peerCertType = TLS_CERT_RSA_SIGN;
      }
   }
   else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED || TLS_DHE_DSS_SUPPORT == ENABLED)
   //DSA public key?
   if(!oidComp(oid, oidLen, DSA_OID, sizeof(DSA_OID)))
   {
      uint_t k;

      //Retrieve the DSA public key
      error = x509ReadDsaPublicKey(subjectPublicKeyInfo,
         &context->peerDsaPublicKey);

      //Check status code
      if(!error)
      {
         //Get the length of the prime modulus, in bits
         k = mpiGetBitLength(&context->peerDsaPublicKey.p);

         //Make sure the prime modulus is acceptable
         if(k < TLS_MIN_DSA_MODULUS_SIZE || k > TLS_MAX_DSA_MODULUS_SIZE)
         {
            //Report an error
            error = ERROR_BAD_CERTIFICATE;
         }
      }

      //Check status code
      if(!error)
      {
         //The certificate contains a valid DSA public key
         context->peerCertType = TLS_CERT_DSS_SIGN;
      }
   }
   else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED || TLS_ECDHE_ECDSA_SUPPORT == ENABLED)
   //EC public key?
   if(!oidComp(oid, oidLen, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)) ||
      !oidComp(oid, oidLen, ED25519_OID, sizeof(ED25519_OID)) ||
      !oidComp(oid, oidLen, ED448_OID, sizeof(ED448_OID)))
   {
      const EcCurveInfo *curveInfo;

      //Ed25519 or Ed448 public key?
      if(!oidComp(oid, oidLen, ED25519_OID, sizeof(ED25519_OID)) ||
         !oidComp(oid, oidLen, ED448_OID, sizeof(ED448_OID)))
      {
         //Retrieve EC domain parameters
         curveInfo = x509GetCurveInfo(oid, oidLen);
      }
      else
      {
         //Retrieve EC domain parameters
         curveInfo = x509GetCurveInfo(subjectPublicKeyInfo->ecParams.namedCurve,
            subjectPublicKeyInfo->ecParams.namedCurveLen);
      }

      //Make sure the specified elliptic curve is supported
      if(curveInfo != NULL)
      {
         //Load EC domain parameters
         error = ecLoadDomainParameters(&context->peerEcParams, curveInfo);

         //Check status code
         if(!error)
         {
            //Retrieve the EC public key
            error = ecImport(&context->peerEcParams, &context->peerEcPublicKey,
               subjectPublicKeyInfo->ecPublicKey.q, subjectPublicKeyInfo->ecPublicKey.qLen);
         }
      }
      else
      {
         //The specified elliptic curve is not supported
         error = ERROR_BAD_CERTIFICATE;
      }

      //Check status code
      if(!error)
      {
         //The certificate contains a valid EC public key
         context->peerCertType = TLS_CERT_ECDSA_SIGN;
      }
   }
   else
#endif
   //Invalid public key?
   {
      //The certificate does not contain any valid public key
      error = ERROR_UNSUPPORTED_CERTIFICATE;
   }

#if (TLS_CLIENT_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //TLS operates as a client?
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //Check key exchange method
         if(context->keyExchMethod == TLS_KEY_EXCH_RSA ||
            context->keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
            context->keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
            context->keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
         {
            //The client expects a valid RSA certificate whenever the agreed-upon
            //key exchange method uses RSA certificates for authentication
            if(context->peerCertType != TLS_CERT_RSA_SIGN)
               error = ERROR_UNSUPPORTED_CERTIFICATE;
         }
         else if(context->keyExchMethod == TLS_KEY_EXCH_DHE_DSS)
         {
            //The client expects a valid DSA certificate whenever the agreed-upon
            //key exchange method uses DSA certificates for authentication
            if(context->peerCertType != TLS_CERT_DSS_SIGN)
               error = ERROR_UNSUPPORTED_CERTIFICATE;
         }
         else if(context->keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
         {
            //The client expects a valid ECDSA certificate whenever the agreed-upon
            //key exchange method uses ECDSA certificates for authentication
            if(context->peerCertType != TLS_CERT_ECDSA_SIGN)
               error = ERROR_UNSUPPORTED_CERTIFICATE;
         }
         else
         {
            //Just for sanity
            error = ERROR_UNSUPPORTED_CERTIFICATE;
         }
      }
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Check certificate key usage
 * @param[in] certInfo Pointer to the X.509 certificate
 * @param[in] entity Specifies whether this entity is considered a client or a server
 * @param[in] keyExchMethod TLS key exchange method
 * @return Error code
 **/

error_t tlsCheckKeyUsage(const X509CertificateInfo *certInfo,
   TlsConnectionEnd entity, TlsKeyExchMethod keyExchMethod)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_CERT_KEY_USAGE_SUPPORT == ENABLED)
   //Check if the KeyUsage extension is present
   if(certInfo->extensions.keyUsage != 0)
   {
      //TLS operates as a client or a server?
      if(entity == TLS_CONNECTION_END_CLIENT)
      {
         //Check key exchange method
         if(keyExchMethod == TLS_KEY_EXCH_RSA ||
            keyExchMethod == TLS_KEY_EXCH_RSA_PSK)
         {
            //The keyEncipherment bit must be asserted when the subject public
            //key is used for enciphering private or secret keys
            if(!(certInfo->extensions.keyUsage & X509_KEY_USAGE_KEY_ENCIPHERMENT))
               error = ERROR_BAD_CERTIFICATE;
         }
         else if(keyExchMethod == TLS_KEY_EXCH_DHE_RSA ||
            keyExchMethod == TLS_KEY_EXCH_DHE_DSS ||
            keyExchMethod == TLS_KEY_EXCH_ECDHE_RSA ||
            keyExchMethod == TLS_KEY_EXCH_ECDHE_ECDSA)
         {
            //The digitalSignature bit must be asserted when the subject public
            //key is used for verifying digital signatures, other than signatures
            //on certificates and CRLs
            if(!(certInfo->extensions.keyUsage & X509_KEY_USAGE_DIGITAL_SIGNATURE))
               error = ERROR_BAD_CERTIFICATE;
         }
         else
         {
            //Just for sanity
         }
      }
      else
      {
         //The digitalSignature bit must be asserted when the subject public
         //key is used for verifying digital signatures, other than signatures
         //on certificates and CRLs
         if(!(certInfo->extensions.keyUsage & X509_KEY_USAGE_DIGITAL_SIGNATURE))
            error = ERROR_BAD_CERTIFICATE;
      }
   }

   //Check if the ExtendedKeyUsage extension is present
   if(certInfo->extensions.extKeyUsage != 0)
   {
      //TLS operates as a client or a server?
      if(entity == TLS_CONNECTION_END_CLIENT)
      {
         //Make sure the certificate can be used for server authentication
         if(!(certInfo->extensions.extKeyUsage & X509_EXT_KEY_USAGE_SERVER_AUTH))
            error = ERROR_BAD_CERTIFICATE;
      }
      else
      {
         //Make sure the certificate can be used for client authentication
         if(!(certInfo->extensions.extKeyUsage & X509_EXT_KEY_USAGE_CLIENT_AUTH))
            error = ERROR_BAD_CERTIFICATE;
      }
   }
#endif

   //Return status code
   return error;
}

#endif
