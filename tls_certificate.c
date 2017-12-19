/**
 * @file tls_certificate.c
 * @brief Certificate handling
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
#include <ctype.h>
#include "tls.h"
#include "tls_certificate.h"
#include "tls_misc.h"
#include "encoding/oid.h"
#include "certificate/pem_import.h"
#include "certificate/x509_cert_parse.h"
#include "certificate/x509_cert_validate.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED)


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
   const TlsEllipticCurveList *curveList, const TlsCertAuthorities *certAuthorities)
{
   size_t i;
   size_t n;
   size_t length;
   bool_t acceptable;

   //Make sure that a valid certificate has been loaded
   if(!cert->certChain || !cert->certChainLen)
      return FALSE;

   //This flag tells whether the certificate is acceptable
   acceptable = TRUE;

   //Filter out certificates with unsupported type
   if(numCertTypes > 0)
   {
      //Loop through the list of supported certificate types
      for(acceptable = FALSE, i = 0; i < numCertTypes; i++)
      {
         //Check whether the certificate type is acceptable
         if(certTypes[i] == cert->type)
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
         //The certificate must be signed using a valid hash/signature algorithm pair
         if(signHashAlgos->value[i].signature == cert->signAlgo &&
            signHashAlgos->value[i].hash == cert->hashAlgo)
         {
            acceptable = TRUE;
            break;
         }
      }
   }

   //Check whether the certificate contains an ECDSA public key
   if(cert->type == TLS_CERT_ECDSA_SIGN)
   {
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
   TlsHashAlgo *certHashAlgo, TlsEcNamedCurve *namedCurve)
{
   const X509SubjectPublicKeyInfo *publicKeyInfo;
   const X509SignatureId *signatureAlgo;

   //Check parameters
   if(certInfo == NULL || certType == NULL || certSignAlgo == NULL ||
      certHashAlgo == NULL || namedCurve == NULL)
   {
      //Report an error
      return ERROR_INVALID_PARAMETER;
   }

   //Point to the subject's public key
   publicKeyInfo = &certInfo->subjectPublicKeyInfo;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_SUPPORT == ENABLED || \
   TLS_DHE_RSA_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_RSA_PSK_SUPPORT == ENABLED)
   //RSA public key?
   if(!oidComp(publicKeyInfo->oid, publicKeyInfo->oidLen,
      RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)))
   {
      //Save certificate type
      *certType = TLS_CERT_RSA_SIGN;
      //Elliptic curve cryptography is not used
      *namedCurve = TLS_EC_CURVE_NONE;
   }
   else
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED || TLS_DHE_DSS_SUPPORT == ENABLED)
   //DSA public key?
   if(!oidComp(publicKeyInfo->oid, publicKeyInfo->oidLen,
      DSA_OID, sizeof(DSA_OID)))
   {
      //Save certificate type
      *certType = TLS_CERT_DSS_SIGN;
      //Elliptic curve cryptography is not used
      *namedCurve = TLS_EC_CURVE_NONE;
   }
   else
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED || TLS_ECDHE_ECDSA_SUPPORT == ENABLED)
   //EC public key?
   if(!oidComp(publicKeyInfo->oid, publicKeyInfo->oidLen,
      EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      //Save certificate type
      *certType = TLS_CERT_ECDSA_SIGN;

      //Retrieve the named curve that has been used to generate the EC public key
      *namedCurve = tlsGetNamedCurve(publicKeyInfo->ecParams.namedCurve,
         publicKeyInfo->ecParams.namedCurveLen);
   }
   else
#endif
   //Invalid public key?
   {
      //The certificate does not contain any valid public key
      return ERROR_BAD_CERTIFICATE;
   }

   //Point to the signature algorithm
   signatureAlgo = &certInfo->signatureAlgo;

   //Retrieve the signature algorithm that has been used to sign the certificate
   if(signatureAlgo->data == NULL)
   {
      //Invalid certificate
      return ERROR_BAD_CERTIFICATE;
   }
#if (TLS_RSA_SIGN_SUPPORT == ENABLED)
   else if(!oidComp(signatureAlgo->data, signatureAlgo->length,
      MD5_WITH_RSA_ENCRYPTION_OID, sizeof(MD5_WITH_RSA_ENCRYPTION_OID)))
   {
      //MD5 with RSA signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_RSA;
      *certHashAlgo = TLS_HASH_ALGO_MD5;
   }
   else if(!oidComp(signatureAlgo->data, signatureAlgo->length,
      SHA1_WITH_RSA_ENCRYPTION_OID, sizeof(SHA1_WITH_RSA_ENCRYPTION_OID)))
   {
      //SHA-1 with RSA signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_RSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA1;
   }
   else if(!oidComp(signatureAlgo->data, signatureAlgo->length,
      SHA256_WITH_RSA_ENCRYPTION_OID, sizeof(SHA256_WITH_RSA_ENCRYPTION_OID)))
   {
      //SHA-256 with RSA signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_RSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA256;
   }
   else if(!oidComp(signatureAlgo->data, signatureAlgo->length,
      SHA384_WITH_RSA_ENCRYPTION_OID, sizeof(SHA384_WITH_RSA_ENCRYPTION_OID)))
   {
      //SHA-384 with RSA signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_RSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA384;
   }
   else if(!oidComp(signatureAlgo->data, signatureAlgo->length,
      SHA512_WITH_RSA_ENCRYPTION_OID, sizeof(SHA512_WITH_RSA_ENCRYPTION_OID)))
   {
      //SHA-512 with RSA signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_RSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA512;
   }
#endif
#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
   else if(!oidComp(signatureAlgo->data, signatureAlgo->length,
      DSA_WITH_SHA1_OID, sizeof(DSA_WITH_SHA1_OID)))
   {
      //DSA with SHA-1 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_DSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA1;
   }
   else if(!oidComp(signatureAlgo->data, signatureAlgo->length,
      DSA_WITH_SHA224_OID, sizeof(DSA_WITH_SHA224_OID)))
   {
      //DSA with SHA-224 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_DSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA224;
   }
   else if(!oidComp(signatureAlgo->data, signatureAlgo->length,
      DSA_WITH_SHA256_OID, sizeof(DSA_WITH_SHA256_OID)))
   {
      //DSA with SHA-256 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_DSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA256;
   }
#endif
#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED)
   else if(!oidComp(signatureAlgo->data, signatureAlgo->length,
      ECDSA_WITH_SHA1_OID, sizeof(ECDSA_WITH_SHA1_OID)))
   {
      //ECDSA with SHA-1 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_ECDSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA1;
   }
   else if(!oidComp(signatureAlgo->data, signatureAlgo->length,
      ECDSA_WITH_SHA224_OID, sizeof(ECDSA_WITH_SHA224_OID)))
   {
      //ECDSA with SHA-224 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_ECDSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA224;
   }
   else if(!oidComp(signatureAlgo->data, signatureAlgo->length,
      ECDSA_WITH_SHA256_OID, sizeof(ECDSA_WITH_SHA256_OID)))
   {
      //ECDSA with SHA-256 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_ECDSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA256;
   }
   else if(!oidComp(signatureAlgo->data, signatureAlgo->length,
      ECDSA_WITH_SHA384_OID, sizeof(ECDSA_WITH_SHA384_OID)))
   {
      //ECDSA with SHA-384 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_ECDSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA384;
   }
   else if(!oidComp(signatureAlgo->data, signatureAlgo->length,
      ECDSA_WITH_SHA512_OID, sizeof(ECDSA_WITH_SHA512_OID)))
   {
      //ECDSA with SHA-512 signature algorithm
      *certSignAlgo = TLS_SIGN_ALGO_ECDSA;
      *certHashAlgo = TLS_HASH_ALGO_SHA512;
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
 * @param[in] certInfo Pointer to the X.509 certificate
 * @return Error code
 **/

error_t tlsReadSubjectPublicKey(TlsContext *context,
   const X509CertificateInfo *certInfo)
{
   error_t error;
   const X509SubjectPublicKeyInfo *publicKeyInfo;

   //Point to the subject's public key
   publicKeyInfo = &certInfo->subjectPublicKeyInfo;

#if (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_SUPPORT == ENABLED || \
   TLS_DHE_RSA_SUPPORT == ENABLED || TLS_ECDHE_RSA_SUPPORT == ENABLED || \
   TLS_RSA_PSK_SUPPORT == ENABLED)
   //RSA public key?
   if(!oidComp(publicKeyInfo->oid, publicKeyInfo->oidLen,
      RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)))
   {
      uint_t k;

      //Retrieve the RSA public key
      error = x509ReadRsaPublicKey(certInfo, &context->peerRsaPublicKey);

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
   if(!oidComp(publicKeyInfo->oid, publicKeyInfo->oidLen,
      DSA_OID, sizeof(DSA_OID)))
   {
      uint_t k;

      //Retrieve the DSA public key
      error = x509ReadDsaPublicKey(certInfo, &context->peerDsaPublicKey);

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
   if(!oidComp(publicKeyInfo->oid, publicKeyInfo->oidLen,
      EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      const EcCurveInfo *curveInfo;

      //Retrieve EC domain parameters
      curveInfo = x509GetCurveInfo(publicKeyInfo->ecParams.namedCurve,
         publicKeyInfo->ecParams.namedCurveLen);

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
               publicKeyInfo->ecPublicKey.q, publicKeyInfo->ecPublicKey.qLen);
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
