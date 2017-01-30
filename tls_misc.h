/**
 * @file tls_misc.h
 * @brief Helper functions (TLS client and server)
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

#ifndef _TLS_MISC_H
#define _TLS_MISC_H

//Dependencies
#include "tls.h"
#include "x509.h"

//TLS related functions
void tlsProcessError(TlsContext *context, error_t errorCode);

error_t tlsGenerateRandomValue(TlsContext *context, TlsRandom *random);

error_t tlsSetVersion(TlsContext *context, uint16_t version);
error_t tlsSetCipherSuite(TlsContext *context, uint16_t identifier);
error_t tlsSetCompressionMethod(TlsContext *context, uint8_t identifier);

error_t tlsSelectSignHashAlgo(TlsContext *context,
   TlsSignatureAlgo signAlgo, const TlsSignHashAlgos *supportedSignAlgos);

error_t tlsSelectNamedCurve(TlsContext *context,
   const TlsEllipticCurveList *curveList);

error_t tlsInitHandshakeHash(TlsContext *context);
void tlsUpdateHandshakeHash(TlsContext *context, const void *data, size_t length);

error_t tlsFinalizeHandshakeHash(TlsContext *context, const HashAlgo *hash,
   const void *hashContext, const char_t *label, uint8_t *output);

error_t tlsComputeVerifyData(TlsContext *context, TlsConnectionEnd entity);

error_t tlsInitEncryptionEngine(TlsContext *context);
error_t tlsInitDecryptionEngine(TlsContext *context);

error_t tlsWriteMpi(const Mpi *a, uint8_t *data, size_t *length);
error_t tlsReadMpi(Mpi *a, const uint8_t *data, size_t size, size_t *length);

error_t tlsWriteEcPoint(const EcDomainParameters *params,
   const EcPoint *a, uint8_t *data, size_t *length);

error_t tlsReadEcPoint(const EcDomainParameters *params,
   EcPoint *a, const uint8_t *data, size_t size, size_t *length);

error_t tlsGenerateRsaSignature(const RsaPrivateKey *key,
   const uint8_t *digest, uint8_t *signature, size_t *signatureLength);

error_t tlsVerifyRsaSignature(const RsaPublicKey *key,
   const uint8_t *digest, const uint8_t *signature, size_t signatureLength);

error_t tlsGenerateDsaSignature(const PrngAlgo *prngAlgo, void *prngContext, const DsaPrivateKey *key,
   const uint8_t *digest, size_t digestLength, uint8_t *signature, size_t *signatureLength);

error_t tlsVerifyDsaSignature(const DsaPublicKey *key, const uint8_t *digest,
   size_t digestLength, const uint8_t *signature, size_t signatureLength);

error_t tlsGenerateEcdsaSignature(const EcDomainParameters *params,
   const PrngAlgo *prngAlgo, void *prngContext, const Mpi *key, const uint8_t *digest,
   size_t digestLength, uint8_t *signature, size_t *signatureLength);

error_t tlsVerifyEcdsaSignature(const EcDomainParameters *params,
   const EcPoint *key, const uint8_t *digest, size_t digestLength,
   const uint8_t *signature, size_t signatureLength);

error_t tlsGeneratePskPremasterSecret(TlsContext *context);
error_t tlsGenerateKeys(TlsContext *context);

error_t tlsPrf(const uint8_t *secret, size_t secretLength, const char_t *label,
   const uint8_t *seed, size_t seedLength, uint8_t *output, size_t outputLength);

error_t tlsPrf2(const HashAlgo *hash, const uint8_t *secret, size_t secretLength,
   const char_t *label, const uint8_t *seed, size_t seedLength, uint8_t *output, size_t outputLength);

bool_t tlsIsCertificateAcceptable(const TlsCertDesc *cert,
   const uint8_t *certTypes, size_t numCertTypes, const TlsSignHashAlgos *signHashAlgos,
   const TlsEllipticCurveList *curveList, const TlsCertAuthorities *certAuthorities);

error_t tlsGetCertificateType(const X509CertificateInfo *certInfo, TlsCertificateType *certType,
   TlsSignatureAlgo *certSignAlgo, TlsHashAlgo *certHashAlgo, TlsEcNamedCurve *namedCurve);

const TlsExtension *tlsGetExtension(const uint8_t *data, size_t length, uint16_t type);
const char_t *tlsGetVersionName(uint16_t version);
const HashAlgo *tlsGetHashAlgo(uint8_t hashAlgoId);
const EcCurveInfo *tlsGetCurveInfo(uint16_t namedCurve);
TlsEcNamedCurve tlsGetNamedCurve(const uint8_t *oid, size_t length);

#endif
