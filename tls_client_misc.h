/**
 * @file tls_client_misc.h
 * @brief Helper functions for TLS client
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

#ifndef _TLS_SERVER_MISC_H
#define _TLS_SERVER_MISC_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
   extern "C" {
#endif

//TLS client specific functions
error_t tlsFormatCipherSuites(TlsContext *context,
   uint_t *cipherSuiteTypes, uint8_t *p, size_t *written);

error_t tlsFormatCompressMethods(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatClientSupportedVersionsExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatClientSniExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatClientMaxFragLenExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatClientRecordSizeLimitExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatSupportedGroupsExtension(TlsContext *context,
   uint_t cipherSuiteTypes, uint8_t *p, size_t *written);

error_t tlsFormatClientEcPointFormatsExtension(TlsContext *context,
   uint_t cipherSuiteTypes, uint8_t *p, size_t *written);

error_t tlsFormatClientAlpnExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatClientCertTypeListExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatServerCertTypeListExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatClientEmsExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatClientRenegoInfoExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatPskIdentity(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatClientKeyParams(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsParseServerSniExtension(TlsContext *context,
   const TlsServerNameList *serverNameList);

error_t tlsParseServerMaxFragLenExtension(TlsContext *context,
   const uint8_t *maxFragLen);

error_t tlsParseServerRecordSizeLimitExtension(TlsContext *context,
   const uint8_t *recordSizeLimit);

error_t tlsParseServerEcPointFormatsExtension(TlsContext *context,
   const TlsEcPointFormatList *ecPointFormatList);

error_t tlsParseServerAlpnExtension(TlsContext *context,
   const TlsProtocolNameList *protocolNameList);

error_t tlsParseClientCertTypeExtension(TlsContext *context,
   const uint8_t *clientCertType);

error_t tlsParseServerCertTypeExtension(TlsContext *context,
   const uint8_t *serverCertType);

error_t tlsParsePskIdentityHint(TlsContext *context,
   const uint8_t *p, size_t length, size_t *consumed);

error_t tlsParseServerKeyParams(TlsContext *context,
   const uint8_t *p, size_t length, size_t *consumed);

error_t tlsVerifyServerKeySignature(TlsContext *context,
   const TlsDigitalSignature *signature, size_t length,
   const uint8_t *params, size_t paramsLen, size_t *consumed);

error_t tls12VerifyServerKeySignature(TlsContext *context,
   const Tls12DigitalSignature *signature, size_t length,
   const uint8_t *params, size_t paramsLen, size_t *consumed);

//C++ guard
#ifdef __cplusplus
   }
#endif

#endif
