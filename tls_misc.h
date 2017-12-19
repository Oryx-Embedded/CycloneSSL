/**
 * @file tls_misc.h
 * @brief TLS helper functions
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

#ifndef _TLS_MISC_H
#define _TLS_MISC_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
   extern "C" {
#endif

//TLS related functions
void tlsProcessError(TlsContext *context, error_t errorCode);

error_t tlsGenerateRandomValue(TlsContext *context, TlsRandom *random);

error_t tlsSelectVersion(TlsContext *context, uint16_t version);
error_t tlsSelectCipherSuite(TlsContext *context, uint16_t identifier);
error_t tlsSelectCompressMethod(TlsContext *context, uint8_t identifier);

error_t tlsSelectNamedCurve(TlsContext *context,
   const TlsEllipticCurveList *curveList);

error_t tlsInitEncryptionEngine(TlsContext *context,
   TlsEncryptionEngine *encryptionEngine, TlsConnectionEnd entity);

void tlsFreeEncryptionEngine(TlsEncryptionEngine *encryptionEngine);

error_t tlsWriteMpi(const Mpi *a, uint8_t *data, size_t *length);
error_t tlsReadMpi(Mpi *a, const uint8_t *data, size_t size, size_t *length);

error_t tlsWriteEcPoint(const EcDomainParameters *params,
   const EcPoint *a, uint8_t *data, size_t *length);

error_t tlsReadEcPoint(const EcDomainParameters *params,
   EcPoint *a, const uint8_t *data, size_t size, size_t *length);

const char_t *tlsGetVersionName(uint16_t version);
const HashAlgo *tlsGetHashAlgo(uint8_t hashAlgoId);
const EcCurveInfo *tlsGetCurveInfo(uint16_t namedCurve);
TlsEcNamedCurve tlsGetNamedCurve(const uint8_t *oid, size_t length);

size_t tlsComputeEncryptionOverhead(TlsEncryptionEngine *encryptionEngine,
   size_t payloadLen);

//C++ guard
#ifdef __cplusplus
   }
#endif

#endif
