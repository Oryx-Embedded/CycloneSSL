/**
 * @file tls_sign_misc.h
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

#ifndef _TLS_SIGN_MISC_H
#define _TLS_SIGN_MISC_H

//Dependencies
#include "tls.h"

//Extract signature algorithm from legacy signature scheme
#define TLS_SIGN_ALGO(signScheme) ((TlsSignatureAlgo) LSB(signScheme))

//Extract hash algorithm from legacy signature scheme
#define TLS_HASH_ALGO(signScheme) ((TlsHashAlgo) MSB(signScheme))

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//TLS related functions
error_t tlsSelectSignAlgo(TlsContext *context, const TlsCertDesc *cert,
   const TlsSignSchemeList *signAlgoList);

error_t tlsFormatSignAlgosExtension(TlsContext *context, uint8_t *p,
   size_t *written);

error_t tlsFormatSignAlgosCertExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatSupportedSignAlgos(TlsContext *context, uint8_t *p,
   size_t *written);

bool_t tlsIsSignAlgoOffered(uint16_t signScheme,
   const TlsSignSchemeList *signSchemeList);

bool_t tlsIsSignAlgoAcceptable(TlsContext *context, uint16_t signScheme,
   const TlsCertDesc *cert);

bool_t tlsIsSignAlgoSupported(TlsContext *context, uint16_t signScheme);
bool_t tlsIsCertSignAlgoSupported(uint16_t signScheme);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
