/**
 * @file tls_handshake_hash.h
 * @brief Handshake hash calculation/verification
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

#ifndef _TLS_HANDSHAKE_HASH_H
#define _TLS_HANDSHAKE_HASH_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
   extern "C" {
#endif

//TLS related functions
error_t tlsInitHandshakeHash(TlsContext *context);

void tlsUpdateHandshakeHash(TlsContext *context, const void *data,
   size_t length);

error_t tlsFinalizeHandshakeHash(TlsContext *context, const HashAlgo *hash,
   const void *hashContext, const char_t *label, uint8_t *output);

error_t tlsComputeVerifyData(TlsContext *context, TlsConnectionEnd entity,
   uint8_t *verifyData, size_t *verifyDataLen);

//C++ guard
#ifdef __cplusplus
   }
#endif

#endif
