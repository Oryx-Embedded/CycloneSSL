/**
 * @file dtls13_record_encrypt.h
 * @brief DTLS 1.3 record encryption
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2026 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.6.2
 **/

#ifndef _DTLS13_RECORD_ENCRYPT_H
#define _DTLS13_RECORD_ENCRYPT_H

//Dependencies
#include "tls/tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//DTLS 1.3 related functions
error_t dtls13EncryptRecord(TlsContext *context,
   TlsEncryptionEngine *encryptionEngine, uint8_t type, const uint8_t *data,
   size_t dataLen, uint8_t *record, size_t *recordLen);

error_t dtls13EncryptAeadRecord(TlsContext *context,
   TlsEncryptionEngine *encryptionEngine, const uint8_t *nonce,
   size_t nonceLen, const uint8_t *aad, size_t aadLen, uint8_t *data,
   size_t dataLen, uint8_t *tag);

error_t dtls13ComputeMac(TlsContext *context,
   TlsEncryptionEngine *encryptionEngine, const uint8_t *nonce,
   size_t nonceLen, const uint8_t *aad, size_t aadLen, const uint8_t *data,
   size_t dataLen, uint8_t *mac);

error_t dtls13EncryptSequenceNumber(TlsEncryptionEngine *encryptionEngine,
   uint8_t *record);

error_t dtls13DecryptSequenceNumber(TlsEncryptionEngine *decryptionEngine,
   uint8_t *record);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
