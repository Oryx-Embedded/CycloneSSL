/**
 * @file tls13_sign_generate.h
 * @brief RSA/DSA/ECDSA/SM2/EdDSA signature generation (TLS 1.3)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2025 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.5.2
 **/

#ifndef _TLS13_SIGN_GENERATE_H
#define _TLS13_SIGN_GENERATE_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//TLS 1.3 related functions
error_t tls13GenerateSignature(TlsContext *context, uint8_t *p,
   size_t *length);

error_t tls13GenerateRsaPssSignature(TlsContext *context, const uint8_t *message,
   size_t length, Tls13DigitalSignature *signature);

error_t tls13GenerateEcdsaSignature(TlsContext *context, const uint8_t *message,
   size_t length, Tls13DigitalSignature *signature);

error_t tls13GenerateSm2Signature(TlsContext *context, const uint8_t *message,
   size_t length, Tls13DigitalSignature *signature);

error_t tls13GenerateEd25519Signature(TlsContext *context, const uint8_t *message,
   size_t length, Tls13DigitalSignature *signature);

error_t tls13GenerateEd448Signature(TlsContext *context, const uint8_t *message,
   size_t length, Tls13DigitalSignature *signature);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
