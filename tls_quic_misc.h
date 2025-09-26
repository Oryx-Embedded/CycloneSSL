/**
 * @file tls_quic_misc.h
 * @brief QUIC helper functions
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
 * @section Description
 *
 * The TLS protocol provides communications security over the Internet. The
 * protocol allows client/server applications to communicate in a way that
 * is designed to prevent eavesdropping, tampering, or message forgery
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.4
 **/

#ifndef _TLS_QUIC_MISC_H
#define _TLS_QUIC_MISC_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//QUIC TLS related functions
error_t tlsFormatQuicTransportParamsExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsParseQuicTransportParamsExtension(TlsContext *context,
   const TlsExtension *quicTransportParams);

error_t tlsSetQuicEncryptionKeys(TlsContext *context, TlsEncryptionLevel level,
   const uint8_t *clientKey, const uint8_t *serverKey, size_t keyLen);

error_t tlsSendQuicHandshakeMessage(TlsContext *context, const uint8_t *message,
   size_t length);

error_t tlsSendQuicAlertMessage(TlsContext *context, const TlsAlert *message,
   size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
