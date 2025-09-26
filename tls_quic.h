/**
 * @file tls_quic.h
 * @brief QUIC TLS related API
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

#ifndef _TLS_QUIC_H
#define _TLS_QUIC_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//QUIC TLS related functions
error_t tlsRegisterQuicCallbacks(TlsContext *context,
   const TlsQuicCallbacks *quicCallbacks, void *handle);

error_t tlsSetQuicHandle(TlsContext *context, void *handle);

error_t tlsSetLocalQuicTransportParams(TlsContext *context,
   const uint8_t *params, size_t length);

error_t tlsGetRemoteQuicTransportParams(TlsContext *context,
   const uint8_t **params, size_t *length);

error_t tlsProcessQuicHandshakeMessage(TlsContext *context,
   TlsEncryptionLevel level, const uint8_t *data, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
