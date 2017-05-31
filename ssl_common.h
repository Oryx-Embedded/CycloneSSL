/**
 * @file ssl_common.h
 * @brief Functions common to SSL 3.0 client and server
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
 * @version 1.7.8
 **/

#ifndef _SSL_COMMON_H
#define _SSL_COMMON_H

//Dependencies
#include "crypto.h"
#include "tls.h"

//SSL 3.0 related constants
extern const uint8_t sslPad1[48];
extern const uint8_t sslPad2[48];

//SSL 3.0 related functions
error_t sslExpandKey(const uint8_t *secret, size_t secretLength,
   const uint8_t *random, size_t randomLength, uint8_t *output, size_t outputLength);

error_t sslComputeMac(TlsContext *context, const void *secret, TlsSequenceNumber seqNum,
   const TlsRecord *record, const uint8_t *data, size_t length, uint8_t *mac);

#endif
