/**
 * @file dtls13_misc.h
 * @brief DTLS 1.3 (Datagram Transport Layer Security)
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

#ifndef _DTLS13_MISC_H
#define _DTLS13_MISC_H

//Dependencies
#include "tls/tls.h"

//Maximum number of retransmissions
#ifndef DTLS13_MAX_ACK_RECORDS
   #define DTLS13_MAX_ACK_RECORDS 32
#elif (DTLS13_MAX_ACK_RECORDS < 1)
   #error DTLS13_MAX_ACK_RECORDS parameter is not valid
#endif

//DTLS 1.3 unified header
#define DTLS13_HEADER_MASK   0xE0
#define DTLS13_HEADER_FIXED  0x20
#define DTLS13_HEADER_FLAG_C 0x10
#define DTLS13_HEADER_FLAG_S 0x08
#define DTLS13_HEADER_FLAG_L 0x04
#define DTLS13_HEADER_FLAG_E 0x03

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//CC-RX, CodeWarrior or Win32 compiler?
#if defined(__CCRX__)
   #pragma pack
#elif defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief Record number
 **/

typedef __packed_struct
{
   uint64_t epoch;  //0-7
   uint64_t seqNum; //8-15
} Dtls13RecordNumber;


/**
 * @brief ACK message
 **/

typedef __packed_struct
{
   uint16_t length;                    //0-1
   Dtls13RecordNumber recordNumbers[]; //2
} Dtls13Ack;


//CC-RX, CodeWarrior or Win32 compiler?
#if defined(__CCRX__)
   #pragma unpack
#elif defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif


/**
 * @brief Retransmission state
 **/

typedef struct
{
   uint64_t start;
   uint_t count;
   uint_t index;
   uint32_t mask;
} Dtls13RetransmitState;


//DTLS 1.3 specific functions
void dtls13SaveRecordNumber(TlsContext *context, uint64_t epoch,
   uint64_t seqNum);

error_t dtls13SendAck(TlsContext *context);

error_t dtls13FormatAck(TlsContext *context, Dtls13Ack *message,
   size_t *length);

error_t dtls13ParseAck(TlsContext *context, const Dtls13Ack *message,
   size_t length);

void dtls13FormatNonce(TlsEncryptionEngine *encryptionEngine,
   const DtlsSequenceNumber *seqNum, uint8_t *nonce, size_t *nonceLen);

size_t dtls13ComputeEncryptionOverhead(TlsEncryptionEngine *encryptionEngine);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
