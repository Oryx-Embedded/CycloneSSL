/**
 * @file tls_handshake_misc.c
 * @brief Helper functions for TLS handshake
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

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include <string.h>
#include "tls.h"
#include "tls_cipher_suites.h"
#include "tls_handshake_hash.h"
#include "tls_handshake_misc.h"
#include "tls_record.h"
#include "dtls_record.h"
#include "debug.h"

//Check SSL library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Send handshake message
 * @param[in] context Pointer to the TLS context
 * @param[in] data Pointer to the handshake message
 * @param[in] length Length of the handshake message
 * @param[in] type Handshake message type
 * @return Error code
 **/

error_t tlsSendHandshakeMessage(TlsContext *context,
   const void *data, size_t length, TlsMessageType type)
{
   error_t error;

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      DtlsHandshake *message;

      //Point to the handshake message header
      message = (DtlsHandshake *) data;

      //Make room for the handshake message header
      memmove(message->data, data, length);

      //Handshake message type
      message->msgType = type;
      //Number of bytes in the message
      STORE24BE(length, message->length);
      //Message sequence number
      message->msgSeq = htons(context->txMsgSeq);
      //Fragment offset
      STORE24BE(0, message->fragOffset);
      //Fragment length
      STORE24BE(length, message->fragLength);

      //Whenever a new message is generated, the message sequence
      //number is incremented by one
      context->txMsgSeq++;

      //Total length of the handshake message
      length += sizeof(DtlsHandshake);
   }
   else
#endif
   //TLS protocol?
   {
      TlsHandshake *message;

      //Point to the handshake message header
      message = (TlsHandshake *) data;

      //Make room for the handshake message header
      memmove(message->data, data, length);

      //Handshake message type
      message->msgType = type;
      //Number of bytes in the message
      STORE24BE(length, message->length);

      //Total length of the handshake message
      length += sizeof(TlsHandshake);
   }

   //The HelloRequest message must not be included in the message hashes
   //that are maintained throughout the handshake and used in the Finished
   //messages and the CertificateVerify message
   if(type != TLS_TYPE_HELLO_REQUEST)
      tlsUpdateHandshakeHash(context, data, length);

#if (DTLS_SUPPORT == ENABLED)
   //DTLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      //Send handshake message
      error = dtlsWriteProtocolData(context, data, length, TLS_TYPE_HANDSHAKE);
   }
   else
#endif
   //TLS protocol?
   {
      //Send handshake message
      error = tlsWriteProtocolData(context, data, length, TLS_TYPE_HANDSHAKE);
   }

   //Return status code
   return error;
}


/**
 * @brief Parse Hello extensions
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the list of extensions
 * @param[in] length Number of bytes available in the input stream
 * @param[out] extensions List of Hello extensions resulting from the parsing process
 * @return Error code
 **/

error_t tlsParseHelloExtensions(TlsContext *context, const uint8_t *p,
   size_t length, TlsHelloExtensions *extensions)
{
   error_t error;
   size_t n;
   uint16_t type;
   const TlsExtensionList *extensionList;
   const TlsExtension *extension;

   //Initialize TLS extensions
   memset(extensions, 0, sizeof(TlsHelloExtensions));

   //The implementation must accept messages both with and without
   //the extensions field
   if(length == 0)
   {
      //The extensions field is not present
      return NO_ERROR;
   }

   //Point to the list of extensions
   extensionList = (TlsExtensionList *) p;

   //Malformed message?
   if(length < sizeof(TlsExtensionList))
      return ERROR_DECODING_FAILED;

   //If the amount of data in the message does not precisely match the
   //format of the message, then send a fatal alert
   if(length != (sizeof(TlsExtensionList) + ntohs(extensionList->length)))
      return ERROR_DECODING_FAILED;

   //Point to the first extension of the list
   p += sizeof(TlsExtensionList);
   //Retrieve the length of the list
   length -= sizeof(TlsExtensionList);

   //Parse the list of extensions offered by the peer
   while(length > 0)
   {
      //Point to the current extension
      extension = (TlsExtension *) p;

      //Check the length of the extension
      if(length < sizeof(TlsExtension))
         return ERROR_DECODING_FAILED;
      if(length < (sizeof(TlsExtension) + ntohs(extension->length)))
         return ERROR_DECODING_FAILED;

      //Get extension type
      type = ntohs(extension->type);
      //Retrieve the length of the extension
      n = ntohs(extension->length);

      //Jump to the next extension
      p += sizeof(TlsExtension) + n;
      //Number of bytes left to process
      length -= sizeof(TlsExtension) + n;

      //Test if the current extension is a duplicate
      error = tlsCheckDuplicateExtension(type, p, length);
      //Duplicate extension found?
      if(error)
         return error;

      //When multiple extensions of different types are present in the
      //ClientHello or ServerHello messages, the extensions may appear
      //in any order
      if(type == TLS_EXT_SERVER_NAME)
      {
         //TLS operates as a client?
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            //If a client receives an extension type in the ServerHello that it
            //did not request in the associated ClientHello, it must abort the
            //handshake with an unsupported_extension fatal alert
            if(context->serverName == NULL)
               return ERROR_UNSUPPORTED_EXTENSION;
         }

         //Empty extension?
         if(n == 0)
         {
            //When the server includes a ServerName extension, the data field
            //of this extension may be empty
            if(context->entity == TLS_CONNECTION_END_SERVER)
               return ERROR_DECODING_FAILED;
         }
         else
         {
            const TlsServerNameList *serverNameList;

            //Point to the ServerName extension
            serverNameList = (TlsServerNameList *) extension->value;

            //Malformed extension?
            if(n < sizeof(TlsServerNameList))
               return ERROR_DECODING_FAILED;
            if(n != (sizeof(TlsServerNameList) + ntohs(serverNameList->length)))
               return ERROR_DECODING_FAILED;

            //Check the length of the list
            if(ntohs(serverNameList->length) == 0)
               return ERROR_DECODING_FAILED;

            //The ServerName extension is valid
            extensions->serverNameList = serverNameList;
         }
      }
      else if(type == TLS_EXT_MAX_FRAGMENT_LENGTH)
      {
         //Malformed extension?
         if(n != sizeof(uint8_t))
            return ERROR_DECODING_FAILED;

         //The MaxFragmentLength extension is valid
         extensions->maxFragLen = extension->value;
      }
      else if(type == TLS_EXT_ELLIPTIC_CURVES)
      {
         const TlsEllipticCurveList *ellipticCurveList;

         //Point to the EllipticCurves extension
         ellipticCurveList = (TlsEllipticCurveList *) extension->value;

         //Malformed extension?
         if(n < sizeof(TlsEllipticCurveList))
            return ERROR_DECODING_FAILED;
         if(n != (sizeof(TlsEllipticCurveList) + ntohs(ellipticCurveList->length)))
            return ERROR_DECODING_FAILED;

         //Check the length of the list
         if(ntohs(ellipticCurveList->length) == 0)
            return ERROR_DECODING_FAILED;
         if((ntohs(ellipticCurveList->length) % 2) != 0)
            return ERROR_DECODING_FAILED;

         //The EllipticCurves extension is valid
         extensions->ellipticCurveList = ellipticCurveList;
      }
      else if(type == TLS_EXT_EC_POINT_FORMATS)
      {
         const TlsEcPointFormatList *ecPointFormatList;

         //Point to the EcPointFormats extension
         ecPointFormatList = (TlsEcPointFormatList *) extension->value;

         //Malformed extension?
         if(n < sizeof(TlsEcPointFormatList))
            return ERROR_DECODING_FAILED;
         if(n != (sizeof(TlsEcPointFormatList) + ecPointFormatList->length))
            return ERROR_DECODING_FAILED;

         //Check the length of the list
         if(ntohs(ecPointFormatList->length) == 0)
            return ERROR_DECODING_FAILED;

         //The EcPointFormats extension is valid
         extensions->ecPointFormatList = ecPointFormatList;
      }
      else if(type == TLS_EXT_SIGNATURE_ALGORITHMS)
      {
         const TlsSignHashAlgos *signAlgoList;

         //Point to the SignatureAlgorithms extension
         signAlgoList = (TlsSignHashAlgos *) extension->value;

         //Malformed extension?
         if(n < sizeof(TlsSignHashAlgos))
            return ERROR_DECODING_FAILED;
         if(n != (sizeof(TlsSignHashAlgos) + ntohs(signAlgoList->length)))
            return ERROR_DECODING_FAILED;

         //Check the length of the list
         if(ntohs(signAlgoList->length) == 0)
            return ERROR_DECODING_FAILED;
         if((ntohs(signAlgoList->length) % 2) != 0)
            return ERROR_DECODING_FAILED;

         //The SignatureAlgorithms extension is valid
         extensions->signAlgoList = signAlgoList;
      }
      else if(type == TLS_EXT_ALPN)
      {
#if (TLS_ALPN_SUPPORT == ENABLED)
         const TlsProtocolNameList *protocolNameList;

         //Point to the ALPN extension
         protocolNameList = (TlsProtocolNameList *) extension->value;

         //Malformed extension?
         if(n < sizeof(TlsProtocolNameList))
            return ERROR_DECODING_FAILED;
         if(n != (sizeof(TlsProtocolNameList) + ntohs(protocolNameList->length)))
            return ERROR_DECODING_FAILED;

         //The ALPN extension is valid
         extensions->protocolNameList = protocolNameList;
#endif
      }
      else if(type == TLS_EXT_EXTENDED_MASTER_SECRET)
      {
#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
         //Malformed extension?
         if(n != 0)
            return ERROR_DECODING_FAILED;

         //The ExtendedMasterSecret extension is valid
         extensions->extendedMasterSecret = extension->value;
#endif
      }
      else if(type == TLS_EXT_RENEGOTIATION_INFO)
      {
#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
         const TlsRenegoInfo *renegoInfo;

         //Point to the RenegotiationInfo extension
         renegoInfo = (TlsRenegoInfo *) extension->value;

         //Malformed extension?
         if(n < sizeof(TlsRenegoInfo))
            return ERROR_DECODING_FAILED;
         if(n != (sizeof(TlsRenegoInfo) + renegoInfo->length))
            return ERROR_DECODING_FAILED;

         //The RenegotiationInfo extension is valid
         extensions->renegoInfo = renegoInfo;
#endif
      }
      else
      {
         //Unknown extension received
         if(context->entity == TLS_CONNECTION_END_CLIENT)
         {
            //If a client receives an extension type in the ServerHello that
            //it did not request in the associated ClientHello, it must abort
            //the handshake with an unsupported_extension fatal alert
            return ERROR_UNSUPPORTED_EXTENSION;
         }
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Check whether the specified extension type is a duplicate
 * @param[in] type Extension type
 * @param[in] p Input stream where to read the list of extensions
 * @param[in] length Number of bytes available in the input stream
 * @return Error code
 **/

error_t tlsCheckDuplicateExtension(uint16_t type, const uint8_t *p,
   size_t length)
{
   size_t n;
   const TlsExtension *extension;

   //Parse the list of extensions offered by the peer
   while(length > 0)
   {
      //Point to the current extension
      extension = (TlsExtension *) p;

      //Check the length of the extension
      if(length < sizeof(TlsExtension))
         return ERROR_DECODING_FAILED;
      if(length < (sizeof(TlsExtension) + ntohs(extension->length)))
         return ERROR_DECODING_FAILED;

      //There must not be more than one extension of the same type (refer to
      //RFC 5246, section 7.4.1.4)
      if(ntohs(extension->type) == type)
         return ERROR_DECODING_FAILED;

      //Retrieve the length of the extension
      n = ntohs(extension->length);

      //Jump to the next extension
      p += sizeof(TlsExtension) + n;
      //Number of bytes left to process
      length -= sizeof(TlsExtension) + n;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Check whether the specified ALPN protocol is supported
 * @param[in] context Pointer to the TLS context
 * @param[in] protocol Pointer to the protocol name
 * @param[in] length Length of the protocol name, in bytes
 * @return TRUE if the specified protocol is supported, else FALSE
 **/

bool_t tlsIsAlpnProtocolSupported(TlsContext *context,
   const char_t *protocol, size_t length)
{
   bool_t supported;

   //Initialize the flag
   supported = FALSE;

#if (TLS_ALPN_SUPPORT == ENABLED)
   //Sanity check
   if(context->protocolList != NULL)
   {
      size_t i;
      size_t j;

      //Move back to the beginning of the list
      i = 0;
      j = 0;

      //Parse the list of supported protocols
      do
      {
         //Delimiter character found?
         if(context->protocolList[i] == ',' || context->protocolList[i] == '\0')
         {
            //Check the length of the protocol name
            if(length == (i - j))
            {
               //Compare protocol names
               if(!memcmp(protocol, context->protocolList + j, i - j))
               {
                  //The specified protocol is supported
                  supported = TRUE;
                  //We are done
                  break;
               }
            }

            //Move to the next token
            j = i + 1;
         }

         //Loop until the NULL character is reached
      } while(context->protocolList[i++] != '\0');
   }
#endif

   //Return TRUE if the specified protocol is supported
   return supported;
}

#endif
