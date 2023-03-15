/**
 * \file sip.cpp
 * \author Tomas Jansky <janskto1@fit.cvut.cz>
 * \date 2015
 * \date 2016
 */
/*
 * Copyright (C) 2015-2016 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#include <cstdlib>
#include <cstring>
#include <iostream>

#ifdef WITH_NEMEA
#include <unirec/unirec.h>
#endif

#include "sip.hpp"

namespace Ipxp {

int RecordExtSIP::s_registeredId = -1;

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("sip", []() { return new SIPPlugin(); });
	registerPlugin(&rec);
	RecordExtSIP::s_registeredId = registerExtension();
}

SIPPlugin::SIPPlugin()
	: m_requests(0)
	, m_responses(0)
	, m_total(0)
	, m_flow_flush(false)
{
}

SIPPlugin::~SIPPlugin()
{
	close();
}

void SIPPlugin::init(const char* params) {}

void SIPPlugin::close() {}

ProcessPlugin* SIPPlugin::copy()
{
	return new SIPPlugin(*this);
}

int SIPPlugin::postCreate(Flow& rec, const Packet& pkt)
{
	uint16_t msgType;

	msgType = parseMsgType(pkt);
	if (msgType == SIP_MSG_TYPE_INVALID) {
		return 0;
	}

	RecordExtSIP* sipData = new RecordExtSIP();
	sipData->msgType = msgType;
	rec.addExtension(sipData);
	parserProcessSip(pkt, sipData);

	return 0;
}

int SIPPlugin::preUpdate(Flow& rec, Packet& pkt)
{
	uint16_t msgType;

	msgType = parseMsgType(pkt);
	if (msgType != SIP_MSG_TYPE_INVALID) {
		return FLOW_FLUSH_WITH_REINSERT;
	}

	return 0;
}

void SIPPlugin::finish(bool printStats)
{
	if (printStats) {
		std::cout << "SIP plugin stats:" << std::endl;
		std::cout << "   Parsed sip requests: " << m_requests << std::endl;
		std::cout << "   Parsed sip responses: " << m_responses << std::endl;
		std::cout << "   Total sip packets processed: " << m_total << std::endl;
	}
}

uint16_t SIPPlugin::parseMsgType(const Packet& pkt)
{
	if (pkt.payloadLen == 0) {
		return SIP_MSG_TYPE_INVALID;
	}

	uint32_t* firstBytes;
	uint32_t check;

	/* Is there any payload to process? */
	if (pkt.payloadLen < SIP_MIN_MSG_LEN) {
		return SIP_MSG_TYPE_INVALID;
	}

	/* Get first four bytes of the packet and compare them against the patterns: */
	firstBytes = (uint32_t*) pkt.payload;

	/* Apply the pattern on the packet: */
	check = *firstBytes ^ SIP_TEST_1;

	/*
	 * Here we will check if at least one of bytes in the SIP pattern is present in the packet.
	 * Add magic_bits to longword
	 *                |      Set those bits which were unchanged by the addition
	 *                |             |        Look at the hole bits. If some of them is unchanged,
	 *                |             |            |    most likely there is zero byte, ie. our
	 * separator. v             v            v */
	if ((((check + MAGIC_BITS) ^ ~check) & MAGIC_BITS_NEG) != 0) {
		/* At least one byte of the test pattern was found -> the packet *may* contain one of the
		 * searched SIP messages: */
		switch (*firstBytes) {
		case SIP_REGISTER:
			return SIP_MSG_TYPE_REGISTER;
		case SIP_INVITE:
			return SIP_MSG_TYPE_INVITE;
		case SIP_OPTIONS:
			/* OPTIONS message is also a request in HTTP - we must identify false positives here: */
			if (firstBytes[1] == SIP_NOT_OPTIONS1 && firstBytes[2] == SIP_NOT_OPTIONS2) {
				return SIP_MSG_TYPE_OPTIONS;
			}

			return SIP_MSG_TYPE_INVALID;
		case SIP_NOTIFY: /* Notify message is a bit tricky because also Microsoft's SSDP protocol
						  * uses HTTP-like structure and NOTIFY message - we must identify false
						  * positives here: */
			if (firstBytes[1] == SIP_NOT_NOTIFY1 && firstBytes[2] == SIP_NOT_NOTIFY2) {
				return SIP_MSG_TYPE_INVALID;
			}

			return SIP_MSG_TYPE_NOTIFY;
		case SIP_CANCEL:
			return SIP_MSG_TYPE_CANCEL;
		case SIP_INFO:
			return SIP_MSG_TYPE_INFO;
		default:
			break;
		}
	}

	/* Do the same thing for the second pattern: */
	check = *firstBytes ^ SIP_TEST_2;
	if ((((check + MAGIC_BITS) ^ ~check) & MAGIC_BITS_NEG) != 0) {
		switch (*firstBytes) {
		case SIP_REPLY:
			return SIP_MSG_TYPE_STATUS;
		case SIP_ACK:
			return SIP_MSG_TYPE_ACK;
		case SIP_BYE:
			return SIP_MSG_TYPE_BYE;
		case SIP_SUBSCRIBE:
			return SIP_MSG_TYPE_SUBSCRIBE;
		case SIP_PUBLISH:
			return SIP_MSG_TYPE_PUBLISH;
		default:
			break;
		}
	}

	/* No pattern found, this is probably not SIP packet: */
	return SIP_MSG_TYPE_INVALID;
}

const unsigned char* SIPPlugin::parserStrtok(
	const unsigned char* str,
	unsigned int instrlen,
	char separator,
	unsigned int* strlen,
	ParserStrtokT* nst)
{
	const unsigned char* charPtr; /* Currently processed characters */
	const unsigned char* beginning; /* Beginning of the original string */
	MAGIC_INT* longwordPtr; /* Currently processed word */
	MAGIC_INT longword; /* Dereferenced longword_ptr useful for the next work */
	MAGIC_INT longwordMask; /* Dereferenced longword_ptr with applied separator mask */
	const unsigned char* cp; /* A byte which is supposed to be the next separator */
	int len; /* Length of the string */
	MAGIC_INT i;

	/*
	 * The idea of the algorithm comes from the implementation of stdlib function strlen().
	 * See http://www.stdlib.net/~colmmacc/strlen.c.html for further details.
	 */

	/* First or next run? */
	if (str != nullptr) {
		charPtr = str;
		nst->saveptr = nullptr;
		nst->separator = separator;
		nst->instrlen = instrlen;

		/* Create a separator mask - put the separator to each byte of the integer: */
		nst->separatorMask = 0;
		for (i = 0; i < sizeof(longword) * 8; i += 8) {
			nst->separatorMask |= (((MAGIC_INT) separator) << i);
		}

	} else if (nst->saveptr != nullptr && nst->instrlen > 0) {
		/* Next run: */
		charPtr = nst->saveptr;
	} else {
		/* Last run: */
		return nullptr;
	}

	/*
	 * Handle the first few characters by reading one character at a time.
	 * Do this until CHAR_PTR is aligned on a longword boundary:
	 */
	len = 0;
	beginning = charPtr;
	for (; ((unsigned long int) charPtr & (sizeof(longword) - 1)) != 0; ++charPtr) {
		/* We found the separator - return the string immediately: */
		if (*charPtr == nst->separator) {
			*strlen = len;
			nst->saveptr = charPtr + 1;
			if (nst->instrlen > 0) {
				nst->instrlen--;
			}
			return beginning;
		}
		len++;

		/* This is end of string - return the string as it is: */
		nst->instrlen--;
		if (nst->instrlen == 0) {
			*strlen = len;
			nst->saveptr = nullptr;
			return beginning;
		}
	}

#define FOUND(A)                                                                                   \
	{                                                                                              \
		nst->saveptr = cp + (A) + 1;                                                               \
		*strlen = len + A;                                                                         \
		nst->instrlen -= A + 1;                                                                    \
		return beginning;                                                                          \
	}

	/* Go across the string word by word: */
	longwordPtr = (MAGIC_INT*) charPtr;
	for (;;) {
		/*
		 * Get the current item and move to the next one. The XOR operator does the following thing:
		 * If the byte is separator, sets it to zero. Otherwise it is nonzero.
		 */
		longword = *longwordPtr++;
		longwordMask = longword ^ nst->separatorMask;

		/* Check the end of string. If we don't have enough bytes for the next longword, return what
		 * we have: */
		if (nst->instrlen < sizeof(longword)) {
			/* The separator could be just before the end of the buffer: */
			cp = (const unsigned char*) (longwordPtr - 1);
			for (i = 0; i < nst->instrlen; i++) {
				if (cp[i] == nst->separator) {
					/* Correct string length: */
					*strlen = len + i;

					/* If the separator is the last character in the buffer: */
					if (nst->instrlen == i + 1) {
						nst->saveptr = nullptr;
					} else {
						nst->saveptr = cp + i + 1;
						nst->instrlen -= i + 1;
					}
					return beginning;
				}
			}
			/* Separator not found, so return the rest of buffer: */
			*strlen = len + nst->instrlen;
			nst->saveptr = nullptr;
			return beginning;
		}

		/*
		 * Here we will try to find the separator:
		 * Add magic_bits to longword
		 *             |      Set those bits which were unchanged by the addition
		 *             |             |        Look at the hole bits. If some of them is unchanged,
		 *             |             |            |    most likely there is zero byte, ie. our
		 * separator. v             v            v */
		if ((((longwordMask + MAGIC_BITS) ^ ~longwordMask) & MAGIC_BITS_NEG) != 0) {
			/* Convert the integer back to the string: */
			cp = (const unsigned char*) (longwordPtr - 1);

			/* Find out which byte is the separator: */
			if (cp[0] == nst->separator)
				FOUND(0);
			if (cp[1] == nst->separator)
				FOUND(1);
			if (cp[2] == nst->separator)
				FOUND(2);
			if (cp[3] == nst->separator)
				FOUND(3);
			if (sizeof(longword) > 4) {
				if (cp[4] == nst->separator)
					FOUND(4);
				if (cp[5] == nst->separator)
					FOUND(5);
				if (cp[6] == nst->separator)
					FOUND(6);
				if (cp[7] == nst->separator)
					FOUND(7);
			}
		}

		/* Add the length: */
		len += sizeof(longword);
		nst->instrlen -= sizeof(longword);
	}
}

void SIPPlugin::parserFieldValue(
	const unsigned char* line,
	int linelen,
	int skip,
	char* dst,
	unsigned int dstlen)
{
	ParserStrtokT pst;
	unsigned int newlen;

	/* Skip the leading characters: */
	line += skip;
	linelen -= skip;

	/* Skip whitespaces: */
	while (isalnum(*line) == 0 && linelen > 0) {
		line++;
		linelen--;
	}

	/* Trim trailing whitespaces: */
	while (isalnum(line[linelen - 1]) == 0 && linelen > 0) {
		linelen--;
	}

	/* Find the first field value: */
	line = parserStrtok(line, linelen, ';', &newlen, &pst);

	/* Trim to the length of the destination buffer: */
	if (newlen > dstlen - 1) {
		newlen = dstlen - 1;
	}

	/* Copy the buffer: */
	memcpy(dst, line, newlen);
	dst[newlen] = 0;
}

void SIPPlugin::parserFieldUri(
	const unsigned char* line,
	int linelen,
	int skip,
	char* dst,
	unsigned int dstlen)
{
	ParserStrtokT pst;
	unsigned int newlen;
	unsigned int finalLen;
	uint32_t uri;
	const unsigned char* start;

	/* Skip leading characters: */
	line += skip;
	linelen -= skip;

	/* Find the first colon, this could be probably a part of the SIP uri: */
	start = nullptr;
	finalLen = 0;
	line = parserStrtok(line, linelen, ':', &newlen, &pst);
	while (line != nullptr && newlen > 0) {
		/* Add the linelen to get the position of the first colon: */
		line += newlen;
		newlen = linelen - newlen;
		/* The characters before colon must be sip or sips: */
		uri = SIP_UCFOUR(*((uint32_t*) (line - SIP_URI_LEN)));
		if (uri == SIP_URI) {
			start = line - SIP_URI_LEN;
			finalLen = newlen + SIP_URI_LEN;
			break;
		} else if (uri == SIP_URIS) {
			start = line - SIP_URIS_LEN;
			finalLen = newlen + SIP_URIS_LEN;
			break;
		}

		/* Not a sip uri - find the next colon: */
		line = parserStrtok(nullptr, 0, ' ', &newlen, &pst);
	}

	/* No URI found? Exit: */
	if (start == nullptr) {
		return;
	}

	/* Now we have the beginning of the SIP uri. Find the end - >, ; or EOL: */
	line = parserStrtok(start, finalLen, '>', &newlen, &pst);
	if (newlen < finalLen) {
		finalLen = newlen;
	} else {
		/* No bracket found, try to find at least a semicolon: */
		line = parserStrtok(start, finalLen, ';', &newlen, &pst);
		if (newlen < finalLen) {
			finalLen = newlen;
		} else {
			/* Nor semicolon found. Strip the whitespaces from the end of line and use the whole
			 * line: */
			while (isalpha(start[finalLen - 1]) == 0 && finalLen > 0) {
				finalLen--;
			}
		}
	}

	/* Trim to the length of the destination buffer: */
	if (finalLen > dstlen - 1) {
		finalLen = dstlen - 1;
	}

	/* Copy the buffer: */
	memcpy(dst, start, finalLen);
	dst[finalLen] = 0;
}

int SIPPlugin::parserProcessSip(const Packet& pkt, RecordExtSIP* sipData)
{
	const unsigned char* payload;
	const unsigned char* line;
	int caplen;
	unsigned int lineLen = 0;
	int fieldLen;
	ParserStrtokT lineParser;
	uint32_t firstBytes4;
	uint32_t firstBytes3;
	uint32_t firstBytes2;

	/* Skip the packet headers: */
	payload = (unsigned char*) pkt.payload;
	caplen = pkt.payloadLen;

	/* Grab the first line of the payload: */
	line = parserStrtok(payload, caplen, '\n', &lineLen, &lineParser);

	/* Get Request-URI for SIP requests from first line of the payload: */
	if (sipData->msgType <= 10) {
		m_requests++;
		/* Note: First SIP request line has syntax: "Method SP Request-URI SP SIP-Version CRLF"
		 * (SP=single space) */
		ParserStrtokT firstLineParser;
		const unsigned char* lineToken;
		unsigned int lineTokenLen;

		/* Get Method part of request: */
		lineToken = parserStrtok(line, lineLen, ' ', &lineTokenLen, &firstLineParser);
		/* Get Request-URI part of request: */
		lineToken = parserStrtok(nullptr, 0, ' ', &lineTokenLen, &firstLineParser);

		if (lineToken != nullptr) {
			/* Request-URI: */
			parserFieldValue(
				lineToken,
				lineTokenLen,
				0,
				sipData->requestUri,
				sizeof(sipData->requestUri));
		} else {
			/* Not found */
			sipData->requestUri[0] = 0;
		}
	} else {
		m_responses++;
		if (sipData->msgType == 99) {
			ParserStrtokT firstLineParser;
			const unsigned char* lineToken;
			unsigned int lineTokenLen;
			lineToken = parserStrtok(line, lineLen, ' ', &lineTokenLen, &firstLineParser);
			lineToken = parserStrtok(nullptr, 0, ' ', &lineTokenLen, &firstLineParser);
			sipData->statusCode = SIP_MSG_TYPE_UNDEFINED;
			if (lineToken) {
				sipData->statusCode = atoi((const char*) lineToken);
			}
		}
	}

	m_total++;
	/* Go to the next line. Divide the packet payload by line breaks and process them one by one: */
	line = parserStrtok(nullptr, 0, ' ', &lineLen, &lineParser);

	/*
	 * Process all the remaining attributes:
	 */
	while (line != nullptr && lineLen > 1) {
		/* Get first 4, 3 and 2 bytes and compare them with searched SIP fields: */
		firstBytes4 = SIP_UCFOUR(*((uint32_t*) line));
		firstBytes3 = SIP_UCTHREE(*((uint32_t*) line));
		firstBytes2 = SIP_UCTWO(*((uint32_t*) line));

		/* From: */
		if (firstBytes4 == SIP_FROM4) {
			parserFieldUri(
				line,
				lineLen,
				5,
				sipData->callingParty,
				sizeof(sipData->callingParty));
		} else if (firstBytes2 == SIP_FROM2) {
			parserFieldUri(
				line,
				lineLen,
				2,
				sipData->callingParty,
				sizeof(sipData->callingParty));
		}

		/* To: */
		else if (firstBytes3 == SIP_TO3) {
			parserFieldUri(
				line,
				lineLen,
				3,
				sipData->calledParty,
				sizeof(sipData->calledParty));
		} else if (firstBytes2 == SIP_TO2) {
			parserFieldUri(
				line,
				lineLen,
				2,
				sipData->calledParty,
				sizeof(sipData->calledParty));
		}

		/* Via: */
		else if (firstBytes4 == SIP_VIA4) {
			/* Via fields can be present more times. Include all and separate them by semicolons: */
			if (sipData->via[0] == 0) {
				parserFieldValue(line, lineLen, 4, sipData->via, sizeof(sipData->via));
			} else {
				fieldLen = strlen(sipData->via);
				sipData->via[fieldLen++] = ';';
				parserFieldValue(
					line,
					lineLen,
					4,
					sipData->via + fieldLen,
					sizeof(sipData->via) - fieldLen);
			}
		} else if (firstBytes2 == SIP_VIA2) {
			if (sipData->via[0] == 0) {
				parserFieldValue(line, lineLen, 2, sipData->via, sizeof(sipData->via));
			} else {
				fieldLen = strlen(sipData->via);
				sipData->via[fieldLen++] = ';';
				parserFieldValue(
					line,
					lineLen,
					2,
					sipData->via + fieldLen,
					sizeof(sipData->via) - fieldLen);
			}
		}

		/* Call-ID: */
		else if (firstBytes4 == SIP_CALLID4) {
			parserFieldValue(line, lineLen, 8, sipData->callId, sizeof(sipData->callId));
		} else if (firstBytes2 == SIP_CALLID2) {
			parserFieldValue(line, lineLen, 2, sipData->callId, sizeof(sipData->callId));
		}

		/* User-Agent: */
		else if (firstBytes4 == SIP_USERAGENT4) {
			parserFieldValue(
				line,
				lineLen,
				11,
				sipData->userAgent,
				sizeof(sipData->userAgent));
		}

		/* CSeq: */
		else if (firstBytes4 == SIP_CSEQ4) {
			/* Save CSeq: */
			parserFieldValue(line, lineLen, 5, sipData->cseq, sizeof(sipData->cseq));
		}

		/* Go to the next line: */
		line = parserStrtok(nullptr, 0, ' ', &lineLen, &lineParser);
	}

	return 0;
}

} // namespace ipxp
