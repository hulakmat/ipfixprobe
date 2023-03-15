/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022, CESNET z.s.p.o.
 */

/**
 * \file tls_parser.cpp
 * \brief Class for parsing TLS traffic.
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
 * \date 2022
 */

#include "tls_parser.hpp"
#include <endian.h>

namespace Ipxp {
TLSParser::TLSParser()
{
	m_tls_hs = NULL;
}

uint64_t quicGetVariableLength(uint8_t* start, uint64_t& offset)
{
	// find out length of parameter field (and load parameter, then move offset) , defined in:
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-summary-of-integer-encoding
	// this approach is used also in length field , and other QUIC defined fields.
	uint64_t tmp = 0;

	uint8_t twoBits = *(start + offset) & 0xC0;

	switch (twoBits) {
	case 0:
		tmp = *(start + offset) & 0x3F;
		offset += sizeof(uint8_t);
		return tmp;

	case 64:
		tmp = be16toh(*(uint16_t*) (start + offset)) & 0x3FFF;
		offset += sizeof(uint16_t);
		return tmp;

	case 128:
		tmp = be32toh(*(uint32_t*) (start + offset)) & 0x3FFFFFFF;
		offset += sizeof(uint32_t);
		return tmp;

	case 192:
		tmp = be64toh(*(uint64_t*) (start + offset)) & 0x3FFFFFFFFFFFFFFF;
		offset += sizeof(uint64_t);
		return tmp;

	default:
		return 0;
	}
} // quic_get_variable_length

bool TLSParser::tlsIsGreaseValue(uint16_t val)
{
	if (val != 0 && !(val & ~(0xFAFA)) && ((0x00FF & val) == (val >> 8))) {
		return true;
	}
	return false;
}

void TLSParser::tlsGetQuicUserAgent(TLSData& data, char* buffer, size_t bufferSize)
{
	// compute end of quic_transport_parameters
	const uint16_t quicTransportParamsLen = ntohs(*(uint16_t*) data.start);
	const uint8_t* quicTransportParamsEnd
		= data.start + quicTransportParamsLen + sizeof(quicTransportParamsLen);

	if (quicTransportParamsEnd > data.end) {
		return;
	}

	uint64_t offset = 0;
	uint64_t param = 0;
	uint64_t length = 0;

	while (data.start + offset < quicTransportParamsEnd) {
		param = quicGetVariableLength((uint8_t*) data.start, offset);
		length = quicGetVariableLength((uint8_t*) data.start, offset);
		if (param == TLS_EXT_GOOGLE_USER_AGENT) {
			if (length + (size_t) 1 > bufferSize) {
				length = bufferSize - 1;
			}
			memcpy(buffer, data.start + offset, length);
			buffer[length] = 0;
			data.obejctsParsed++;
		}
		offset += length;
	}
	return;
}

void TLSParser::tlsGetServerName(TLSData& data, char* buffer, size_t bufferSize)
{
	uint16_t listLen = ntohs(*(uint16_t*) data.start);
	uint16_t offset = sizeof(listLen);
	const uint8_t* listEnd = data.start + listLen + offset;
	size_t buffOffset = 0;

	if (listEnd > data.end) {
		// data.valid = false;
		return;
	}

	while (data.start + sizeof(TlsExtSni) + offset < listEnd) {
		TlsExtSni* tmpSni = (TlsExtSni*) (data.start + offset);
		uint16_t sniLen = ntohs(tmpSni->length);

		offset += sizeof(TlsExtSni);
		if (data.start + offset + sniLen > listEnd) {
			break;
		}
		if (sniLen + (size_t) 1 + buffOffset > bufferSize) {
			sniLen = bufferSize - 1 - buffOffset;
		}
		memcpy(buffer + buffOffset, data.start + offset, sniLen);

		buffOffset += sniLen + 1;
		buffer[buffOffset - 1] = 0;
		data.obejctsParsed++;
		offset += ntohs(tmpSni->length);
	}
	return;
}

void TLSParser::tlsGetAlpn(TLSData& data, char* buffer, size_t bufferSize)
{
	uint16_t listLen = ntohs(*(uint16_t*) data.start);
	uint16_t offset = sizeof(listLen);
	const uint8_t* listEnd = data.start + listLen + offset;

	if (listEnd > data.end) {
		// data.valid = false;
		return;
	}
	if (buffer[0] != 0) {
		return;
	}

	uint16_t alpnWritten = 0;

	while (data.start + sizeof(uint8_t) + offset < listEnd) {
		uint8_t alpnLen = *(uint8_t*) (data.start + offset);
		const uint8_t* alpnStr = data.start + offset + sizeof(uint8_t);

		offset += sizeof(uint8_t) + alpnLen;
		if (data.start + offset > listEnd) {
			break;
		}
		if (alpnWritten + alpnLen + (size_t) 2 >= bufferSize) {
			break;
		}

		if (alpnWritten != 0) {
			buffer[alpnWritten++] = ';';
		}
		memcpy(buffer + alpnWritten, alpnStr, alpnLen);
		alpnWritten += alpnLen;
		buffer[alpnWritten] = 0;
	}
	return;
} // TLSParser::tls_get_alpn

TlsHandshake TLSParser::tlsGetHandshake()
{
	if (m_tls_hs != NULL) {
		return *m_tls_hs;
	}
	return {};
}

bool TLSParser::tlsCheckHandshake(TLSData& payload)
{
	m_tls_hs = (TlsHandshake*) payload.start;
	const uint8_t tmpHsType = m_tls_hs->type;

	if (payload.start + sizeof(TlsHandshake) > payload.end
		|| !(
			tmpHsType == TLS_HANDSHAKE_CLIENT_HELLO
			|| tmpHsType == TLS_HANDSHAKE_SERVER_HELLO)) {
		return false;
	}
	if (payload.start + 44 > payload.end || m_tls_hs->version.major != 3 || m_tls_hs->version.minor < 1
		|| m_tls_hs->version.minor > 3) {
		return false;
	}
	payload.start += sizeof(TlsHandshake);
	return true;
}

bool TLSParser::tlsCheckRec(TLSData& payload)
{
	TlsRec* tls = (TlsRec*) payload.start;

	if (payload.start + sizeof(TlsRec) > payload.end || !tls || tls->type != TLS_HANDSHAKE
		|| tls->version.major != 3 || tls->version.minor > 3) {
		return false;
	}
	payload.start += sizeof(TlsRec);
	return true;
}

bool TLSParser::tlsSkipRandom(TLSData& payload)
{
	if (payload.start + 32 > payload.end) {
		return false;
	}
	payload.start += 32;
	return true;
}

bool TLSParser::tlsSkipSessid(TLSData& payload)
{
	uint8_t sessIdLen = *(uint8_t*) payload.start;

	if (payload.start + sizeof(sessIdLen) + sessIdLen > payload.end) {
		return false;
	}
	payload.start += sizeof(sessIdLen) + sessIdLen;
	return true;
}

bool TLSParser::tlsSkipCipherSuites(TLSData& payload)
{
	uint16_t cipherSuiteLen = ntohs(*(uint16_t*) payload.start);

	if (payload.start + sizeof(cipherSuiteLen) + +cipherSuiteLen > payload.end) {
		return false;
	}
	payload.start += sizeof(cipherSuiteLen) + cipherSuiteLen;
	return true;
}

bool TLSParser::tlsSkipCompressionMet(TLSData& payload)
{
	uint8_t compressionMetLen = *(uint8_t*) payload.start;

	if (payload.start + sizeof(compressionMetLen) + compressionMetLen > payload.end) {
		return false;
	}
	payload.start += sizeof(compressionMetLen) + compressionMetLen;
	return true;
}

bool TLSParser::tlsCheckExtLen(TLSData& payload)
{
	const uint8_t* extEnd = payload.start + ntohs(*(uint16_t*) payload.start) + sizeof(uint16_t);

	payload.start += 2;
	if (extEnd > payload.end) {
		return false;
	}
	if (extEnd <= payload.end) {
		payload.end = extEnd;
	}
	return true;
}

bool TLSParser::tlsGetJa3CipherSuites(std::string& ja3, TLSData& data)
{
	uint16_t cipherSuitesLength = ntohs(*(uint16_t*) data.start);
	uint16_t typeId = 0;
	const uint8_t* sectionEnd = data.start + cipherSuitesLength;

	if (data.start + cipherSuitesLength + 1 > data.end) {
		// data.valid = false;
		return false;
	}
	data.start += sizeof(cipherSuitesLength);

	for (; data.start <= sectionEnd; data.start += sizeof(uint16_t)) {
		typeId = ntohs(*(uint16_t*) (data.start));
		if (!tlsIsGreaseValue(typeId)) {
			ja3 += std::to_string(typeId);
			if (data.start < sectionEnd) {
				ja3 += '-';
			}
		}
	}
	ja3 += ',';
	return true;
}

std::string TLSParser::tlsGetJa3EcplipticCurves(TLSData& data)
{
	std::string collectedTypes;
	uint16_t typeId = 0;
	uint16_t listLen = ntohs(*(uint16_t*) data.start);
	const uint8_t* listEnd = data.start + listLen + sizeof(listLen);
	uint16_t offset = sizeof(listLen);

	if (listEnd > data.end) {
		// data.valid = false;
		return "";
	}

	while (data.start + sizeof(uint16_t) + offset <= listEnd) {
		typeId = ntohs(*(uint16_t*) (data.start + offset));
		offset += sizeof(uint16_t);
		if (!tlsIsGreaseValue(typeId)) {
			collectedTypes += std::to_string(typeId);

			if (data.start + sizeof(uint16_t) + offset <= listEnd) {
				collectedTypes += '-';
			}
		}
	}
	return collectedTypes;
}

std::string TLSParser::tlsGetJa3EcPointFormats(TLSData& data)
{
	std::string collectedFormats;
	uint8_t listLen = *data.start;
	uint16_t offset = sizeof(listLen);
	const uint8_t* listEnd = data.start + listLen + offset;
	uint8_t format;

	if (listEnd > data.end) {
		// data.valid = false;
		return "";
	}

	while (data.start + sizeof(uint8_t) + offset <= listEnd) {
		format = *(data.start + offset);
		collectedFormats += std::to_string((int) format);
		offset += sizeof(uint8_t);
		if (data.start + sizeof(uint8_t) + offset <= listEnd) {
			collectedFormats += '-';
		}
	}
	return collectedFormats;
}
} // namespace ipxp
