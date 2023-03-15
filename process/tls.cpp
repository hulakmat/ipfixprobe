/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2018-2022, CESNET z.s.p.o.
 */

/**
 * \file tls.cpp
 * \brief Plugin for enriching flows for tls data.
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \author Ondrej Sedlacek <xsedla1o@stud.fit.vutbr.cz>
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \date 2018-2022
 */

#include <iostream>
#include <sstream>

#include <stdio.h>

#include "md5.hpp"
#include "tls.hpp"

namespace Ipxp {
int RecordExtTLS::s_registeredId = -1;

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("tls", []() { return new TLSPlugin(); });

	registerPlugin(&rec);
	RecordExtTLS::s_registeredId = registerExtension();
}

// Print debug message if debugging is allowed.
#ifdef DEBUG_TLS
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_TLS
#define DEBUG_CODE(code) code
#else
#define DEBUG_CODE(code)
#endif

TLSPlugin::TLSPlugin()
	: m_ext_ptr(nullptr)
	, m_parsed_sni(0)
	, m_flow_flush(false)
{
}

TLSPlugin::~TLSPlugin()
{
	close();
}

void TLSPlugin::init(const char* params) {}

void TLSPlugin::close()
{
	if (m_ext_ptr != nullptr) {
		delete m_ext_ptr;
		m_ext_ptr = nullptr;
	}
}

ProcessPlugin* TLSPlugin::copy()
{
	return new TLSPlugin(*this);
}

int TLSPlugin::postCreate(Flow& rec, const Packet& pkt)
{
	addTlsRecord(rec, pkt);
	return 0;
}

int TLSPlugin::preUpdate(Flow& rec, Packet& pkt)
{
	RecordExtTLS* ext = static_cast<RecordExtTLS*>(rec.getExtension(RecordExtTLS::s_registeredId));

	if (ext != nullptr) {
		if (ext->alpn[0] == 0) {
			// Add ALPN from server packet
			parseTls(pkt.payload, pkt.payloadLen, ext);
		}
		return 0;
	}
	addTlsRecord(rec, pkt);

	return 0;
}

bool TLSPlugin::obtainTlsData(
	TLSData& payload,
	RecordExtTLS* rec,
	std::string& ja3,
	uint8_t hsType)
{
	std::string eclipticCurves;
	std::string ecPointFormats;

	while (payload.start + sizeof(TlsExt) <= payload.end) {
		TlsExt* ext = (TlsExt*) payload.start;
		uint16_t length = ntohs(ext->length);
		uint16_t type = ntohs(ext->type);

		payload.start += sizeof(TlsExt);
		if (payload.start + length > payload.end) {
			break;
		}

		if (hsType == TLS_HANDSHAKE_CLIENT_HELLO) {
			if (type == TLS_EXT_SERVER_NAME) {
				m_tls_parser.tlsGetServerName(payload, rec->sni, sizeof(rec->sni));
			} else if (type == TLS_EXT_ECLIPTIC_CURVES) {
				eclipticCurves = m_tls_parser.tlsGetJa3EcplipticCurves(payload);
			} else if (type == TLS_EXT_EC_POINT_FORMATS) {
				ecPointFormats = m_tls_parser.tlsGetJa3EcPointFormats(payload);
			}
		} else if (hsType == TLS_HANDSHAKE_SERVER_HELLO) {
			if (type == TLS_EXT_ALPN) {
				m_tls_parser.tlsGetAlpn(payload, rec->alpn, BUFF_SIZE);
				return true;
			}
		}
		payload.start += length;
		if (!m_tls_parser.tlsIsGreaseValue(type)) {
			ja3 += std::to_string(type);

			if (payload.start + sizeof(TlsExt) <= payload.end) {
				ja3 += '-';
			}
		}
	}
	if (hsType == TLS_HANDSHAKE_SERVER_HELLO) {
		return false;
	}
	ja3 += ',' + eclipticCurves + ',' + ecPointFormats;
	md5GetBin(ja3, rec->ja3HashBin);
	return true;
} // TLSPlugin::obtain_tls_data

bool TLSPlugin::parseTls(const uint8_t* data, uint16_t payloadLen, RecordExtTLS* rec)
{
	TLSData payload = {
		payload.start = data,
		payload.end = data + payloadLen,
		payload.obejctsParsed = 0,
	};
	std::string ja3;

	if (!m_tls_parser.tlsCheckRec(payload)) {
		return false;
	}
	if (!m_tls_parser.tlsCheckHandshake(payload)) {
		return false;
	}
	TlsHandshake tlsHs = m_tls_parser.tlsGetHandshake();

	rec->version = ((uint16_t) tlsHs.version.major << 8) | tlsHs.version.minor;
	ja3 += std::to_string((uint16_t) tlsHs.version.version) + ',';

	if (!m_tls_parser.tlsSkipRandom(payload)) {
		return false;
	}
	if (!m_tls_parser.tlsSkipSessid(payload)) {
		return false;
	}

	if (tlsHs.type == TLS_HANDSHAKE_CLIENT_HELLO) {
		if (!m_tls_parser.tlsGetJa3CipherSuites(ja3, payload)) {
			return false;
		}
		if (!m_tls_parser.tlsSkipCompressionMet(payload)) {
			return false;
		}
	} else if (tlsHs.type == TLS_HANDSHAKE_SERVER_HELLO) {
		payload.start += 2; // Skip cipher suite
		payload.start += 1; // Skip compression method
	} else {
		return false;
	}
	if (!m_tls_parser.tlsCheckExtLen(payload)) {
		return false;
	}
	if (!obtainTlsData(payload, rec, ja3, tlsHs.type)) {
		return false;
	}
	m_parsed_sni = payload.obejctsParsed;
	return payload.obejctsParsed != 0 || !ja3.empty();
} // TLSPlugin::parse_sni

void TLSPlugin::addTlsRecord(Flow& rec, const Packet& pkt)
{
	if (m_ext_ptr == nullptr) {
		m_ext_ptr = new RecordExtTLS();
	}

	if (parseTls(pkt.payload, pkt.payloadLen, m_ext_ptr)) {
		DEBUG_CODE(for (int i = 0; i < 16; i++) { DEBUG_MSG("%02x", ext_ptr->ja3_hash_bin[i]); })
		DEBUG_MSG("\n");
		DEBUG_MSG("%s\n", ext_ptr->sni);
		DEBUG_MSG("%s\n", ext_ptr->alpn);
		rec.addExtension(m_ext_ptr);
		m_ext_ptr = nullptr;
	}
}

void TLSPlugin::finish(bool printStats)
{
	if (printStats) {
		std::cout << "TLS plugin stats:" << std::endl;
		std::cout << "   Parsed SNI: " << m_parsed_sni << std::endl;
	}
}
} // namespace ipxp
