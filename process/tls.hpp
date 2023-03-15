/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2018-2022, CESNET z.s.p.o.
 */

/**
 * \file tls.hpp
 * \brief Plugin for enriching flows for tls data.
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \date 2022
 */

#ifndef IPXP_PROCESS_TLS_HPP
#define IPXP_PROCESS_TLS_HPP

#include <arpa/inet.h>
#include <cstring>
#include <string>

#include <iomanip>
#include <sstream>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/process.hpp>
#include <ipfixprobe/utils.hpp>
#include <process/tls_parser.hpp>

#define BUFF_SIZE 255

namespace Ipxp {
#define TLS_UNIREC_TEMPLATE "TLS_SNI,TLS_JA3,TLS_ALPN,TLS_VERSION"

UR_FIELDS(string TLS_SNI, string TLS_ALPN, uint16 TLS_VERSION, bytes TLS_JA3)

/**
 * \brief Flow record extension header for storing parsed HTTPS packets.
 */
struct RecordExtTLS : public RecordExt {
	static int s_registeredId;

	uint16_t version;
	char alpn[BUFF_SIZE] = {0};
	char sni[BUFF_SIZE] = {0};
	char ja3Hash[33] = {0};
	uint8_t ja3HashBin[16] = {0};
	std::string ja3;

	/**
	 * \brief Constructor.
	 */
	RecordExtTLS()
		: RecordExt(s_registeredId)
		, version(0)
	{
		alpn[0] = 0;
		sni[0] = 0;
		ja3Hash[0] = 0;
	}

#ifdef WITH_NEMEA
	virtual void fillUnirec(ur_template_t* tmplt, void* record)
	{
		ur_set(tmplt, record, F_TLS_VERSION, version);
		ur_set_string(tmplt, record, F_TLS_SNI, sni);
		ur_set_string(tmplt, record, F_TLS_ALPN, alpn);
		ur_set_var(tmplt, record, F_TLS_JA3, ja3HashBin, 16);
	}

	const char* getUnirecTmplt() const
	{
		return TLS_UNIREC_TEMPLATE;
	}

#endif // ifdef WITH_NEMEA

	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		uint16_t sniLen = strlen(sni);
		uint16_t alpnLen = strlen(alpn);

		uint32_t pos = 0;
		uint32_t reqBuffLen
			= (sniLen + 3) + (alpnLen + 3) + (2) + (16 + 3); // (SNI) + (ALPN) + (VERSION) + (JA3)

		if (reqBuffLen > (uint32_t) size) {
			return -1;
		}

		*(uint16_t*) buffer = ntohs(version);
		pos += 2;

		pos += variable2ipfixBuffer(buffer + pos, (uint8_t*) sni, sniLen);
		pos += variable2ipfixBuffer(buffer + pos, (uint8_t*) alpn, alpnLen);

		buffer[pos++] = 16;
		memcpy(buffer + pos, ja3HashBin, 16);
		pos += 16;

		return pos;
	}

	const char** getIpfixTmplt() const
	{
		static const char* ipfixTemplate[] = {IPFIX_TLS_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};

		return ipfixTemplate;
	}

	std::string getText() const
	{
		std::ostringstream out;

		out << "tlssni=\"" << sni << "\""
			<< ",tlsalpn=\"" << alpn << "\""
			<< ",tlsversion=0x" << std::hex << std::setw(4) << std::setfill('0') << version
			<< ",tlsja3=";
		for (int i = 0; i < 16; i++) {
			out << std::hex << std::setw(2) << std::setfill('0') << (unsigned) ja3HashBin[i];
		}
		return out.str();
	}
};

#define TLS_HANDSHAKE_CLIENT_HELLO 1
#define TLS_HANDSHAKE_SERVER_HELLO 2

#define TLS_EXT_SERVER_NAME 0
#define TLS_EXT_ECLIPTIC_CURVES 10 // AKA supported_groups
#define TLS_EXT_EC_POINT_FORMATS 11
#define TLS_EXT_ALPN 16

/**
 * \brief Flow cache plugin for parsing HTTPS packets.
 */
class TLSPlugin : public ProcessPlugin {
public:
	TLSPlugin();
	~TLSPlugin();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const
	{
		return new OptionsParser("tls", "Parse SNI from TLS traffic");
	}

	std::string getName() const { return "tls"; }

	RecordExtTLS* getExt() const { return new RecordExtTLS(); }

	ProcessPlugin* copy();

	int postCreate(Flow& rec, const Packet& pkt);
	int preUpdate(Flow& rec, Packet& pkt);
	void finish(bool printStats);

private:
	void addTlsRecord(Flow&, const Packet&);
	bool parseTls(const uint8_t*, uint16_t, RecordExtTLS*);
	bool obtainTlsData(TLSData&, RecordExtTLS*, std::string&, uint8_t);

	RecordExtTLS* m_ext_ptr;
	TLSParser m_tls_parser;
	uint32_t m_parsed_sni;
	bool m_flow_flush;
};
} // namespace ipxp
#endif /* IPXP_PROCESS_TLS_HPP */
