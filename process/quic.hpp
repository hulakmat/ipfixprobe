/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021-2022, CESNET z.s.p.o.
 */

/**
 * \file quic.hpp
 * \brief Plugin for enriching flows for quic data.
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
 * \date 2022
 */

#ifndef IPXP_PROCESS_QUIC_HPP
#define IPXP_PROCESS_QUIC_HPP

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include "quic_parser.hpp"
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/utils.hpp>
#include <sstream>

namespace Ipxp {
#define QUIC_UNIREC_TEMPLATE "QUIC_SNI,QUIC_USER_AGENT,QUIC_VERSION"
UR_FIELDS(string QUIC_SNI, string QUIC_USER_AGENT, uint32 QUIC_VERSION)

/**
 * \brief Flow record extension header for storing parsed QUIC packets.
 */
struct RecordExtQUIC : public RecordExt {
	static int s_registeredId;
	char sni[BUFF_SIZE] = {0};
	char userAgent[BUFF_SIZE] = {0};
	uint32_t quicVersion;

	RecordExtQUIC()
		: RecordExt(s_registeredId)
	{
		sni[0] = 0;
		userAgent[0] = 0;
		quicVersion = 0;
	}

#ifdef WITH_NEMEA
	virtual void fillUnirec(ur_template_t* tmplt, void* record)
	{
		ur_set_string(tmplt, record, F_QUIC_SNI, sni);
		ur_set_string(tmplt, record, F_QUIC_USER_AGENT, userAgent);
		ur_set(tmplt, record, F_QUIC_VERSION, quicVersion);
	}

	const char* getUnirecTmplt() const
	{
		return QUIC_UNIREC_TEMPLATE;
	}

#endif // ifdef WITH_NEMEA

	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		uint16_t lenSni = strlen(sni);
		uint16_t lenUserAgent = strlen(userAgent);
		uint16_t lenVersion = sizeof(quicVersion);
		int pos = 0;

		if ((lenSni + 3) + (lenUserAgent + 3) + lenVersion > size) {
			return -1;
		}

		pos += variable2ipfixBuffer(buffer + pos, (uint8_t*) sni, lenSni);
		pos += variable2ipfixBuffer(buffer + pos, (uint8_t*) userAgent, lenUserAgent);
		*(uint32_t*) (buffer + pos) = htonl(quicVersion);
		pos += lenVersion;
		return pos;
	}

	const char** getIpfixTmplt() const
	{
		static const char* ipfixTemplate[] = {IPFIX_QUIC_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};

		return ipfixTemplate;
	}

	std::string getText() const
	{
		std::ostringstream out;

		out << "quicsni=\"" << sni << "\""
			<< "quicuseragent=\"" << userAgent << "\""
			<< "quicversion=\"" << quicVersion << "\"";
		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing QUIC packets.
 */
class QUICPlugin : public ProcessPlugin {
public:
	QUICPlugin();
	~QUICPlugin();
	void init(const char* params);
	void close();
	RecordExt* getExt() const { return new RecordExtQUIC(); }

	OptionsParser* getParser() const { return new OptionsParser("quic", "Parse QUIC traffic"); }

	std::string getName() const { return "quic"; }

	ProcessPlugin* copy();

	int preCreate(Packet& pkt);
	int postCreate(Flow& rec, const Packet& pkt);
	int preUpdate(Flow& rec, Packet& pkt);
	int postUpdate(Flow& rec, const Packet& pkt);
	void addQuic(Flow& rec, const Packet& pkt);
	void finish(bool printStats);

private:
	bool processQuic(RecordExtQUIC*, const Packet&);
	int m_parsed_initial;
	RecordExtQUIC* m_quic_ptr;
};
} // namespace ipxp
#endif /* IPXP_PROCESS_QUIC_HPP */
