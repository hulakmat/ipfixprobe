/**
 * \file ssdp.hpp
 * \brief Plugin for parsing ssdp traffic.
 * \author Ondrej Sedlacek xsedla1o@stud.fit.vutbr.cz
 * \date 2020
 */
/*
 * Copyright (C) 2020 CESNET
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
 * This software is provided as is'', and any express or implied
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

#ifndef IPXP_PROCESS_SSDP_HPP
#define IPXP_PROCESS_SSDP_HPP

#include <cstring>
#include <sstream>
#include <string>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/process.hpp>

namespace Ipxp {

#define SSDP_URN_LEN 511
#define SSDP_SERVER_LEN 255
#define SSDP_USER_AGENT_LEN 255

#define SSDP_UNIREC_TEMPLATE "SSDP_LOCATION_PORT,SSDP_NT,SSDP_SERVER,SSDP_ST,SSDP_USER_AGENT"

UR_FIELDS(
	uint16 SSDP_LOCATION_PORT,
	string SSDP_NT,
	string SSDP_SERVER,
	string SSDP_ST,
	string SSDP_USER_AGENT)

/**
 * \brief Flow record extension header for storing parsed SSDP packets.
 */
struct RecordExtSSDP : public RecordExt {
	static int s_registeredId;

	uint16_t port;
	char nt[SSDP_URN_LEN];
	char st[SSDP_URN_LEN];
	char server[SSDP_SERVER_LEN];
	char userAgent[SSDP_USER_AGENT_LEN];

	/**
	 * \brief Constructor.
	 */
	RecordExtSSDP()
		: RecordExt(s_registeredId)
	{
		port = 0;
		nt[0] = 0;
		st[0] = 0;
		server[0] = 0;
		userAgent[0] = 0;
	}

#ifdef WITH_NEMEA
	virtual void fillUnirec(ur_template_t* tmplt, void* record)
	{
		ur_set(tmplt, record, F_SSDP_LOCATION_PORT, port);
		ur_set_string(tmplt, record, F_SSDP_NT, nt);
		ur_set_string(tmplt, record, F_SSDP_SERVER, server);
		ur_set_string(tmplt, record, F_SSDP_ST, st);
		ur_set_string(tmplt, record, F_SSDP_USER_AGENT, userAgent);
	}

	const char* getUnirecTmplt() const
	{
		return SSDP_UNIREC_TEMPLATE;
	}
#endif

	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		int length = 2;

		int ntLen = strlen(nt);
		int serverLen = strlen(server);
		int stLen = strlen(st);
		int userAgentLen = strlen(userAgent);

		if (length + ntLen + serverLen + stLen + userAgentLen + 8 > size) {
			return -1;
		}

		*(uint16_t*) (buffer) = ntohs(port);

		if (ntLen >= 255) {
			buffer[length++] = 255;
			*(uint16_t*) (buffer + length) = ntohs(ntLen);
			length += sizeof(uint16_t);
		} else {
			buffer[length++] = ntLen;
		}
		memcpy(buffer + length, nt, ntLen);
		length += ntLen;

		buffer[length++] = serverLen;
		memcpy(buffer + length, server, serverLen);
		length += serverLen;

		if (stLen >= 255) {
			buffer[length++] = 255;
			*(uint16_t*) (buffer + length) = ntohs(stLen);
			length += sizeof(uint16_t);
		} else {
			buffer[length++] = stLen;
		}
		memcpy(buffer + length, st, stLen);
		length += stLen;

		buffer[length++] = userAgentLen;
		memcpy(buffer + length, userAgent, userAgentLen);
		length += userAgentLen;

		return length;
	}

	const char** getIpfixTmplt() const
	{
		static const char* ipfixTmplt[] = {IPFIX_SSDP_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};

		return ipfixTmplt;
	}

	std::string getText() const
	{
		std::ostringstream out;
		out << "ssdpport=" << port << ",nt=\"" << nt << "\""
			<< ",server=\"" << server << "\""
			<< ",st=\"" << st << "\""
			<< ",useragent=\"" << userAgent << "\"";
		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing SSDP packets.
 */
class SSDPPlugin : public ProcessPlugin {
public:
	SSDPPlugin();
	~SSDPPlugin();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const { return new OptionsParser("ssdp", "Parse SSDP traffic"); }
	std::string getName() const { return "ssdp"; }
	RecordExt* getExt() const { return new RecordExtSSDP(); }
	ProcessPlugin* copy();

	int postCreate(Flow& rec, const Packet& pkt);
	int preUpdate(Flow& rec, Packet& pkt);
	void finish(bool printStats);

	/**
	 * \brief Struct passed to parse_headers function.
	 */
	struct HeaderParserConf {
		const char** headers; /**< Pointer to array of header strings. */
		uint8_t ipVersion; /**< IP version of source IP address. */
		RecordExtSSDP* ext; /**< Pointer to allocated record exitension. */
		unsigned selectCnt; /**< Number of selected headers. */
		int* select; /**< Array of selected header indices. */
	};

private:
	RecordExtSSDP* m_record; /**< Pointer to allocated record extension */
	uint32_t m_notifies; /**< Total number of parsed SSDP notifies. */
	uint32_t m_searches; /**< Total number of parsed SSDP m-searches. */
	uint32_t m_total; /**< Total number of parsed SSDP packets. */

	uint16_t parseLocPort(const char* data, unsigned dataLen, uint8_t ipVersion);
	bool getHeaderVal(const char** data, const char* header, const int len);
	void parseHeaders(const uint8_t* data, size_t payloadLen, HeaderParserConf conf);
	void parseSsdpMessage(Flow& rec, const Packet& pkt);
	void appendValue(char* currEntry, unsigned entryMax, const char* value, unsigned valueLen);
};

} // namespace ipxp
#endif /* IPXP_PROCESS_SSDP_HPP */
