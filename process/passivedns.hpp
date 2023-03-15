/**
 * \file passivedns.h
 * \brief Plugin for exporting DNS A and AAAA records.
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2017
 */
/*
 * Copyright (C) 2017 CESNET
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

#ifndef IPXP_PROCESS_PASSIVEDNS_HPP
#define IPXP_PROCESS_PASSIVEDNS_HPP

#include <config.h>
#include <sstream>
#include <string>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include "dns-utils.hpp"
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/process.hpp>

namespace Ipxp {

#define DNS_UNIREC_TEMPLATE "DNS_ID,DNS_ATYPE,DNS_NAME,DNS_RR_TTL,DNS_IP"

UR_FIELDS(uint16 DNS_ID, uint16 DNS_ATYPE, string DNS_NAME, uint32 DNS_RR_TTL, ipaddr DNS_IP)

/**
 * \brief Flow record extension header for storing parsed DNS packets.
 */
struct RecordExtPassiveDNS : public RecordExt {
	static int s_registeredId;
	uint16_t atype;
	uint16_t id;
	uint8_t ipVersion;
	char aname[255];
	uint32_t rrTtl;
	ipaddr_t ip;

	/**
	 * \brief Constructor.
	 */
	RecordExtPassiveDNS()
		: RecordExt(s_registeredId)
	{
		id = 0;
		atype = 0;
		ipVersion = 0;
		aname[0] = 0;
		rrTtl = 0;
	}

#ifdef WITH_NEMEA
	virtual void fillUnirec(ur_template_t* tmplt, void* record)
	{
		ur_set(tmplt, record, F_DNS_ID, id);
		ur_set(tmplt, record, F_DNS_ATYPE, atype);
		ur_set_string(tmplt, record, F_DNS_NAME, aname);
		ur_set(tmplt, record, F_DNS_RR_TTL, rrTtl);
		if (ipVersion == 4) {
			ur_set(tmplt, record, F_DNS_IP, ip_from_4_bytes_be((char*) &ip.v4));
		} else if (ipVersion == 6) {
			ur_set(tmplt, record, F_DNS_IP, ip_from_16_bytes_be((char*) ip.v6));
		}
	}

	const char* getUnirecTmplt() const
	{
		return DNS_UNIREC_TEMPLATE;
	}
#endif

	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		int length;
		int rdataLen = (ipVersion == 4 ? 4 : 16);

		length = strlen(aname);
		if (length + rdataLen + 10 > size) {
			return -1;
		}

		*(uint16_t*) (buffer) = ntohs(id);
		*(uint32_t*) (buffer + 2) = ntohl(rrTtl);
		*(uint16_t*) (buffer + 6) = ntohs(atype);
		buffer[8] = rdataLen;
		if (ipVersion == 4) {
			*(uint32_t*) (buffer + 9) = ntohl(ip.v4);
		} else {
			memcpy(buffer + 9, ip.v6, sizeof(ip.v6));
		}
		buffer[9 + rdataLen] = length;
		memcpy(buffer + rdataLen + 10, aname, length);

		return length + rdataLen + 10;
	}

	const char** getIpfixTmplt() const
	{
		static const char* ipfixTmplt[] = {IPFIX_PASSIVEDNS_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};

		return ipfixTmplt;
	}

	std::string getText() const
	{
		char ipStr[INET6_ADDRSTRLEN];
		std::ostringstream out;

		if (ipVersion == 4) {
			inet_ntop(AF_INET, (const void*) &ip.v4, ipStr, INET6_ADDRSTRLEN);
		} else if (ipVersion == 6) {
			inet_ntop(AF_INET6, (const void*) &ip.v6, ipStr, INET6_ADDRSTRLEN);
		}

		out << "dnsid=" << id << ",atype=" << atype << ",aname=\"" << aname << "\""
			<< ",rrttl=" << rrTtl << ",ip=" << ipStr;
		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing DNS packets.
 */
class PassiveDNSPlugin : public ProcessPlugin {
public:
	PassiveDNSPlugin();
	~PassiveDNSPlugin();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const
	{
		return new OptionsParser("passivedns", "Parse A, AAAA and PTR records from DNS traffic");
	}
	std::string getName() const { return "passivedns"; }
	RecordExt* getExt() const { return new RecordExtPassiveDNS(); }
	ProcessPlugin* copy();
	int postCreate(Flow& rec, const Packet& pkt);
	int postUpdate(Flow& rec, const Packet& pkt);
	void finish(bool printStats);

private:
	uint32_t m_total; /**< Total number of parsed DNS responses. */
	uint32_t m_parsed_a; /**< Number of parsed A records. */
	uint32_t m_parsed_aaaa; /**< Number of parsed AAAA records. */
	uint32_t m_parsed_ptr; /**< Number of parsed PTR records. */

	const char* m_data_begin; /**< Pointer to begin of payload. */
	uint32_t m_data_len; /**< Length of packet payload. */

	RecordExtPassiveDNS* parseDns(const char* data, unsigned int payloadLen, bool tcp);
	int addExtDns(const char* data, unsigned int payloadLen, bool tcp, Flow& rec);

	std::string get_name(const char* data) const;
	size_t getNameLength(const char* data) const;
	bool processPtrRecord(std::string name, RecordExtPassiveDNS* rec);
	bool strToUint4(std::string str, uint8_t& dst);
};

} // namespace ipxp
#endif /* IPXP_PROCESS_PASSIVEDNS_HPP */
