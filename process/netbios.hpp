/**
 * \file netbios.h
 * \brief Plugin for parsing netbios traffic.
 * \author Ondrej Sedlacek <xsedla1o@stud.fit.vutbr.cz>
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

#ifndef IPXP_PROCESS_NETBIOS_HPP
#define IPXP_PROCESS_NETBIOS_HPP

#include <cstring>
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

#define NETBIOS_UNIREC_TEMPLATE "NB_NAME,NB_SUFFIX"

UR_FIELDS(string NB_NAME, uint8 NB_SUFFIX)

/**
 * \brief Flow record extension header for storing parsed NETBIOS packets.
 */
struct RecordExtNETBIOS : public RecordExt {
	static int s_registeredId;

	std::string netbiosName;
	char netbiosSuffix;

	RecordExtNETBIOS()
		: RecordExt(s_registeredId)
		, netbiosSuffix(0)
	{
	}

#ifdef WITH_NEMEA
	virtual void fillUnirec(ur_template_t* tmplt, void* record)
	{
		ur_set(tmplt, record, F_NB_SUFFIX, netbiosSuffix);
		ur_set_string(tmplt, record, F_NB_NAME, netbiosName.c_str());
	}

	const char* getUnirecTmplt() const
	{
		return NETBIOS_UNIREC_TEMPLATE;
	}
#endif

	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		int length = netbiosName.length();

		if (2 + length > size) {
			return -1;
		}

		buffer[0] = netbiosSuffix;
		buffer[1] = length;
		memcpy(buffer + 2, netbiosName.c_str(), length);

		return length + 2;
	}

	const char** getIpfixTmplt() const
	{
		static const char* ipfixNetbiosTemplate[]
			= {IPFIX_NETBIOS_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};
		return ipfixNetbiosTemplate;
	}

	std::string getText() const
	{
		std::ostringstream out;
		out << "netbiossuffix=" << netbiosSuffix << ",name=\"" << netbiosName << "\"";
		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing NETBIOS packets.
 */
class NETBIOSPlugin : public ProcessPlugin {
public:
	NETBIOSPlugin();
	~NETBIOSPlugin();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const
	{
		return new OptionsParser("netbios", "Parse netbios traffic");
	}
	std::string getName() const { return "netbios"; }
	RecordExt* getExt() const { return new RecordExtNETBIOS(); }
	ProcessPlugin* copy();

	int postCreate(Flow& rec, const Packet& pkt);
	int postUpdate(Flow& rec, const Packet& pkt);
	void finish(bool printStats);

private:
	int m_total_netbios_packets;

	int addNetbiosExt(Flow& rec, const Packet& pkt);
	bool parseNbns(RecordExtNETBIOS* rec, const Packet& pkt);
	int getQueryCount(const char* payload, uint16_t payloadLength);
	bool storeFirstQuery(const char* payload, RecordExtNETBIOS* rec);
	char compressNbnsNameChar(const char* uncompressed);
	uint8_t getNbnsSuffix(const char* uncompressed);
};

} // namespace ipxp
#endif /* IPXP_PROCESS_NETBIOS_HPP */
