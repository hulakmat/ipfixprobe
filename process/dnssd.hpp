/**
 * \file dnssd.hpp
 * \brief Plugin for parsing dnssd traffic.
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

#ifndef IPXP_PROCESS_DNSSD_HPP
#define IPXP_PROCESS_DNSSD_HPP

#include <algorithm>
#include <cstring>
#include <fstream>
#include <list>
#include <sstream>
#include <string>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include "dns-utils.hpp"
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/process.hpp>

namespace Ipxp {

#define DNSSD_UNIREC_TEMPLATE "DNSSD_QUERIES,DNSSD_RESPONSES"

UR_FIELDS(string DNSSD_QUERIES, string DNSSD_RESPONSES)

class DNSSDOptParser : public OptionsParser {
public:
	bool mTxtAll;
	std::string mConfigFile;

	DNSSDOptParser()
		: OptionsParser("dnssd", "Processing plugin for parsing DNS service discovery packets")
		, mTxtAll(false)
		, mConfigFile("")
	{
		registerOption(
			"t",
			"txt",
			"FILE",
			"Activates processing of all txt records. Allow to specify whitelist txt records file "
			"(file line format: service.domain,txt_key1,txt_key2,...)",
			[this](const char* arg) {
				mTxtAll = true;
				if (arg != nullptr) {
					mConfigFile = arg;
				}
				return true;
			},
			OptionFlags::OPTIONAL_ARGUMENT);
	}
};

struct DnsSdRr {
	std::string name;
	int32_t srvPort;
	std::string srvTarget;
	std::string hinfo[2];
	std::string txt;

	/**
	 * \brief Constructor.
	 */
	DnsSdRr()
	{
		name = std::string();
		srvPort = -1;
		srvTarget = std::string();
		hinfo[0] = std::string();
		txt = std::string();
	}
};

/**
 * \brief Flow record extension header for storing parsed DNSSD packets.
 */
struct RecordExtDNSSD : public RecordExt {
	static int s_registeredId;

	std::list<std::string> queries;
	std::list<DnsSdRr> responses;

	/**
	 * \brief Constructor.
	 */
	RecordExtDNSSD()
		: RecordExt(s_registeredId)
	{
	}

	/**
	 * \brief Concatenates all collected queries to a single string.
	 * \param [in] max_length Size limit for the output string.
	 * \return String of semicolon separated queries.
	 *
	 * The string will allways contain complete entries.
	 */
	std::string queriesToString(size_t maxLength) const
	{
		std::string ret;

		for (auto it = queries.cbegin(); it != queries.cend(); it++) {
			if (maxLength == std::string::npos) {
				ret += *it + ";";
			} else {
				if (ret.length() + (*it).length() + 1 <= maxLength) {
					ret += *it + ";";
				} else {
					break;
				}
			}
		}
		return ret;
	}

	/**
	 * \brief Converts a response to semicolon separated string.
	 * \param [in] response Iterator pointing at the response.
	 */
	std::string responseToString(std::list<DnsSdRr>::const_iterator response) const
	{
		std::stringstream ret;

		ret << response->name + ";";
		ret << response->srvPort << ";";
		ret << response->srvTarget + ";";
		if (!(response->hinfo[0].empty() && response->hinfo[1].empty())) {
			ret << response->hinfo[0] << ":" << response->hinfo[1] + ";";
		} else {
			ret << ";";
		}
		ret << response->txt + ";";
		return ret.str();
	}

	/**
	 * \brief Concatenates all collected responses to single string.
	 * \param [in] max_length Size limit for the output string.
	 * \return String of semicolon separated responses.
	 *
	 * The string will allways contain complete entries.
	 */
	std::string responsesToString(size_t maxLength) const
	{
		std::string ret, part;

		for (auto it = responses.cbegin(); it != responses.cend(); it++) {
			if (maxLength == std::string::npos) {
				ret += responseToString(it);
			} else {
				part = responseToString(it);
				if (ret.length() + part.length() + 1 <= maxLength) {
					ret += part;
				} else {
					break;
				}
			}
		}
		return ret;
	}

#ifdef WITH_NEMEA
	virtual void fillUnirec(ur_template_t* tmplt, void* record)
	{
		ur_set_string(tmplt, record, F_DNSSD_QUERIES, queriesToString(std::string::npos).c_str());
		ur_set_string(
			tmplt,
			record,
			F_DNSSD_RESPONSES,
			responsesToString(std::string::npos).c_str());
	}

	const char* getUnirecTmplt() const
	{
		return DNSSD_UNIREC_TEMPLATE;
	}
#endif

	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		std::string queries = queriesToString(510);
		std::string responses = responsesToString(510);

		int length = 0;
		int qryLen = queries.length();
		int respLen = responses.length();

		if (qryLen + respLen + 6 > size) {
			return -1;
		}

		if (qryLen >= 255) {
			buffer[length++] = 255;
			*(uint16_t*) (buffer + length) = ntohs(qryLen);
			length += sizeof(uint16_t);
		} else {
			buffer[length++] = qryLen;
		}
		memcpy(buffer + length, queries.c_str(), qryLen);
		length += qryLen;

		if (respLen >= 255) {
			buffer[length++] = 255;
			*(uint16_t*) (buffer + length) = ntohs(respLen);
			length += sizeof(uint16_t);
		} else {
			buffer[length++] = respLen;
		}
		memcpy(buffer + length, responses.c_str(), respLen);
		length += respLen;

		return length;
	}

	const char** getIpfixTmplt() const
	{
		static const char* ipfixTmplt[] = {IPFIX_DNSSD_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};

		return ipfixTmplt;
	}

	std::string getText() const
	{
		std::ostringstream out;
		out << "dnssdqueries=\"" << queriesToString(std::string::npos) << "\""
			<< ",dnssdresponses=\"" << responsesToString(std::string::npos) << "\"";
		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing DNSSD packets.
 */
class DNSSDPlugin : public ProcessPlugin {
public:
	DNSSDPlugin();
	~DNSSDPlugin();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const { return new DNSSDOptParser(); }
	std::string getName() const { return "dnssd"; }
	RecordExt* getExt() const { return new RecordExtDNSSD(); }
	ProcessPlugin* copy();

	int postCreate(Flow& rec, const Packet& pkt);
	int postUpdate(Flow& rec, const Packet& pkt);
	void finish(bool printStats);

private:
	bool m_txt_all_records; /**< Indicator whether to process all TXT recods. */
	uint32_t m_queries; /**< Total number of parsed DNS queries. */
	uint32_t m_responses; /**< Total number of parsed DNS responses. */
	uint32_t m_total; /**< Total number of parsed DNS packets. */

	const char* m_data_begin; /**< Pointer to begin of payload. */
	uint32_t m_data_len; /**< Length of packet payload. */

	bool parseDns(const char* data, unsigned int payloadLen, bool tcp, RecordExtDNSSD* rec);
	int addExtDnssd(const char* data, unsigned int payloadLen, bool tcp, Flow& rec);
	void processRdata(
		const char* recordBegin,
		const char* data,
		DnsSdRr& rdata,
		uint16_t type,
		size_t length) const;
	void filteredAppend(RecordExtDNSSD* rec, std::string name);
	void filteredAppend(RecordExtDNSSD* rec, std::string name, uint16_t type, DnsSdRr& rdata);

	std::string get_name(const char* data) const;
	size_t getNameLength(const char* data) const;
	const std::string getServiceStr(std::string& name) const;

	bool parseParams(const std::string& params, std::string& configFile);
	void loadTxtconfig(const char* configFile);
	bool matchesService(
		std::list<std::pair<std::string, std::list<std::string>>>::const_iterator& it,
		std::string& name) const;

	std::list<std::pair<std::string, std::list<std::string>>>
		m_txt_config; /**< Configuration for TXT record filter. */
};

} // namespace Ipxp
#endif /* IPXP_PROCESS_DNSSD_HPP */
