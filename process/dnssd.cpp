/**
 * \file dnssd.cpp
 * \brief Plugin for parsing DNS-SD traffic.
 * \author Ondrej Sedlacek xsedla1o@stud.fit.vutbr.cz
 * \author Jiri Havranek <havranek@cesnet.cz>
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

#include <arpa/inet.h>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>

#ifdef WITH_NEMEA
#include <unirec/unirec.h>
#endif

#include <errno.h>

#include "dnssd.hpp"

namespace Ipxp {

int RecordExtDNSSD::s_registeredId = -1;

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("dnssd", []() { return new DNSSDPlugin(); });
	registerPlugin(&rec);
	RecordExtDNSSD::s_registeredId = registerExtension();
}

// #define DEBUG_DNSSD

// Print debug message if debugging is allowed.
#ifdef DEBUG_DNSSD
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_DNSSD
#define DEBUG_CODE(code) code
#else
#define DEBUG_CODE(code)
#endif

/**
 * \brief Check for label pointer in DNS name.
 */
#define IS_POINTER(ch) ((ch & 0xC0) == 0xC0)

#define MAX_LABEL_CNT 127

/**
 * \brief Get offset from 2 byte pointer.
 */
#define GET_OFFSET(half1, half2) ((((uint8_t) (half1) &0x3F) << 8) | (uint8_t) (half2))

DNSSDPlugin::DNSSDPlugin()
	: m_txt_all_records(false)
	, m_queries(0)
	, m_responses(0)
	, m_total(0)
	, m_data_begin(nullptr)
	, m_data_len(0)
{
}

DNSSDPlugin::~DNSSDPlugin()
{
	close();
}

void DNSSDPlugin::init(const char* params)
{
	DNSSDOptParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	m_txt_all_records = parser.mTxtAll;
	if (!parser.mConfigFile.empty()) {
		loadTxtconfig(parser.mConfigFile.c_str());
	}
}

void DNSSDPlugin::close() {}

ProcessPlugin* DNSSDPlugin::copy()
{
	return new DNSSDPlugin(*this);
}

int DNSSDPlugin::postCreate(Flow& rec, const Packet& pkt)
{
	if (pkt.dstPort == 5353 || pkt.srcPort == 5353) {
		return addExtDnssd(
			reinterpret_cast<const char*>(pkt.payload),
			pkt.payloadLen,
			pkt.ipProto == IPPROTO_TCP,
			rec);
	}

	return 0;
}

int DNSSDPlugin::postUpdate(Flow& rec, const Packet& pkt)
{
	if (pkt.dstPort == 5353 || pkt.srcPort == 5353) {
		RecordExt* ext = rec.getExtension(RecordExtDNSSD::s_registeredId);

		if (ext == nullptr) {
			return addExtDnssd(
				reinterpret_cast<const char*>(pkt.payload),
				pkt.payloadLen,
				pkt.ipProto == IPPROTO_TCP,
				rec);
		} else {
			parseDns(
				reinterpret_cast<const char*>(pkt.payload),
				pkt.payloadLen,
				pkt.ipProto == IPPROTO_TCP,
				static_cast<RecordExtDNSSD*>(ext));
		}
		return 0;
	}

	return 0;
}

void DNSSDPlugin::finish(bool printStats)
{
	if (printStats) {
		std::cout << "DNSSD plugin stats:" << std::endl;
		std::cout << "   Parsed dns queries: " << m_queries << std::endl;
		std::cout << "   Parsed dns responses: " << m_responses << std::endl;
		std::cout << "   Total dns packets processed: " << m_total << std::endl;
	}
}

/**
 * \brief Load configuration for TXT filtering.
 *
 * Takes path to file from enviroment variable DNSSD_TXTCONFIG_PATH.
 */
void DNSSDPlugin::loadTxtconfig(const char* configFile)
{
	if (!configFile) {
		return;
	}
	std::ifstream inFile;

	inFile.open(configFile);
	if (!inFile) {
		std::ostringstream oss;
		oss << strerror(errno) << " '" << configFile << "'";
		throw PluginError(oss.str());
	}
	std::string line, part;
	size_t begin = 0, end = 0;

	while (getline(inFile, line)) {
		begin = end = 0;
		std::pair<std::string, std::list<std::string>> conf;
		end = line.find(",", begin);
		conf.first = line.substr(
			begin,
			(end == std::string::npos ? (line.length() - begin) : (end - begin)));
		DEBUG_MSG("TXT filter service loaded: %s\n", conf.first.c_str());

		begin = end + 1;
		DEBUG_MSG("TXT filter keys loaded: ");
		while (end != std::string::npos) {
			end = line.find(",", begin);
			part = line.substr(
				begin,
				(end == std::string::npos ? (line.length() - begin) : (end - begin)));
			conf.second.push_back(part);
			DEBUG_MSG("%s ", part.c_str());
			begin = end + 1;
		}
		DEBUG_MSG("\n");
		m_txt_config.push_back(conf);
	}
	inFile.close();
}

/**
 * \brief Get name length.
 * \param [in] data Pointer to string.
 * \return Number of characters in string.
 */
size_t DNSSDPlugin::getNameLength(const char* data) const
{
	size_t len = 0;

	while (1) {
		if ((uint32_t) (data - m_data_begin) + 1 > m_data_len) {
			throw "Error: overflow";
		}
		if (!data[0]) {
			break;
		}
		if (IS_POINTER(data[0])) {
			return len + 2;
		}

		len += (uint8_t) data[0] + 1;
		data += (uint8_t) data[0] + 1;
	}

	return len + 1;
}

/**
 * \brief Decompress dns name.
 * \param [in] data Pointer to compressed data.
 * \return String with decompressed dns name.
 */
std::string DNSSDPlugin::get_name(const char* data) const
{
	std::string name = "";
	int labelCnt = 0;

	if ((uint32_t) (data - m_data_begin) > m_data_len) {
		throw "Error: overflow";
	}

	while (data[0]) { /* Check for terminating character. */
		if (IS_POINTER(data[0])) { /* Check for label pointer (11xxxxxx byte) */
			data = m_data_begin + GET_OFFSET(data[0], data[1]);

			/* Check for possible errors. */
			if (labelCnt++ > MAX_LABEL_CNT || (uint32_t) (data - m_data_begin) > m_data_len) {
				throw "Error: label count exceed or overflow";
			}

			continue;
		}

		/* Check for possible errors. */
		if (labelCnt++ > MAX_LABEL_CNT || (uint8_t) data[0] > 63
			|| (uint32_t) ((data - m_data_begin) + (uint8_t) data[0] + 2) > m_data_len) {
			throw "Error: label count exceed or overflow";
		}

		name += '.' + std::string(data + 1, (uint8_t) data[0]);
		data += ((uint8_t) data[0] + 1);
	}

	if (name[0] == '.') {
		name.erase(0, 1);
	}

	return name;
}

/**
 * \brief Returns a DNS Service Instance Name without the <Instance> part.
 * \param [in] name DNS Service Instance Name.
 *
 * Service Instance Name = <Instance> . <Service> . <Domain>
 * As an example, given input "My MacBook Air._device-info._tcp.local"
 * returns "_device-info._tcp.local".
 */
const std::string DNSSDPlugin::getServiceStr(std::string& name) const
{
	size_t begin = name.length();
	int8_t underscoreCounter = 0;

	while (underscoreCounter < 2 && begin != std::string::npos) {
		begin = name.rfind("_", begin - 1);
		if (begin != std::string::npos) {
			underscoreCounter++;
		}
	}
	return name.substr((begin == std::string::npos ? 0 : begin), name.length());
}

/**
 * \brief Checks if Service Instance Name is allowed for TXT processing by checking txt_config.
 * \return True if allowed, otherwise false.
 */
bool DNSSDPlugin::matchesService(
	std::list<std::pair<std::string, std::list<std::string>>>::const_iterator& it,
	std::string& name) const
{
	std::string service = getServiceStr(name);

	for (it = m_txt_config.begin(); it != m_txt_config.end(); it++) {
		if (it->first == service) {
			return true;
		}
	}
	return false;
}

/**
 * \brief Process RDATA section.
 * \param [in] record_begin Pointer to start of current resource record.
 * \param [in] data Pointer to RDATA section.
 * \param [out] rdata String which stores processed data.
 * \param [in] type Type of RDATA section.
 * \param [in] length Length of RDATA section.
 */
void DNSSDPlugin::processRdata(
	const char* recordBegin,
	const char* data,
	DnsSdRr& rdata,
	uint16_t type,
	size_t length) const
{
	std::string name = rdata.name;
	rdata = DnsSdRr();

	switch (type) {
	case DNS_TYPE_PTR:
		DEBUG_MSG("%16s\t\t    %s\n", "PTR", get_name(data).c_str());
		break;
	case DNS_TYPE_SRV: {
		struct DnsSrv* srv = (struct DnsSrv*) data;

		std::string tmp = get_name(data + 6);

		DEBUG_MSG("%16s\t%8u    %s\n", "SRV", ntohs(srv->port), tmp.c_str());

		rdata.srvPort = ntohs(srv->port);
		rdata.srvTarget = tmp;
	} break;
	case DNS_TYPE_HINFO: {
		rdata.hinfo[0] = std::string(data + 1, (uint8_t) data[0]);
		data += ((uint8_t) data[0] + 1);
		rdata.hinfo[1] = std::string(data + 1, (uint8_t) data[0]);
		data += ((uint8_t) data[0] + 1);
		DEBUG_MSG("%16s\t\t    %s, %s\n", "HINFO", rdata.hinfo[0].c_str(), rdata.hinfo[1].c_str());
	} break;
	case DNS_TYPE_TXT: {
		std::list<std::pair<std::string, std::list<std::string>>>::const_iterator it;
		if (!(m_txt_all_records || matchesService(it, name))) { // all_records overrides filter
			break;
		}
		size_t len = (uint8_t) * (data++);
		size_t totalLen = len + 1;
		std::list<std::string>::const_iterator sit;
		std::string txt;

		while (length != 0 && totalLen <= length) {
			txt = std::string(data, len);

			if (m_txt_all_records) {
				DEBUG_MSG("%16s\t\t    %s\n", "TXT", txt.c_str());
				rdata.txt += txt + ":";
			} else {
				for (sit = it->second.begin(); sit != it->second.end(); sit++) {
					if (*sit == txt.substr(0, txt.find("="))) {
						DEBUG_MSG("%16s\t\t    %s\n", "TXT", txt.c_str());
						rdata.txt += txt + ":";
						break;
					}
				}
			}

			data += len;
			len = (uint8_t) * (data++);
			totalLen += len + 1;
		}
	} break;
	default:
		break;
	}
}

#ifdef DEBUG_DNSSD
uint32_t s_queries = 0;
uint32_t s_responses = 0;
#endif /* DEBUG_DNSSD */

/**
 * \brief Parse and store DNS packet.
 * \param [in] data Pointer to packet payload section.
 * \param [in] payload_len Payload length.
 * \param [in] tcp DNS over tcp.
 * \param [out] rec Output Flow extension header.
 * \return True if DNS was parsed.
 */
bool DNSSDPlugin::parseDns(
	const char* data,
	unsigned int payloadLen,
	bool tcp,
	RecordExtDNSSD* rec)
{
	try {
		m_total++;

		DEBUG_MSG("---------- dns parser #%u ----------\n", total);
		DEBUG_MSG("Payload length: %u\n", payload_len);

		if (tcp) {
			payloadLen -= 2;
			if (ntohs(*(uint16_t*) data) != payloadLen) {
				DEBUG_MSG("parser quits: fragmented tcp pkt");
				return false;
			}
			data += 2;
		}

		if (payloadLen < sizeof(struct DnsHdr)) {
			DEBUG_MSG("parser quits: payload length < %ld\n", sizeof(struct dns_hdr));
			return false;
		}

		m_data_begin = data;
		m_data_len = payloadLen;

		struct DnsHdr* dns = (struct DnsHdr*) data;
		uint16_t flags = ntohs(dns->flags);
		uint16_t questionCnt = ntohs(dns->questionRecCnt);
		uint16_t answerRrCnt = ntohs(dns->answerRecCnt);
		uint16_t authorityRrCnt = ntohs(dns->nameServerRecCnt);
		uint16_t additionalRrCnt = ntohs(dns->additionalRecCnt);

		DEBUG_MSG(
			"%s number: %u\n",
			DNS_HDR_GET_QR(flags) ? "Response" : "Query",
			DNS_HDR_GET_QR(flags) ? s_queries++ : s_responses++);
		DEBUG_MSG("DNS message header\n");
		DEBUG_MSG("\tFlags:\t\t\t%#06x\n", ntohs(dns->flags));

		DEBUG_MSG(
			"\t\tQuestion/reply:\t\t%u (%s)\n",
			DNS_HDR_GET_QR(flags),
			DNS_HDR_GET_QR(flags) ? "Response" : "Query");
		DEBUG_MSG("\t\tAuthoritative answer:\t%u\n", DNS_HDR_GET_AA(flags));

		DEBUG_MSG("\tQuestions:\t\t%u\n", question_cnt);
		DEBUG_MSG("\tAnswer RRs:\t\t%u\n", answer_rr_cnt);
		DEBUG_MSG("\tAuthority RRs:\t\t%u\n", authority_rr_cnt);
		DEBUG_MSG("\tAdditional RRs:\t\t%u\n", additional_rr_cnt);

		/********************************************************************
		*****                   DNS Question section                    *****
		********************************************************************/
		data += sizeof(struct DnsHdr);
		for (int i = 0; i < questionCnt; i++) {
			DEBUG_CODE(if (i == 0) {
				DEBUG_MSG("\nDNS questions section\n");
				DEBUG_MSG("%8s%8s%8s%8s%8s\n", "num", "type", "ttl", "port", "name");
			});
			std::string name = get_name(data);

			data += getNameLength(data);
			DEBUG_CODE(struct dns_question* question = (struct dns_question*) data);

			if ((data - m_data_begin) + sizeof(struct DnsQuestion) > payloadLen) {
				DEBUG_MSG("DNS parser quits: overflow\n\n");
				return 1;
			}

			filteredAppend(rec, name);

			DEBUG_MSG("#%7d%8u%20s%s\n", i + 1, ntohs(question->qtype), "", name.c_str());
			data += sizeof(struct DnsQuestion);
		}

		/********************************************************************
		*****                    DNS Answers section                    *****
		********************************************************************/
		const char* recordBegin;
		size_t rdlength;
		DnsSdRr rdata;

		for (int i = 0; i < answerRrCnt; i++) { // Process answers section.
			if (i == 0) {
				DEBUG_MSG("DNS answers section\n");
				DEBUG_MSG("%8s%8s%8s%8s%8s\n", "num", "type", "ttl", "port", "name");
			}

			recordBegin = data;
			std::string name = get_name(data);

			data += getNameLength(data);

			struct DnsAnswer* answer = (struct DnsAnswer*) data;

			uint32_t tmp = (data - m_data_begin) + sizeof(DnsAnswer);

			if (tmp > payloadLen || tmp + ntohs(answer->rdlength) > payloadLen) {
				DEBUG_MSG("DNS parser quits: overflow\n\n");
				return 1;
			}
			DEBUG_MSG(
				"#%7d%8u%8u%12s%s\n",
				i + 1,
				ntohs(answer->atype),
				ntohl(answer->ttl),
				"",
				name.c_str());

			data += sizeof(struct DnsAnswer);
			rdlength = ntohs(answer->rdlength);
			rdata.name = name;

			processRdata(recordBegin, data, rdata, ntohs(answer->atype), rdlength);
			if (DNS_HDR_GET_QR(flags)) { // Ignore the known answers in a query.
				filteredAppend(rec, name, ntohs(answer->atype), rdata);
			}
			data += rdlength;
		}

		/********************************************************************
		*****                 DNS Authority RRs section                 *****
		********************************************************************/

		for (int i = 0; i < authorityRrCnt; i++) {
			DEBUG_CODE(if (i == 0) {
				DEBUG_MSG("DNS authority RRs section\n");
				DEBUG_MSG("%8s%8s%8s%8s%8s\n", "num", "type", "ttl", "port", "name");
			});

			recordBegin = data;
			std::string name = get_name(data);

			data += getNameLength(data);

			struct DnsAnswer* answer = (struct DnsAnswer*) data;

			uint32_t tmp = (data - m_data_begin) + sizeof(DnsAnswer);

			if (tmp > payloadLen || tmp + ntohs(answer->rdlength) > payloadLen) {
				DEBUG_MSG("DNS parser quits: overflow\n\n");
				return 1;
			}

			DEBUG_MSG(
				"#%7d%8u%8u%12s%s\n",
				i + 1,
				ntohs(answer->atype),
				ntohl(answer->ttl),
				"",
				name.c_str());

			data += sizeof(struct DnsAnswer);
			rdlength = ntohs(answer->rdlength);
			rdata.name = name;

			processRdata(recordBegin, data, rdata, ntohs(answer->atype), rdlength);
			filteredAppend(rec, name, ntohs(answer->atype), rdata);

			data += rdlength;
		}

		/********************************************************************
		*****                 DNS Additional RRs section                *****
		********************************************************************/
		for (int i = 0; i < additionalRrCnt; i++) {
			DEBUG_CODE(if (i == 0) {
				DEBUG_MSG("DNS additional RRs section\n");
				DEBUG_MSG("%8s%8s%8s%8s%8s\n", "num", "type", "ttl", "port", "name");
			});

			recordBegin = data;

			std::string name = get_name(data);

			data += getNameLength(data);

			struct DnsAnswer* answer = (struct DnsAnswer*) data;

			uint32_t tmp = (data - m_data_begin) + sizeof(DnsAnswer);

			if (tmp > payloadLen || tmp + ntohs(answer->rdlength) > payloadLen) {
				DEBUG_MSG("DNS parser quits: overflow\n\n");
				return 1;
			}

			DEBUG_MSG(
				"#%7d%8u%8u%12s%s\n",
				i + 1,
				ntohs(answer->atype),
				ntohl(answer->ttl),
				"",
				name.c_str());

			rdlength = ntohs(answer->rdlength);

			if (ntohs(answer->atype) != DNS_TYPE_OPT) {
				data += sizeof(struct DnsAnswer);
				rdata.name = name;

				processRdata(recordBegin, data, rdata, ntohs(answer->atype), rdlength);
				if (DNS_HDR_GET_QR(flags)) {
					filteredAppend(rec, name, ntohs(answer->atype), rdata);
				}
			}

			data += rdlength;
		}

		if (DNS_HDR_GET_QR(flags)) {
			m_responses++;
		} else {
			m_queries++;
		}

		DEBUG_MSG("DNS parser quits: parsing done\n\n");
	} catch (const char* err) {
		DEBUG_MSG("%s\n", err);
		return false;
	}

	return true;
}

/**
 * \brief Append new unique query to DNSSD extension record.
 * \param [in,out] rec Pointer to DNSSD extension record
 * \param [in] name Domain name of the DNS record.
 */
void DNSSDPlugin::filteredAppend(RecordExtDNSSD* rec, std::string name)
{
	if (name.rfind("arpa") == std::string::npos
		&& std::find(rec->queries.begin(), rec->queries.end(), name) == rec->queries.end()) {
		rec->queries.push_back(name);
	}
}

/**
 * \brief Append new unique response to DNSSD extension record.
 * \param [in,out] rec Pointer to DNSSD extension record
 * \param [in] name Domain name of the DNS record.
 * \param [in] type DNS type id of the DNS record.
 * \param [in] rdata RDATA of the DNS record.
 */
void DNSSDPlugin::filteredAppend(
	RecordExtDNSSD* rec,
	std::string name,
	uint16_t type,
	DnsSdRr& rdata)
{
	if ((type != DNS_TYPE_SRV && type != DNS_TYPE_HINFO && type != DNS_TYPE_TXT)
		|| name.rfind("arpa") != std::string::npos) {
		return;
	}
	std::list<DnsSdRr>::iterator it;

	for (it = rec->responses.begin(); it != rec->responses.end(); it++) {
		if (it->name == name) {
			switch (type) {
			case DNS_TYPE_SRV:
				it->srvPort = rdata.srvPort;
				it->srvTarget = rdata.srvTarget;
				return;
			case DNS_TYPE_HINFO:
				it->hinfo[0] = rdata.hinfo[0];
				it->hinfo[1] = rdata.hinfo[1];
				return;
			case DNS_TYPE_TXT:
				if (!rdata.txt.empty() && it->txt.find(rdata.txt) == std::string::npos) {
					it->txt += rdata.txt + ":";
				}
				return;
			default:
				return;
			}
		}
	}

	DnsSdRr rr;

	rr.name = name;
	switch (type) {
	case DNS_TYPE_SRV:
		rr.srvPort = rdata.srvPort;
		rr.srvTarget = rdata.srvTarget;
		break;
	case DNS_TYPE_HINFO:
		rr.hinfo[0] = rdata.hinfo[0];
		rr.hinfo[1] = rdata.hinfo[1];
		break;
	case DNS_TYPE_TXT:
		rr.txt = rdata.txt;
		break;
	default:
		return;
	}
	rec->responses.push_back(rr);
}

/**
 * \brief Add new extension DNSSD header into Flow.
 * \param [in] data Pointer to packet payload section.
 * \param [in] payload_len Payload length.
 * \param [in] tcp DNS over tcp.
 * \param [out] rec Destination Flow.
 */
int DNSSDPlugin::addExtDnssd(const char* data, unsigned int payloadLen, bool tcp, Flow& rec)
{
	RecordExtDNSSD* ext = new RecordExtDNSSD();

	if (!parseDns(data, payloadLen, tcp, ext)) {
		delete ext;

		return 0;
	} else {
		rec.addExtension(ext);
	}
	return 0;
}

} // namespace ipxp
