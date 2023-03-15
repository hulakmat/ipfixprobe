/**
 * \file ssdp.cpp
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

#include <iostream>

#include "common.hpp"
#include "ssdp.hpp"

namespace Ipxp {

int RecordExtSSDP::s_registeredId = -1;

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("ssdp", []() { return new SSDPPlugin(); });
	registerPlugin(&rec);
	RecordExtSSDP::s_registeredId = registerExtension();
}

// #define DEBUG_SSDP

// Print debug message if debugging is allowed.
#ifdef DEBUG_SSDP
#define SSDP_DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define SSDP_DEBUG_MSG(format, ...)
#endif

enum header_types { LOCATION, NT, ST, SERVER, USER_AGENT, NONE };

const char* g_headers[] = {"location", "nt", "st", "server", "user-agent"};

SSDPPlugin::SSDPPlugin()
	: m_record(nullptr)
	, m_notifies(0)
	, m_searches(0)
	, m_total(0)
{
}

SSDPPlugin::~SSDPPlugin()
{
	close();
}

void SSDPPlugin::init(const char* params) {}

void SSDPPlugin::close() {}

ProcessPlugin* SSDPPlugin::copy()
{
	return new SSDPPlugin(*this);
}

int SSDPPlugin::postCreate(Flow& rec, const Packet& pkt)
{
	if (pkt.dstPort == 1900) {
		m_record = new RecordExtSSDP();
		rec.addExtension(m_record);
		m_record = nullptr;

		parseSsdpMessage(rec, pkt);
	}
	return 0;
}

int SSDPPlugin::preUpdate(Flow& rec, Packet& pkt)
{
	if (pkt.dstPort == 1900) {
		parseSsdpMessage(rec, pkt);
	}
	return 0;
}

void SSDPPlugin::finish(bool printStats)
{
	if (printStats) {
		std::cout << "SSDP plugin stats:" << std::endl;
		std::cout << "   Parsed SSDP M-Searches: " << m_searches << std::endl;
		std::cout << "   Parsed SSDP Notifies: " << m_notifies << std::endl;
		std::cout << "   Total SSDP packets processed: " << m_total << std::endl;
	}
}

/**
 * \brief Parses port from location header message string.
 *
 * \param [in, out] data Pointer to SSDP data.
 * \param [in] ip_version IP version of the Location url being parsed.
 * \return Parsed port number on success, 0 otherwise.
 */
uint16_t SSDPPlugin::parseLocPort(const char* data, unsigned dataLen, uint8_t ipVersion)
{
	uint16_t port;
	char* endPtr = nullptr;
	const void* dataMem = static_cast<const void*>(data);

	if (ipVersion == IP::V6) {
		dataMem = memchr(dataMem, ']', dataLen);
	} else {
		dataMem = memchr(dataMem, '.', dataLen);
	}
	if (dataMem == nullptr) {
		return 0;
	}
	dataMem = memchr(dataMem, ':', dataLen);

	if (dataMem == nullptr) {
		return 0;
	}
	data = static_cast<const char*>(dataMem);
	data++;

	port = strtol(data, &endPtr, 0);
	if (data != endPtr) {
		return port;
	}
	return 0;
}

/**
 * \brief Checks for given header string in data
 *
 * \param [in, out] data Pointer to pointer to SSDP data.
 * \param [in] header String containing the desired header.
 * \param [in] len Lenght of the desired header.
 * \return True if the header is found, otherwise false.
 */
bool SSDPPlugin::getHeaderVal(const char** data, const char* header, const int len)
{
	if (strncasecmp(*data, header, len) == 0 && (*data)[len] == ':') {
		(*data) += len + 1;
		while (isspace(**data)) {
			(*data)++;
		};
		return true;
	}
	return false;
}

/**
 * \brief Parses SSDP payload based on configuration in conf struct.
 *
 * \param [in] data Pointer to pointer to SSDP data.
 * \param [in] payload_len Lenght of payload data
 * \param [in] conf Struct containing parser configuration.
 */
void SSDPPlugin::parseHeaders(const uint8_t* data, size_t payloadLen, HeaderParserConf conf)
{
	const char* ptr = (const char*) (data);
	const char* oldPtr = ptr;
	size_t len = 0;

	while (*ptr != '\0' && len <= payloadLen) {
		if (*ptr == '\n' && *(ptr - 1) == '\r') {
			for (unsigned j = 0, i = 0; j < conf.selectCnt; j++) {
				i = conf.select[j];
				if (getHeaderVal(&oldPtr, conf.headers[i], strlen(conf.headers[i]))) {
					switch ((header_types) i) {
					case ST:
						if (getHeaderVal(&oldPtr, "urn", strlen("urn"))) {
							SSDP_DEBUG_MSG("%s\n", old_ptr);
							appendValue(conf.ext->st, SSDP_URN_LEN, oldPtr, ptr - oldPtr);
						}
						break;
					case NT:
						if (getHeaderVal(&oldPtr, "urn", strlen("urn"))) {
							SSDP_DEBUG_MSG("%s\n", old_ptr);
							appendValue(conf.ext->nt, SSDP_URN_LEN, oldPtr, ptr - oldPtr);
						}
						break;
					case LOCATION: {
						uint16_t port = parseLocPort(oldPtr, ptr - oldPtr, conf.ipVersion);

						if (port > 0) {
							SSDP_DEBUG_MSG("%d <- %d\n", conf.ext->port, port);
							conf.ext->port = port;
						}
						break;
					}
					case USER_AGENT:
						SSDP_DEBUG_MSG("%s\n", old_ptr);
						appendValue(
							conf.ext->userAgent,
							SSDP_USER_AGENT_LEN,
							oldPtr,
							ptr - oldPtr);
						break;
					case SERVER:
						SSDP_DEBUG_MSG("%s\n", old_ptr);
						appendValue(conf.ext->server, SSDP_SERVER_LEN, oldPtr, ptr - oldPtr);
						break;
					default:
						break;
					}
					break;
				}
			}
			oldPtr = ptr + 1;
		}
		ptr++;
		len++;
	}
	return;
}

/**
 * \brief Appends a value to the existing semicolon separated entry.
 *
 * Appends only values that are not already included in the current entry.
 *
 * \param [in,out] curr_entry String containing the current entry.
 * \param [in] entry_max Maximum length if the entry.
 * \param [in] value String containing the new entry.
 */
void SSDPPlugin::appendValue(
	char* currEntry,
	unsigned entryMax,
	const char* value,
	unsigned valueLen)
{
	if (strlen(currEntry) + valueLen + 1 < entryMax) {
		// return if value already in curr_entry
		for (unsigned i = 0; i < strlen(currEntry) - valueLen; i++) {
			if (strlen(currEntry) < valueLen) {
				break;
			}
			if (strncmp(&currEntry[i], value, valueLen) == 0) {
				return;
			}
		}

		SSDP_DEBUG_MSG("New entry\n");
		strncat(currEntry, value, valueLen);
		strcat(currEntry, ";");
	}
}

/**
 * \brief Parses SSDP payload.
 *
 * Detects type of message and configures the parser accordingly.
 *
 * \param [in, out] rec Flow record containing basic flow data.
 * \param [in] pkt Packet struct containing packet data.
 */
void SSDPPlugin::parseSsdpMessage(Flow& rec, const Packet& pkt)
{
	HeaderParserConf parseConf
		= {g_headers,
		   rec.ipVersion,
		   static_cast<RecordExtSSDP*>(rec.getExtension(RecordExtSSDP::s_registeredId))};

	m_total++;
	if (pkt.payload[0] == 'N') {
		m_notifies++;
		SSDP_DEBUG_MSG("Notify #%d\n", notifies);
		int notifyHeaders[] = {NT, LOCATION, SERVER};
		parseConf.select = notifyHeaders;
		parseConf.selectCnt = sizeof(notifyHeaders) / sizeof(notifyHeaders[0]);
		parseHeaders(pkt.payload, pkt.payloadLen, parseConf);
	} else if (pkt.payload[0] == 'M') {
		m_searches++;
		SSDP_DEBUG_MSG("M-search #%d\n", searches);
		int searchHeaders[] = {ST, USER_AGENT};
		parseConf.select = searchHeaders;
		parseConf.selectCnt = sizeof(searchHeaders) / sizeof(searchHeaders[0]);
		parseHeaders(pkt.payload, pkt.payloadLen, parseConf);
	}
	SSDP_DEBUG_MSG("\n");
}

} // namespace ipxp
