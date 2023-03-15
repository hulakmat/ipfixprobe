/**
 * \file http.hpp
 * \brief Plugin for parsing HTTP traffic
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2015
 * \date 2016
 */
/*
 * Copyright (C) 2014-2016 CESNET
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

#ifndef IPXP_PROCESS_HTTP_HPP
#define IPXP_PROCESS_HTTP_HPP

#include <config.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/process.hpp>
#include <ipfixprobe/utils.hpp>

namespace Ipxp {

#define HTTP_UNIREC_TEMPLATE                                                                       \
	"HTTP_REQUEST_METHOD,HTTP_REQUEST_HOST,HTTP_REQUEST_URL,HTTP_REQUEST_AGENT,HTTP_REQUEST_"      \
	"REFERER,HTTP_RESPONSE_STATUS_CODE,HTTP_RESPONSE_CONTENT_TYPE"

UR_FIELDS(
	string HTTP_REQUEST_METHOD,
	string HTTP_REQUEST_HOST,
	string HTTP_REQUEST_URL,
	string HTTP_REQUEST_AGENT,
	string HTTP_REQUEST_REFERER,

	uint16 HTTP_RESPONSE_STATUS_CODE,
	string HTTP_RESPONSE_CONTENT_TYPE)

void copyStr(char* dst, ssize_t size, const char* begin, const char* end);

/**
 * \brief Flow record extension header for storing HTTP requests.
 */
struct RecordExtHTTP : public RecordExt {
	static int s_registeredId;

	bool req;
	bool resp;

	char method[10];
	char host[64];
	char uri[128];
	char userAgent[128];
	char referer[128];

	uint16_t code;
	char contentType[32];

	/**
	 * \brief Constructor.
	 */
	RecordExtHTTP()
		: RecordExt(s_registeredId)
	{
		req = false;
		resp = false;
		method[0] = 0;
		host[0] = 0;
		uri[0] = 0;
		userAgent[0] = 0;
		referer[0] = 0;
		code = 0;
		contentType[0] = 0;
	}

#ifdef WITH_NEMEA
	virtual void fillUnirec(ur_template_t* tmplt, void* record)
	{
		ur_set_string(tmplt, record, F_HTTP_REQUEST_METHOD, method);
		ur_set_string(tmplt, record, F_HTTP_REQUEST_HOST, host);
		ur_set_string(tmplt, record, F_HTTP_REQUEST_URL, uri);
		ur_set_string(tmplt, record, F_HTTP_REQUEST_AGENT, userAgent);
		ur_set_string(tmplt, record, F_HTTP_REQUEST_REFERER, referer);
		ur_set_string(tmplt, record, F_HTTP_RESPONSE_CONTENT_TYPE, contentType);
		ur_set(tmplt, record, F_HTTP_RESPONSE_STATUS_CODE, code);
	}

	const char* getUnirecTmplt() const
	{
		return HTTP_UNIREC_TEMPLATE;
	}
#endif

	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		uint16_t length = 0;
		uint32_t totalLength = 0;

		length = strlen(userAgent);
		if ((uint32_t) (length + 3) > (uint32_t) size) {
			return -1;
		}
		totalLength += variable2ipfixBuffer(buffer + totalLength, (uint8_t*) userAgent, length);

		length = strlen(method);
		if (totalLength + length + 3 > (uint32_t) size) {
			return -1;
		}
		totalLength += variable2ipfixBuffer(buffer + totalLength, (uint8_t*) method, length);

		length = strlen(host);
		if (totalLength + length + 3 > (uint32_t) size) {
			return -1;
		}
		totalLength += variable2ipfixBuffer(buffer + totalLength, (uint8_t*) host, length);

		length = strlen(referer);
		if (totalLength + length + 3 > (uint32_t) size) {
			return -1;
		}
		totalLength += variable2ipfixBuffer(buffer + totalLength, (uint8_t*) referer, length);

		length = strlen(uri);
		if (totalLength + length + 3 > (uint32_t) size) {
			return -1;
		}
		totalLength += variable2ipfixBuffer(buffer + totalLength, (uint8_t*) uri, length);

		length = strlen(contentType);
		if (totalLength + length + 3 > (uint32_t) size) {
			return -1;
		}
		totalLength
			+= variable2ipfixBuffer(buffer + totalLength, (uint8_t*) contentType, length);

		*(uint16_t*) (buffer + totalLength) = ntohs(code);
		totalLength += 2;

		return totalLength;
	}

	const char** getIpfixTmplt() const
	{
		static const char* ipfixTemplate[] = {IPFIX_HTTP_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};
		return ipfixTemplate;
	}

	std::string getText() const
	{
		std::ostringstream out;
		out << "method=\"" << method << "\""
			<< ",host=\"" << host << "\""
			<< ",uri=\"" << uri << "\""
			<< ",agent=\"" << userAgent << "\""
			<< ",referer=\"" << referer << "\""
			<< ",content=\"" << contentType << "\""
			<< ",status=" << code;
		return out.str();
	}
};

/**
 * \brief Flow cache plugin used to parse HTTP requests / responses.
 */
class HTTPPlugin : public ProcessPlugin {
public:
	HTTPPlugin();
	~HTTPPlugin();
	void init(const char* params);
	void close();
	RecordExt* getExt() const { return new RecordExtHTTP(); }
	OptionsParser* getParser() const { return new OptionsParser("http", "Parse HTTP traffic"); }
	std::string getName() const { return "http"; }
	ProcessPlugin* copy();

	int postCreate(Flow& rec, const Packet& pkt);
	int preUpdate(Flow& rec, Packet& pkt);
	void finish(bool printStats);

private:
	bool isResponse(const char* data, int payloadLen);
	bool isRequest(const char* data, int payloadLen);
	bool parseHttpRequest(const char* data, int payloadLen, RecordExtHTTP* rec);
	bool parseHttpResponse(const char* data, int payloadLen, RecordExtHTTP* rec);
	void addExtHttpRequest(const char* data, int payloadLen, Flow& flow);
	void addExtHttpResponse(const char* data, int payloadLen, Flow& flow);
	bool validHttpMethod(const char* method) const;

	RecordExtHTTP* m_recPrealloc; /**< Preallocated extension. */
	bool m_flow_flush; /**< Tell storage plugin to flush current Flow. */
	uint32_t m_requests; /**< Total number of parsed HTTP requests. */
	uint32_t m_responses; /**< Total number of parsed HTTP responses. */
	uint32_t m_total; /**< Total number of parsed HTTP packets. */
};

} // namespace ipxp
#endif /* IPXP_PROCESS_HTTP_HPP */
