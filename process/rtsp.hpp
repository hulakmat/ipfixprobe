/**
 * \file rtsp.hpp
 * \brief Plugin for parsing RTSP traffic
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

#ifndef IPXP_PROCESS_RTSP_HPP
#define IPXP_PROCESS_RTSP_HPP

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>

#ifdef WITH_NEMEA
#include <fields.h>
#endif

#include "http.hpp"
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/process.hpp>

namespace Ipxp {

#define RTSP_UNIREC_TEMPLATE                                                                       \
	"RTSP_REQUEST_METHOD,RTSP_REQUEST_AGENT,RTSP_REQUEST_URI,RTSP_RESPONSE_STATUS_CODE,RTSP_"      \
	"RESPONSE_SERVER,RTSP_RESPONSE_CONTENT_TYPE"
UR_FIELDS(
	string RTSP_REQUEST_METHOD,
	string RTSP_REQUEST_AGENT,
	string RTSP_REQUEST_URI,

	uint16 RTSP_RESPONSE_STATUS_CODE,
	string RTSP_RESPONSE_SERVER,
	string RTSP_RESPONSE_CONTENT_TYPE)

/**
 * \brief Flow record extension header for storing RTSP requests.
 */
struct RecordExtRTSP : public RecordExt {
	static int s_registeredId;
	bool req;
	bool resp;

	char method[10];
	char userAgent[128];
	char uri[128];

	uint16_t code;
	char contentType[32];
	char server[128];

	/**
	 * \brief Constructor.
	 */
	RecordExtRTSP()
		: RecordExt(s_registeredId)
	{
		req = false;
		resp = false;

		method[0] = 0;
		userAgent[0] = 0;
		uri[0] = 0;

		code = 0;
		contentType[0] = 0;
		server[0] = 0;
	}

#ifdef WITH_NEMEA
	virtual void fillUnirec(ur_template_t* tmplt, void* record)
	{
		ur_set_string(tmplt, record, F_RTSP_REQUEST_METHOD, method);
		ur_set_string(tmplt, record, F_RTSP_REQUEST_AGENT, userAgent);
		ur_set_string(tmplt, record, F_RTSP_REQUEST_URI, uri);

		ur_set(tmplt, record, F_RTSP_RESPONSE_STATUS_CODE, code);
		ur_set_string(tmplt, record, F_RTSP_RESPONSE_SERVER, server);
		ur_set_string(tmplt, record, F_RTSP_RESPONSE_CONTENT_TYPE, contentType);
	}

	const char* getUnirecTmplt() const
	{
		return RTSP_UNIREC_TEMPLATE;
	}
#endif

	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		int length, totalLength = 0;

		// Method
		length = strlen(method);
		if (totalLength + length + 1 > size) {
			return -1;
		}
		buffer[totalLength] = length;
		memcpy(buffer + totalLength + 1, method, length);
		totalLength += length + 1;

		// User Agent
		length = strlen(userAgent);
		if (totalLength + length + 1 > size) {
			return -1;
		}
		buffer[totalLength] = length;
		memcpy(buffer + totalLength + 1, userAgent, length);
		totalLength += length + 1;

		// URI
		length = strlen(uri);
		if (totalLength + length + 3 > size) {
			return -1;
		}
		buffer[totalLength] = length;
		memcpy(buffer + totalLength + 1, uri, length);
		totalLength += length + 1;

		// Response code
		*(uint16_t*) (buffer + totalLength) = ntohs(code);
		totalLength += 2;

		// Server
		length = strlen(server);
		if (totalLength + length + 1 > size) {
			return -1;
		}
		buffer[totalLength] = length;
		memcpy(buffer + totalLength + 1, server, length);
		totalLength += length + 1;

		// Content type
		length = strlen(contentType);
		if (totalLength + length + 1 > size) {
			return -1;
		}
		buffer[totalLength] = length;
		memcpy(buffer + totalLength + 1, contentType, length);
		totalLength += length + 1;

		return totalLength;
	}

	const char** getIpfixTmplt() const
	{
		static const char* ipfixTemplate[] = {IPFIX_RTSP_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};
		return ipfixTemplate;
	}

	std::string getText() const
	{
		std::ostringstream out;
		out << "httpmethod=\"" << method << "\""
			<< ",uri=\"" << uri << "\""
			<< ",agent=\"" << userAgent << "\""
			<< ",server=\"" << server << "\""
			<< ",content=\"" << contentType << "\""
			<< ",status=" << code;
		return out.str();
	}
};

/**
 * \brief Flow cache plugin used to parse RTSP requests / responses.
 */
class RTSPPlugin : public ProcessPlugin {
public:
	RTSPPlugin();
	~RTSPPlugin();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const { return new OptionsParser("rtsp", "Parse RTSP traffic"); }
	std::string getName() const { return "rtsp"; }
	RecordExt* getExt() const { return new RecordExtRTSP(); }
	ProcessPlugin* copy();

	int postCreate(Flow& rec, const Packet& pkt);
	int preUpdate(Flow& rec, Packet& pkt);
	void finish(bool printStats);

private:
	bool isResponse(const char* data, int payloadLen);
	bool isRequest(const char* data, int payloadLen);
	bool parseRtspRequest(const char* data, int payloadLen, RecordExtRTSP* rec);
	bool parseRtspResponse(const char* data, int payloadLen, RecordExtRTSP* rec);
	void addExtRtspRequest(const char* data, int payloadLen, Flow& flow);
	void addExtRtspResponse(const char* data, int payloadLen, Flow& flow);
	bool validRtspMethod(const char* method) const;

	RecordExtRTSP* m_recPrealloc; /**< Preallocated extension. */
	bool m_flow_flush; /**< Tell storage plugin to flush current Flow. */
	uint32_t m_requests; /**< Total number of parsed RTSP requests. */
	uint32_t m_responses; /**< Total number of parsed RTSP responses. */
	uint32_t m_total; /**< Total number of parsed RTSP packets. */
};

} // namespace ipxp
#endif /* IPXP_PROCESS_RTSP_HPP */
