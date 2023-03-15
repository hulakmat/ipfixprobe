/**
 * \file rtsp.cpp
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

#include <cstdlib>
#include <cstring>
#include <iostream>

#ifdef WITH_NEMEA
#include <unirec/unirec.h>
#endif

#include "common.hpp"
#include "rtsp.hpp"

namespace Ipxp {

int RecordExtRTSP::s_registeredId = -1;

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("rtsp", []() { return new RTSPPlugin(); });
	registerPlugin(&rec);
	RecordExtRTSP::s_registeredId = registerExtension();
}

//#define DEBUG_RTSP

// Print debug message if debugging is allowed.
#ifdef DEBUG_RTSP
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_RTSP
#define DEBUG_CODE(code) code
#else
#define DEBUG_CODE(code)
#endif

#define RTSP_LINE_DELIMITER '\n'
#define RTSP_KEYVAL_DELIMITER ':'

RTSPPlugin::RTSPPlugin()
	: m_recPrealloc(nullptr)
	, m_flow_flush(false)
	, m_requests(0)
	, m_responses(0)
	, m_total(0)
{
}

RTSPPlugin::~RTSPPlugin()
{
	close();
}

void RTSPPlugin::init(const char* params) {}

void RTSPPlugin::close()
{
	if (m_recPrealloc != nullptr) {
		delete m_recPrealloc;
		m_recPrealloc = nullptr;
	}
}

ProcessPlugin* RTSPPlugin::copy()
{
	return new RTSPPlugin(*this);
}

int RTSPPlugin::postCreate(Flow& rec, const Packet& pkt)
{
	const char* payload = reinterpret_cast<const char*>(pkt.payload);
	if (isRequest(payload, pkt.payloadLen)) {
		addExtRtspRequest(payload, pkt.payloadLen, rec);
	} else if (isResponse(payload, pkt.payloadLen)) {
		addExtRtspResponse(payload, pkt.payloadLen, rec);
	}

	return 0;
}

int RTSPPlugin::preUpdate(Flow& rec, Packet& pkt)
{
	RecordExt* ext = nullptr;
	const char* payload = reinterpret_cast<const char*>(pkt.payload);
	if (isRequest(payload, pkt.payloadLen)) {
		ext = rec.getExtension(RecordExtRTSP::s_registeredId);
		if (ext == nullptr) { /* Check if header is present in flow. */
			addExtRtspRequest(payload, pkt.payloadLen, rec);
			return 0;
		}

		parseRtspRequest(payload, pkt.payloadLen, static_cast<RecordExtRTSP*>(ext));
		if (m_flow_flush) {
			m_flow_flush = false;
			return FLOW_FLUSH_WITH_REINSERT;
		}
	} else if (isResponse(payload, pkt.payloadLen)) {
		ext = rec.getExtension(RecordExtRTSP::s_registeredId);
		if (ext == nullptr) { /* Check if header is present in flow. */
			addExtRtspResponse(payload, pkt.payloadLen, rec);
			return 0;
		}

		parseRtspResponse(payload, pkt.payloadLen, static_cast<RecordExtRTSP*>(ext));
		if (m_flow_flush) {
			m_flow_flush = false;
			return FLOW_FLUSH_WITH_REINSERT;
		}
	}

	return 0;
}

void RTSPPlugin::finish(bool printStats)
{
	if (printStats) {
		std::cout << "RTSP plugin stats:" << std::endl;
		std::cout << "   Parsed rtsp requests: " << m_requests << std::endl;
		std::cout << "   Parsed rtsp responses: " << m_responses << std::endl;
		std::cout << "   Total rtsp packets processed: " << m_total << std::endl;
	}
}

bool RTSPPlugin::isRequest(const char* data, int payloadLen)
{
	char chars[5];

	if (payloadLen < 4) {
		return false;
	}
	memcpy(chars, data, 4);
	chars[4] = 0;
	return validRtspMethod(chars);
}

bool RTSPPlugin::isResponse(const char* data, int payloadLen)
{
	char chars[5];

	if (payloadLen < 4) {
		return false;
	}
	memcpy(chars, data, 4);
	chars[4] = 0;
	return !strcmp(chars, "RTSP");
}

#ifdef DEBUG_RTSP
static uint32_t s_requests = 0, s_responses = 0;
#endif /* DEBUG_RTSP */

/**
 * \brief Parse and store rtsp request.
 * \param [in] data Packet payload data.
 * \param [in] payload_len Length of packet payload.
 * \param [out] rec Variable where rtsp request will be stored.
 * \return True if request was parsed, false if error occured.
 */
bool RTSPPlugin::parseRtspRequest(const char* data, int payloadLen, RecordExtRTSP* rec)
{
	char buffer[64];
	const char* begin;
	const char* end;
	const char* keyvalDelimiter;
	size_t remaining;

	m_total++;

	DEBUG_MSG("---------- rtsp parser #%u ----------\n", total);
	DEBUG_MSG("Parsing request number: %u\n", ++s_requests);
	DEBUG_MSG("Payload length: %u\n\n", payload_len);

	if (payloadLen == 0) {
		DEBUG_MSG("Parser quits:\tpayload length = 0\n");
		return false;
	}

	/* Request line:
	 *
	 * METHOD URI VERSION
	 * |     |   |
	 * |     |   -------- end
	 * |     ------------ begin
	 * ----- ------------ data
	 */

	/* Find begin of URI. */
	begin = static_cast<const char*>(memchr(data, ' ', payloadLen));
	if (begin == nullptr) {
		DEBUG_MSG("Parser quits:\tnot a rtsp request header\n");
		return false;
	}

	/* Find end of URI. */

	if (checkPayloadLen(payloadLen, (begin + 1) - data)) {
		DEBUG_MSG("Parser quits:\tpayload end\n");
		return false;
	}
	remaining = payloadLen - ((begin + 1) - data);
	end = static_cast<const char*>(memchr(begin + 1, ' ', remaining));
	if (end == nullptr) {
		DEBUG_MSG("Parser quits:\trequest is fragmented\n");
		return false;
	}

	if (memcmp(end + 1, "RTSP", 4)) {
		DEBUG_MSG("Parser quits:\tnot a RTSP request\n");
		return false;
	}

	/* Copy and check RTSP method */
	copyStr(buffer, sizeof(buffer), data, begin);
	if (rec->req) {
		m_flow_flush = true;
		m_total--;
		DEBUG_MSG("Parser quits:\tflushing flow\n");
		return false;
	}
	strncpy(rec->method, buffer, sizeof(rec->method));
	rec->method[sizeof(rec->method) - 1] = 0;

	copyStr(rec->uri, sizeof(rec->uri), begin + 1, end);
	DEBUG_MSG("\tMethod: %s\n", rec->method);
	DEBUG_MSG("\tURI: %s\n", rec->uri);

	/* Find begin of next line after request line. */
	if (checkPayloadLen(payloadLen, end - data)) {
		DEBUG_MSG("Parser quits:\tpayload end\n");
		return false;
	}
	remaining = payloadLen - (end - data);
	begin = static_cast<const char*>(memchr(end, RTSP_LINE_DELIMITER, remaining));
	if (begin == nullptr) {
		DEBUG_MSG("Parser quits:\tNo line delim after request line\n");
		return false;
	}
	begin++;

	/* Header:
	 *
	 * REQ-FIELD: VALUE
	 * |        |      |
	 * |        |      ----- end
	 * |        ------------ keyval_delimiter
	 * --------------------- begin
	 */

	rec->userAgent[0] = 0;
	/* Process headers. */
	while (begin - data < payloadLen) {
		remaining = payloadLen - (begin - data);
		end = static_cast<const char*>(memchr(begin, RTSP_LINE_DELIMITER, remaining));
		keyvalDelimiter
			= static_cast<const char*>(memchr(begin, RTSP_KEYVAL_DELIMITER, remaining));

		int tmp = end - begin;
		if (tmp == 0 || tmp == 1) { /* Check for blank line with \r\n or \n ending. */
			break; /* Double LF found - end of header section. */
		} else if (end == nullptr || keyvalDelimiter == NULL) {
			DEBUG_MSG("Parser quits:\theader is fragmented\n");
			return false;
		}

		/* Copy field name. */
		copyStr(buffer, sizeof(buffer), begin, keyvalDelimiter);

		DEBUG_CODE(char debug_buffer[4096]);
		DEBUG_CODE(copy_str(debug_buffer, sizeof(debug_buffer), keyval_delimiter + 2, end));
		DEBUG_MSG("\t%s: %s\n", buffer, debug_buffer);

		/* Copy interesting field values. */
		if (!strcmp(buffer, "User-Agent")) {
			copyStr(rec->userAgent, sizeof(rec->userAgent), keyvalDelimiter + 2, end);
		}

		/* Go to next line. */
		begin = end + 1;
	}

	DEBUG_MSG("Parser quits:\tend of header section\n");
	rec->req = true;
	m_requests++;
	return true;
}

/**
 * \brief Parse and store rtsp response.
 * \param [in] data Packet payload data.
 * \param [in] payload_len Length of packet payload.
 * \param [out] rec Variable where rtsp response will be stored.
 * \return True if request was parsed, false if error occured.
 */
bool RTSPPlugin::parseRtspResponse(const char* data, int payloadLen, RecordExtRTSP* rec)
{
	char buffer[64];
	const char* begin;
	const char* end;
	const char* keyvalDelimiter;
	size_t remaining;
	int code;

	m_total++;

	DEBUG_MSG("---------- rtsp parser #%u ----------\n", total);
	DEBUG_MSG("Parsing response number: %u\n", ++s_responses);
	DEBUG_MSG("Payload length: %u\n\n", payload_len);

	if (payloadLen == 0) {
		DEBUG_MSG("Parser quits:\tpayload length = 0\n");
		return false;
	}

	/* Check begin of response header. */
	if (memcmp(data, "RTSP", 4)) {
		DEBUG_MSG("Parser quits:\tpacket contains rtsp response data\n");
		return false;
	}

	/* Response line:
	 *
	 * VERSION CODE REASON
	 * |      |    |
	 * |      |    --------- end
	 * |      -------------- begin
	 * --------------------- data
	 */

	/* Find begin of status code. */
	begin = static_cast<const char*>(memchr(data, ' ', payloadLen));
	if (begin == nullptr) {
		DEBUG_MSG("Parser quits:\tnot a rtsp response header\n");
		return false;
	}

	/* Find end of status code. */
	if (checkPayloadLen(payloadLen, (begin + 1) - data)) {
		DEBUG_MSG("Parser quits:\tpayload end\n");
		return false;
	}
	remaining = payloadLen - ((begin + 1) - data);
	end = static_cast<const char*>(memchr(begin + 1, ' ', remaining));
	if (end == nullptr) {
		DEBUG_MSG("Parser quits:\tresponse is fragmented\n");
		return false;
	}

	/* Copy and check RTSP response code. */
	copyStr(buffer, sizeof(buffer), begin + 1, end);
	code = atoi(buffer);
	if (code <= 0) {
		DEBUG_MSG("Parser quits:\twrong response code: %d\n", code);
		return false;
	}

	DEBUG_MSG("\tCode: %d\n", code);
	if (rec->resp) {
		m_flow_flush = true;
		m_total--;
		DEBUG_MSG("Parser quits:\tflushing flow\n");
		return false;
	}
	rec->code = code;

	/* Find begin of next line after request line. */
	if (checkPayloadLen(payloadLen, end - data)) {
		DEBUG_MSG("Parser quits:\tpayload end\n");
		return false;
	}
	remaining = payloadLen - (end - data);
	begin = static_cast<const char*>(memchr(end, RTSP_LINE_DELIMITER, remaining));
	if (begin == nullptr) {
		DEBUG_MSG("Parser quits:\tNo line delim after request line\n");
		return false;
	}
	begin++;

	/* Header:
	 *
	 * REQ-FIELD: VALUE
	 * |        |      |
	 * |        |      ----- end
	 * |        ------------ keyval_delimiter
	 * --------------------- begin
	 */

	rec->contentType[0] = 0;
	/* Process headers. */
	while (begin - data < payloadLen) {
		remaining = payloadLen - (begin - data);
		end = static_cast<const char*>(memchr(begin, RTSP_LINE_DELIMITER, remaining));
		keyvalDelimiter
			= static_cast<const char*>(memchr(begin, RTSP_KEYVAL_DELIMITER, remaining));

		int tmp = end - begin;
		if (tmp == 0 || tmp == 1) { /* Check for blank line with \r\n or \n ending. */
			break; /* Double LF found - end of header section. */
		} else if (end == nullptr || keyvalDelimiter == NULL) {
			DEBUG_MSG("Parser quits:\theader is fragmented\n");
			return false;
		}

		/* Copy field name. */
		copyStr(buffer, sizeof(buffer), begin, keyvalDelimiter);

		DEBUG_CODE(char debug_buffer[4096]);
		DEBUG_CODE(copy_str(debug_buffer, sizeof(debug_buffer), keyval_delimiter + 2, end));
		DEBUG_MSG("\t%s: %s\n", buffer, debug_buffer);

		/* Copy interesting field values. */
		if (!strcmp(buffer, "Content-Type")) {
			copyStr(rec->contentType, sizeof(rec->contentType), keyvalDelimiter + 2, end);
		} else if (!strcmp(buffer, "Server")) {
			copyStr(rec->server, sizeof(rec->server), keyvalDelimiter + 2, end);
		}

		/* Go to next line. */
		begin = end + 1;
	}

	DEBUG_MSG("Parser quits:\tend of header section\n");
	rec->resp = true;
	m_responses++;
	return true;
}

/**
 * \brief Check rtsp method.
 * \param [in] method C string with rtsp method.
 * \return True if rtsp method is valid.
 */
bool RTSPPlugin::validRtspMethod(const char* method) const
{
	return (
		!strcmp(method, "GET ") || !strcmp(method, "POST") || !strcmp(method, "PUT ")
		|| !strcmp(method, "HEAD") || !strcmp(method, "DELE") || !strcmp(method, "TRAC")
		|| !strcmp(method, "OPTI") || !strcmp(method, "CONN") || !strcmp(method, "PATC")
		|| !strcmp(method, "DESC") || !strcmp(method, "SETU") || !strcmp(method, "PLAY")
		|| !strcmp(method, "PAUS") || !strcmp(method, "TEAR") || !strcmp(method, "RECO")
		|| !strcmp(method, "ANNO"));
}

/**
 * \brief Add new extension rtsp request header into flow record.
 * \param [in] data Packet payload data.
 * \param [in] payload_len Length of packet payload.
 * \param [out] flow Flow record where to store created extension header.
 */
void RTSPPlugin::addExtRtspRequest(const char* data, int payloadLen, Flow& flow)
{
	if (m_recPrealloc == nullptr) {
		m_recPrealloc = new RecordExtRTSP();
	}

	if (parseRtspRequest(data, payloadLen, m_recPrealloc)) {
		flow.addExtension(m_recPrealloc);
		m_recPrealloc = nullptr;
	}
}

/**
 * \brief Add new extension rtsp response header into flow record.
 * \param [in] data Packet payload data.
 * \param [in] payload_len Length of packet payload.
 * \param [out] flow Flow record where to store created extension header.
 */
void RTSPPlugin::addExtRtspResponse(const char* data, int payloadLen, Flow& flow)
{
	if (m_recPrealloc == nullptr) {
		m_recPrealloc = new RecordExtRTSP();
	}

	if (parseRtspResponse(data, payloadLen, m_recPrealloc)) {
		flow.addExtension(m_recPrealloc);
		m_recPrealloc = nullptr;
	}
}

} // namespace ipxp
