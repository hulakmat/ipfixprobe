/**
 * \file http.cpp
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

#include <cstdlib>
#include <cstring>
#include <iostream>

#ifdef WITH_NEMEA
#include <unirec/unirec.h>
#endif

#include "common.hpp"
#include "http.hpp"

namespace Ipxp {

int RecordExtHTTP::s_registeredId = -1;

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("http", []() { return new HTTPPlugin(); });
	registerPlugin(&rec);
	RecordExtHTTP::s_registeredId = registerExtension();
}

//#define DEBUG_HTTP

// Print debug message if debugging is allowed.
#ifdef DEBUG_HTTP
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_HTTP
#define DEBUG_CODE(code) code
#else
#define DEBUG_CODE(code)
#endif

#define HTTP_LINE_DELIMITER "\r\n"
#define HTTP_KEYVAL_DELIMITER ':'

HTTPPlugin::HTTPPlugin()
	: m_recPrealloc(nullptr)
	, m_flow_flush(false)
	, m_requests(0)
	, m_responses(0)
	, m_total(0)
{
}

HTTPPlugin::~HTTPPlugin()
{
	close();
}

void HTTPPlugin::init(const char* params) {}

void HTTPPlugin::close()
{
	if (m_recPrealloc != nullptr) {
		delete m_recPrealloc;
		m_recPrealloc = nullptr;
	}
}

ProcessPlugin* HTTPPlugin::copy()
{
	return new HTTPPlugin(*this);
}

int HTTPPlugin::postCreate(Flow& rec, const Packet& pkt)
{
	const char* payload = reinterpret_cast<const char*>(pkt.payload);
	if (isRequest(payload, pkt.payloadLen)) {
		addExtHttpRequest(payload, pkt.payloadLen, rec);
	} else if (isResponse(payload, pkt.payloadLen)) {
		addExtHttpResponse(payload, pkt.payloadLen, rec);
	}

	return 0;
}

int HTTPPlugin::preUpdate(Flow& rec, Packet& pkt)
{
	RecordExt* ext = nullptr;
	const char* payload = reinterpret_cast<const char*>(pkt.payload);
	if (isRequest(payload, pkt.payloadLen)) {
		ext = rec.getExtension(RecordExtHTTP::s_registeredId);
		if (ext == nullptr) { /* Check if header is present in flow. */
			addExtHttpRequest(payload, pkt.payloadLen, rec);
			return 0;
		}

		parseHttpRequest(payload, pkt.payloadLen, static_cast<RecordExtHTTP*>(ext));
		if (m_flow_flush) {
			m_flow_flush = false;
			return FLOW_FLUSH_WITH_REINSERT;
		}
	} else if (isResponse(payload, pkt.payloadLen)) {
		ext = rec.getExtension(RecordExtHTTP::s_registeredId);
		if (ext == nullptr) { /* Check if header is present in flow. */
			addExtHttpResponse(payload, pkt.payloadLen, rec);
			return 0;
		}

		parseHttpResponse(payload, pkt.payloadLen, static_cast<RecordExtHTTP*>(ext));
		if (m_flow_flush) {
			m_flow_flush = false;
			return FLOW_FLUSH_WITH_REINSERT;
		}
	}

	return 0;
}

void HTTPPlugin::finish(bool printStats)
{
	if (printStats) {
		std::cout << "HTTP plugin stats:" << std::endl;
		std::cout << "   Parsed http requests: " << m_requests << std::endl;
		std::cout << "   Parsed http responses: " << m_responses << std::endl;
		std::cout << "   Total http packets processed: " << m_total << std::endl;
	}
}

/**
 * \brief Copy string and append \0 character.
 * NOTE: function removes any CR chars at the end of string.
 * \param [in] dst Destination buffer.
 * \param [in] size Size of destination buffer.
 * \param [in] begin Ptr to begin of source string.
 * \param [in] end Ptr to end of source string.
 */
void copyStr(char* dst, ssize_t size, const char* begin, const char* end)
{
	ssize_t len = end - begin;
	if (len >= size) {
		len = size - 1;
	}

	memcpy(dst, begin, len);

	if (len >= 1 && dst[len - 1] == '\n') {
		len--;
	}

	if (len >= 1 && dst[len - 1] == '\r') {
		len--;
	}

	dst[len] = 0;
}

bool HTTPPlugin::isRequest(const char* data, int payloadLen)
{
	char chars[5];

	if (payloadLen < 4) {
		return false;
	}
	memcpy(chars, data, 4);
	chars[4] = 0;
	return validHttpMethod(chars);
}

bool HTTPPlugin::isResponse(const char* data, int payloadLen)
{
	char chars[5];

	if (payloadLen < 4) {
		return false;
	}
	memcpy(chars, data, 4);
	chars[4] = 0;
	return !strcmp(chars, "HTTP");
}

#ifdef DEBUG_HTTP
static uint32_t s_requests = 0, s_responses = 0;
#endif /* DEBUG_HTTP */

/**
 * \brief Parse and store http request.
 * \param [in] data Packet payload data.
 * \param [in] payload_len Length of packet payload.
 * \param [out] rec Variable where http request will be stored.
 * \return True if request was parsed, false if error occured.
 */
bool HTTPPlugin::parseHttpRequest(const char* data, int payloadLen, RecordExtHTTP* rec)
{
	char buffer[64];
	size_t remaining;
	const char *begin, *end, *keyvalDelimiter;

	m_total++;

	DEBUG_MSG("---------- http parser #%u ----------\n", total);
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
		DEBUG_MSG("Parser quits:\tnot a http request header\n");
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

	if (memcmp(end + 1, "HTTP", 4)) {
		DEBUG_MSG("Parser quits:\tnot a HTTP request\n");
		return false;
	}

	/* Copy and check HTTP method */
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
	begin = Ipxp::strnstr(end, HTTP_LINE_DELIMITER, remaining);
	if (begin == nullptr) {
		DEBUG_MSG("Parser quits:\tNo line delim after request line\n");
		return false;
	}
	begin += 2;

	/* Header:
	 *
	 * REQ-FIELD: VALUE
	 * |        |      |
	 * |        |      ----- end
	 * |        ------------ keyval_delimiter
	 * --------------------- begin
	 */

	rec->host[0] = 0;
	rec->userAgent[0] = 0;
	rec->referer[0] = 0;
	/* Process headers. */
	while (begin - data < payloadLen) {
		remaining = payloadLen - (begin - data);
		end = Ipxp::strnstr(begin, HTTP_LINE_DELIMITER, remaining);
		keyvalDelimiter
			= static_cast<const char*>(memchr(begin, HTTP_KEYVAL_DELIMITER, remaining));

		if (end == nullptr) {
			DEBUG_MSG("Parser quits:\theader is fragmented\n");
			return false;
		}

		end += 1;
		int tmp = end - begin;
		if (tmp == 0 || tmp == 1) { /* Check for blank line with \r\n or \n ending. */
			break; /* Double LF found - end of header section. */
		} else if (keyvalDelimiter == nullptr) {
			DEBUG_MSG("Parser quits:\theader is fragmented\n");
			return false;
		}

		/* Copy field name. */
		copyStr(buffer, sizeof(buffer), begin, keyvalDelimiter);

		DEBUG_CODE(char debug_buffer[4096]);
		DEBUG_CODE(copy_str(debug_buffer, sizeof(debug_buffer), keyval_delimiter + 2, end));
		DEBUG_MSG("\t%s: %s\n", buffer, debug_buffer);

		/* Copy interesting field values. */
		if (!strcmp(buffer, "Host")) {
			copyStr(rec->host, sizeof(rec->host), keyvalDelimiter + 2, end);
		} else if (!strcmp(buffer, "User-Agent")) {
			copyStr(rec->userAgent, sizeof(rec->userAgent), keyvalDelimiter + 2, end);
		} else if (!strcmp(buffer, "Referer")) {
			copyStr(rec->referer, sizeof(rec->referer), keyvalDelimiter + 2, end);
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
 * \brief Parse and store http response.
 * \param [in] data Packet payload data.
 * \param [in] payload_len Length of packet payload.
 * \param [out] rec Variable where http response will be stored.
 * \return True if request was parsed, false if error occured.
 */
bool HTTPPlugin::parseHttpResponse(const char* data, int payloadLen, RecordExtHTTP* rec)
{
	char buffer[64];
	const char *begin, *end, *keyvalDelimiter;
	size_t remaining;
	int code;

	m_total++;

	DEBUG_MSG("---------- http parser #%u ----------\n", total);
	DEBUG_MSG("Parsing response number: %u\n", ++s_responses);
	DEBUG_MSG("Payload length: %u\n\n", payload_len);

	if (payloadLen == 0) {
		DEBUG_MSG("Parser quits:\tpayload length = 0\n");
		return false;
	}

	/* Check begin of response header. */
	if (memcmp(data, "HTTP", 4)) {
		DEBUG_MSG("Parser quits:\tpacket contains http response data\n");
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
		DEBUG_MSG("Parser quits:\tnot a http response header\n");
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

	/* Copy and check HTTP response code. */
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
	begin = Ipxp::strnstr(end, HTTP_LINE_DELIMITER, remaining);
	if (begin == nullptr) {
		DEBUG_MSG("Parser quits:\tNo line delim after request line\n");
		return false;
	}
	begin += 2;

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
		end = Ipxp::strnstr(begin, HTTP_LINE_DELIMITER, remaining);
		keyvalDelimiter
			= static_cast<const char*>(memchr(begin, HTTP_KEYVAL_DELIMITER, remaining));

		if (end == nullptr) {
			DEBUG_MSG("Parser quits:\theader is fragmented\n");
			return false;
		}

		end += 1;
		int tmp = end - begin;
		if (tmp == 0 || tmp == 1) { /* Check for blank line with \r\n or \n ending. */
			break; /* Double LF found - end of header section. */
		} else if (keyvalDelimiter == nullptr) {
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
 * \brief Check http method.
 * \param [in] method C string with http method.
 * \return True if http method is valid.
 */
bool HTTPPlugin::validHttpMethod(const char* method) const
{
	return (
		!strcmp(method, "GET ") || !strcmp(method, "POST") || !strcmp(method, "PUT ")
		|| !strcmp(method, "HEAD") || !strcmp(method, "DELE") || !strcmp(method, "TRAC")
		|| !strcmp(method, "OPTI") || !strcmp(method, "CONN") || !strcmp(method, "PATC"));
}

/**
 * \brief Add new extension http request header into flow record.
 * \param [in] data Packet payload data.
 * \param [in] payload_len Length of packet payload.
 * \param [out] flow Flow record where to store created extension header.
 */
void HTTPPlugin::addExtHttpRequest(const char* data, int payloadLen, Flow& flow)
{
	if (m_recPrealloc == nullptr) {
		m_recPrealloc = new RecordExtHTTP();
	}

	if (parseHttpRequest(data, payloadLen, m_recPrealloc)) {
		flow.addExtension(m_recPrealloc);
		m_recPrealloc = nullptr;
	}
}

/**
 * \brief Add new extension http response header into flow record.
 * \param [in] data Packet payload data.
 * \param [in] payload_len Length of packet payload.
 * \param [out] flow Flow record where to store created extension header.
 */
void HTTPPlugin::addExtHttpResponse(const char* data, int payloadLen, Flow& flow)
{
	if (m_recPrealloc == nullptr) {
		m_recPrealloc = new RecordExtHTTP();
	}

	if (parseHttpResponse(data, payloadLen, m_recPrealloc)) {
		flow.addExtension(m_recPrealloc);
		m_recPrealloc = nullptr;
	}
}

} // namespace ipxp
