/**
 * \file smtp.cpp
 * \brief Plugin for parsing smtp traffic.
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2018
 */
/*
 * Copyright (C) 2018 CESNET
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

#include <cstring>
#include <ctype.h>
#include <iostream>

#include "common.hpp"
#include "smtp.hpp"

namespace Ipxp {

int RecordExtSMTP::s_registeredId = -1;

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("smtp", []() { return new SMTPPlugin(); });
	registerPlugin(&rec);
	RecordExtSMTP::s_registeredId = registerExtension();
}

SMTPPlugin::SMTPPlugin()
	: m_ext_ptr(nullptr)
	, m_total(0)
	, m_replies_cnt(0)
	, m_commands_cnt(0)
{
}

SMTPPlugin::~SMTPPlugin()
{
	close();
}

void SMTPPlugin::init(const char* params) {}

void SMTPPlugin::close() {}

ProcessPlugin* SMTPPlugin::copy()
{
	return new SMTPPlugin(*this);
}

int SMTPPlugin::postCreate(Flow& rec, const Packet& pkt)
{
	if (pkt.srcPort == 25 || pkt.dstPort == 25) {
		createSmtpRecord(rec, pkt);
	}

	return 0;
}

int SMTPPlugin::preUpdate(Flow& rec, Packet& pkt)
{
	if (pkt.srcPort == 25 || pkt.dstPort == 25) {
		RecordExt* ext = rec.getExtension(RecordExtSMTP::s_registeredId);
		if (ext == nullptr) {
			createSmtpRecord(rec, pkt);
			return 0;
		}
		updateSmtpRecord(static_cast<RecordExtSMTP*>(ext), pkt);
	}

	return 0;
}

char* strncasestr(const char* str, size_t n, const char* substr)
{
	size_t i = 0;
	size_t j = 0;
	while (i < n && *str) {
		if (tolower(*str) == tolower(substr[j])) {
			j++;
			if (!substr[j]) {
				return (char*) str;
			}
		} else {
			j = 0;
		}
		i++;
		str++;
	}
	return nullptr;
}

/**
 * \brief Parse SMTP server data.
 *
 * \param [in] data Pointer to SMTP data.
 * \param [in] payload_len Length of `data` buffer.
 * \param [out] rec Pointer to SMTP extension record.
 * \return True on success, false otherwise.
 */
bool SMTPPlugin::parseSmtpResponse(const char* data, int payloadLen, RecordExtSMTP* rec)
{
	if (payloadLen < 5 || !(data[3] == ' ' || data[3] == '-')) {
		return false;
	}
	for (int i = 0; i < 3; i++) {
		if (!isdigit(data[i])) {
			return false;
		}
	}

	switch (atoi(data)) {
	case 211:
		rec->mailCodeFlags |= SMTP_SC_211;
		break;
	case 214:
		rec->mailCodeFlags |= SMTP_SC_214;
		break;
	case 220:
		rec->mailCodeFlags |= SMTP_SC_220;
		break;
	case 221:
		rec->mailCodeFlags |= SMTP_SC_221;
		break;
	case 250:
		rec->mailCodeFlags |= SMTP_SC_250;
		break;
	case 251:
		rec->mailCodeFlags |= SMTP_SC_251;
		break;
	case 252:
		rec->mailCodeFlags |= SMTP_SC_252;
		break;
	case 354:
		rec->mailCodeFlags |= SMTP_SC_354;
		break;
	case 421:
		rec->mailCodeFlags |= SMTP_SC_421;
		break;
	case 450:
		rec->mailCodeFlags |= SMTP_SC_450;
		break;
	case 451:
		rec->mailCodeFlags |= SMTP_SC_451;
		break;
	case 452:
		rec->mailCodeFlags |= SMTP_SC_452;
		break;
	case 455:
		rec->mailCodeFlags |= SMTP_SC_455;
		break;
	case 500:
		rec->mailCodeFlags |= SMTP_SC_500;
		break;
	case 501:
		rec->mailCodeFlags |= SMTP_SC_501;
		break;
	case 502:
		rec->mailCodeFlags |= SMTP_SC_502;
		break;
	case 503:
		rec->mailCodeFlags |= SMTP_SC_503;
		break;
	case 504:
		rec->mailCodeFlags |= SMTP_SC_504;
		break;
	case 550:
		rec->mailCodeFlags |= SMTP_SC_550;
		break;
	case 551:
		rec->mailCodeFlags |= SMTP_SC_551;
		break;
	case 552:
		rec->mailCodeFlags |= SMTP_SC_552;
		break;
	case 553:
		rec->mailCodeFlags |= SMTP_SC_553;
		break;
	case 554:
		rec->mailCodeFlags |= SMTP_SC_554;
		break;
	case 555:
		rec->mailCodeFlags |= SMTP_SC_555;
		break;
	default:
		rec->mailCodeFlags |= SC_UNKNOWN;
		break;
	}

	if (strncasestr(data, payloadLen, "SPAM") != nullptr) {
		rec->mailCodeFlags |= SC_SPAM;
	}

	switch (data[0]) {
	case '2':
		rec->code2xxCnt++;
		break;
	case '3':
		rec->code3xxCnt++;
		break;
	case '4':
		rec->code4xxCnt++;
		break;
	case '5':
		rec->code5xxCnt++;
		break;
	default:
		return false;
	}

	m_replies_cnt++;
	return true;
}

/**
 * \brief Check for keyword.
 *
 * \param [in] data Pointer to data.
 * \return True on success, false otherwise.
 */
bool SMTPPlugin::smtpKeyword(const char* data)
{
	for (int i = 0; data[i]; i++) {
		if (!isupper(data[i])) {
			return false;
		}
	}
	return true;
}

/**
 * \brief Parse SMTP client traffic.
 *
 * \param [in] data Pointer to SMTP data.
 * \param [in] payload_len Length of `data` buffer.
 * \param [out] rec Pointer to SMTP extension record.
 * \return True on success, false otherwise.
 */
bool SMTPPlugin::parseSmtpCommand(const char* data, int payloadLen, RecordExtSMTP* rec)
{
	const char *begin, *end;
	char buffer[32];
	size_t len;
	size_t remaining;

	if (payloadLen == 0) {
		return false;
	}

	if (rec->dataTransfer) {
		if (payloadLen != 3 || strcmp(data, ".\r\n")) {
			return false;
		}
		rec->dataTransfer = 0;
		return true;
	}

	begin = data;
	end = static_cast<const char*>(memchr(begin, '\r', payloadLen));

	len = end - begin;
	if (end == nullptr) {
		return false;
	}
	end = static_cast<const char*>(memchr(begin, ' ', payloadLen));
	if (end != nullptr) {
		len = end - begin;
	}
	if (len >= sizeof(buffer)) {
		return false;
	}

	memcpy(buffer, begin, len);
	buffer[len] = 0;

	if (!strcmp(buffer, "HELO") || !strcmp(buffer, "EHLO")) {
		if (rec->domain[0] == 0 && end != nullptr) {
			begin = end;
			remaining = payloadLen - (begin - data);
			end = static_cast<const char*>(memchr(begin, '\r', remaining));
			if (end != nullptr && begin != NULL) {
				begin++;
				len = end - begin;
				if (len >= sizeof(rec->domain)) {
					len = sizeof(rec->domain) - 1;
				}

				memcpy(rec->domain, begin, len);
				rec->domain[len] = 0;
			}
		}
		if (!strcmp(buffer, "HELO")) {
			rec->commandFlags |= SMTP_CMD_HELO;
		} else {
			rec->commandFlags |= SMTP_CMD_EHLO;
		}
	} else if (!strcmp(buffer, "RCPT")) {
		rec->mailRcptCnt++;
		if (rec->firstRecipient[0] == 0 && end != nullptr) {
			if (checkPayloadLen(payloadLen, (end + 1) - data)) {
				return false;
			}
			remaining = payloadLen - ((end + 1) - data);
			begin = static_cast<const char*>(memchr(end + 1, ':', remaining));
			remaining = payloadLen - (end - data);
			end = static_cast<const char*>(memchr(end, '\r', remaining));

			if (end != nullptr && begin != NULL) {
				begin++;
				len = end - begin;
				if (len >= sizeof(rec->firstRecipient)) {
					len = sizeof(rec->firstRecipient) - 1;
				}

				memcpy(rec->firstRecipient, begin, len);
				rec->firstRecipient[len] = 0;
			}
		}
		rec->commandFlags |= SMTP_CMD_RCPT;
	} else if (!strcmp(buffer, "MAIL")) {
		rec->mailCmdCnt++;
		if (rec->firstSender[0] == 0 && end != nullptr) {
			if (checkPayloadLen(payloadLen, (end + 1) - data)) {
				return false;
			}
			remaining = payloadLen - ((end + 1) - data);
			begin = static_cast<const char*>(memchr(end + 1, ':', remaining));
			remaining = payloadLen - (end - data);
			end = static_cast<const char*>(memchr(end, '\r', remaining));

			if (end != nullptr && begin != NULL) {
				begin++;
				len = end - begin;
				if (len >= sizeof(rec->firstSender)) {
					len = sizeof(rec->firstSender) - 1;
				}

				memcpy(rec->firstSender, begin, len);
				rec->firstSender[len] = 0;
			}
		}
		rec->commandFlags |= SMTP_CMD_MAIL;
	} else if (!strcmp(buffer, "DATA")) {
		rec->dataTransfer = 1;
		rec->commandFlags |= SMTP_CMD_DATA;
	} else if (!strcmp(buffer, "VRFY")) {
		rec->commandFlags |= SMTP_CMD_VRFY;
	} else if (!strcmp(buffer, "EXPN")) {
		rec->commandFlags |= SMTP_CMD_EXPN;
	} else if (!strcmp(buffer, "HELP")) {
		rec->commandFlags |= SMTP_CMD_HELP;
	} else if (!strcmp(buffer, "NOOP")) {
		rec->commandFlags |= SMTP_CMD_NOOP;
	} else if (!strcmp(buffer, "QUIT")) {
		rec->commandFlags |= SMTP_CMD_QUIT;
	} else if (!smtpKeyword(buffer)) {
		rec->commandFlags |= CMD_UNKNOWN;
	}

	m_commands_cnt++;
	return true;
}

void SMTPPlugin::createSmtpRecord(Flow& rec, const Packet& pkt)
{
	if (m_ext_ptr == nullptr) {
		m_ext_ptr = new RecordExtSMTP();
	}

	if (updateSmtpRecord(m_ext_ptr, pkt)) {
		rec.addExtension(m_ext_ptr);
		m_ext_ptr = nullptr;
	}
}

bool SMTPPlugin::updateSmtpRecord(RecordExtSMTP* ext, const Packet& pkt)
{
	m_total++;
	const char* payload = reinterpret_cast<const char*>(pkt.payload);
	if (pkt.srcPort == 25) {
		return parseSmtpResponse(payload, pkt.payloadLen, ext);
	} else if (pkt.dstPort == 25) {
		return parseSmtpCommand(payload, pkt.payloadLen, ext);
	}

	return false;
}

void SMTPPlugin::finish(bool printStats)
{
	if (printStats) {
		std::cout << "SMTP plugin stats:" << std::endl;
		std::cout << "   Total SMTP packets: " << m_total << std::endl;
		std::cout << "   Parsed SMTP replies: " << m_replies_cnt << std::endl;
		std::cout << "   Parsed SMTP commands: " << m_commands_cnt << std::endl;
	}
}

} // namespace ipxp
