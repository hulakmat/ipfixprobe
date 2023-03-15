/**
 * \file smtp.hpp
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

#ifndef IPXP_PROCESS_SMTP_HPP
#define IPXP_PROCESS_SMTP_HPP

#include <cstring>
#include <sstream>
#include <string>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/process.hpp>

namespace Ipxp {

/* Commands. */
#define SMTP_CMD_EHLO 0x0001
#define SMTP_CMD_HELO 0x0002
#define SMTP_CMD_MAIL 0x0004
#define SMTP_CMD_RCPT 0x0008
#define SMTP_CMD_DATA 0x0010
#define SMTP_CMD_RSET 0x0020
#define SMTP_CMD_VRFY 0x0040
#define SMTP_CMD_EXPN 0x0080
#define SMTP_CMD_HELP 0x0100
#define SMTP_CMD_NOOP 0x0200
#define SMTP_CMD_QUIT 0x0400
#define CMD_UNKNOWN 0x8000

/* Status codes. */
#define SMTP_SC_211 0x00000001
#define SMTP_SC_214 0x00000002
#define SMTP_SC_220 0x00000004
#define SMTP_SC_221 0x00000008
#define SMTP_SC_250 0x00000010
#define SMTP_SC_251 0x00000020
#define SMTP_SC_252 0x00000040
#define SMTP_SC_354 0x00000080
#define SMTP_SC_421 0x00000100
#define SMTP_SC_450 0x00000200
#define SMTP_SC_451 0x00000400
#define SMTP_SC_452 0x00000800
#define SMTP_SC_455 0x00001000
#define SMTP_SC_500 0x00002000
#define SMTP_SC_501 0x00004000
#define SMTP_SC_502 0x00008000
#define SMTP_SC_503 0x00010000
#define SMTP_SC_504 0x00020000
#define SMTP_SC_550 0x00040000
#define SMTP_SC_551 0x00080000
#define SMTP_SC_552 0x00100000
#define SMTP_SC_553 0x00200000
#define SMTP_SC_554 0x00400000
#define SMTP_SC_555 0x00800000
#define SC_SPAM 0x40000000 // indicates that answer contains SPAM keyword
#define SC_UNKNOWN 0x80000000

#define SMTP_UNIREC_TEMPLATE                                                                       \
	"SMTP_2XX_STAT_CODE_COUNT,SMTP_3XX_STAT_CODE_COUNT,SMTP_4XX_STAT_CODE_COUNT,SMTP_5XX_STAT_"    \
	"CODE_COUNT,SMTP_COMMAND_FLAGS,SMTP_MAIL_CMD_COUNT,SMTP_RCPT_CMD_COUNT,SMTP_STAT_CODE_FLAGS,"  \
	"SMTP_DOMAIN,SMTP_FIRST_RECIPIENT,SMTP_FIRST_SENDER"

UR_FIELDS(
	uint32 SMTP_2XX_STAT_CODE_COUNT,
	uint32 SMTP_3XX_STAT_CODE_COUNT,
	uint32 SMTP_4XX_STAT_CODE_COUNT,
	uint32 SMTP_5XX_STAT_CODE_COUNT,
	uint32 SMTP_COMMAND_FLAGS,
	uint32 SMTP_MAIL_CMD_COUNT,
	uint32 SMTP_RCPT_CMD_COUNT,
	uint32 SMTP_STAT_CODE_FLAGS,
	string SMTP_DOMAIN,
	string SMTP_FIRST_SENDER,
	string SMTP_FIRST_RECIPIENT)

/**
 * \brief Flow record extension header for storing parsed SMTP packets.
 */
struct RecordExtSMTP : public RecordExt {
	static int s_registeredId;

	uint32_t code2xxCnt;
	uint32_t code3xxCnt;
	uint32_t code4xxCnt;
	uint32_t code5xxCnt;
	uint32_t commandFlags;
	uint32_t mailCmdCnt;
	uint32_t mailRcptCnt;
	uint32_t mailCodeFlags;
	char domain[255];
	char firstSender[255];
	char firstRecipient[255];
	int dataTransfer;

	/**
	 * \brief Constructor.
	 */
	RecordExtSMTP()
		: RecordExt(s_registeredId)
	{
		code2xxCnt = 0;
		code3xxCnt = 0;
		code4xxCnt = 0;
		code5xxCnt = 0;
		commandFlags = 0;
		mailCmdCnt = 0;
		mailRcptCnt = 0;
		mailCodeFlags = 0;
		domain[0] = 0;
		firstSender[0] = 0;
		firstRecipient[0] = 0;
		dataTransfer = 0;
	}

#ifdef WITH_NEMEA
	virtual void fillUnirec(ur_template_t* tmplt, void* record)
	{
		ur_set(tmplt, record, F_SMTP_2XX_STAT_CODE_COUNT, code2xxCnt);
		ur_set(tmplt, record, F_SMTP_3XX_STAT_CODE_COUNT, code3xxCnt);
		ur_set(tmplt, record, F_SMTP_4XX_STAT_CODE_COUNT, code4xxCnt);
		ur_set(tmplt, record, F_SMTP_5XX_STAT_CODE_COUNT, code5xxCnt);
		ur_set(tmplt, record, F_SMTP_COMMAND_FLAGS, commandFlags);
		ur_set(tmplt, record, F_SMTP_MAIL_CMD_COUNT, mailCmdCnt);
		ur_set(tmplt, record, F_SMTP_RCPT_CMD_COUNT, mailRcptCnt);
		ur_set(tmplt, record, F_SMTP_STAT_CODE_FLAGS, mailCodeFlags);
		ur_set_string(tmplt, record, F_SMTP_DOMAIN, domain);
		ur_set_string(tmplt, record, F_SMTP_FIRST_SENDER, firstSender);
		ur_set_string(tmplt, record, F_SMTP_FIRST_RECIPIENT, firstRecipient);
	}

	const char* getUnirecTmplt() const
	{
		return SMTP_UNIREC_TEMPLATE;
	}
#endif

	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		int domainLen = strlen(domain);
		int senderLen = strlen(firstSender);
		int recipientLen = strlen(firstRecipient);
		int length;

		if (domainLen + senderLen + recipientLen + 35 > size) {
			return -1;
		}

		*(uint32_t*) (buffer) = ntohl(commandFlags);
		*(uint32_t*) (buffer + 4) = ntohl(mailCmdCnt);
		*(uint32_t*) (buffer + 8) = ntohl(mailRcptCnt);
		*(uint32_t*) (buffer + 12) = ntohl(mailCodeFlags);
		*(uint32_t*) (buffer + 16) = ntohl(code2xxCnt);
		*(uint32_t*) (buffer + 20) = ntohl(code3xxCnt);
		*(uint32_t*) (buffer + 24) = ntohl(code4xxCnt);
		*(uint32_t*) (buffer + 28) = ntohl(code5xxCnt);

		length = 32;
		buffer[length++] = domainLen;
		memcpy(buffer + length, domain, domainLen);

		length += domainLen;
		buffer[length++] = senderLen;
		memcpy(buffer + length, firstSender, senderLen);

		length += senderLen;
		buffer[length++] = recipientLen;
		memcpy(buffer + length, firstRecipient, recipientLen);

		length += recipientLen;

		return length;
	}

	const char** getIpfixTmplt() const
	{
		static const char* ipfixTemplate[] = {IPFIX_SMTP_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};
		return ipfixTemplate;
	}

	std::string getText() const
	{
		std::ostringstream out;
		out << "2xxcnt=" << code2xxCnt << ",3xxcnt=" << code3xxCnt << ",4xxcnt=" << code4xxCnt
			<< ",5xxcnt=" << code5xxCnt << ",cmdflgs=" << commandFlags
			<< ",mailcmdcnt=" << mailCmdCnt << ",rcptcmdcnt=" << mailRcptCnt
			<< ",codeflags=" << mailCodeFlags << ",domain=\"" << domain << "\""
			<< ",firstsender=\"" << firstSender << "\""
			<< ",firstrecipient=\"" << firstRecipient << "\"";
		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing SMTP packets.
 */
class SMTPPlugin : public ProcessPlugin {
public:
	SMTPPlugin();
	~SMTPPlugin();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const { return new OptionsParser("smtp", "Parse SMTP traffic"); }
	std::string getName() const { return "smtp"; }
	RecordExt* getExt() const { return new RecordExtSMTP(); }
	ProcessPlugin* copy();

	int postCreate(Flow& rec, const Packet& pkt);
	int preUpdate(Flow& rec, Packet& pkt);
	void finish(bool printStats);

	bool smtpKeyword(const char* data);
	bool parseSmtpResponse(const char* data, int payloadLen, RecordExtSMTP* rec);
	bool parseSmtpCommand(const char* data, int payloadLen, RecordExtSMTP* rec);
	void createSmtpRecord(Flow& rec, const Packet& pkt);
	bool updateSmtpRecord(RecordExtSMTP* ext, const Packet& pkt);

private:
	RecordExtSMTP* m_ext_ptr; /**< Pointer to allocated record extension. */
	uint32_t m_total; /**< Total number of SMTP packets seen. */
	uint32_t m_replies_cnt; /**< Total number of SMTP replies. */
	uint32_t m_commands_cnt; /**< Total number of SMTP commands. */
};

} // namespace ipxp
#endif /* IPXP_PROCESS_SMTP_HPP */
