/**
 * \file basicplus.hpp
 * \brief Plugin for parsing basicplus traffic.
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
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

#ifndef IPXP_PROCESS_BASICPLUS_HPP
#define IPXP_PROCESS_BASICPLUS_HPP

#include <sstream>
#include <string>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/byte-utils.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/process.hpp>

namespace Ipxp {

#define BASICPLUS_UNIREC_TEMPLATE                                                                  \
	"IP_TTL,IP_TTL_REV,IP_FLG,IP_FLG_REV,TCP_WIN,TCP_WIN_REV,TCP_OPT,TCP_OPT_REV,TCP_MSS,TCP_MSS_" \
	"REV,TCP_SYN_SIZE"

UR_FIELDS(
	uint8 IP_TTL,
	uint8 IP_TTL_REV,
	uint8 IP_FLG,
	uint8 IP_FLG_REV,
	uint16 TCP_WIN,
	uint16 TCP_WIN_REV,
	uint64 TCP_OPT,
	uint64 TCP_OPT_REV,
	uint32 TCP_MSS,
	uint32 TCP_MSS_REV,
	uint16 TCP_SYN_SIZE)

/**
 * \brief Flow record extension header for storing parsed BASICPLUS packets.
 */
struct RecordExtBASICPLUS : public RecordExt {
	static int s_registeredId;

	uint8_t ipTtl[2];
	uint8_t ipFlg[2];
	uint16_t tcpWin[2];
	uint64_t tcpOpt[2];
	uint32_t tcpMss[2];
	uint16_t tcpSynSize;

	bool dstFilled;

	RecordExtBASICPLUS()
		: RecordExt(s_registeredId)
	{
		ipTtl[0] = 0;
		ipTtl[1] = 0;
		ipFlg[0] = 0;
		ipFlg[1] = 0;
		tcpWin[0] = 0;
		tcpWin[1] = 0;
		tcpOpt[0] = 0;
		tcpOpt[1] = 0;
		tcpMss[0] = 0;
		tcpMss[1] = 0;
		tcpSynSize = 0;

		dstFilled = false;
	}

#ifdef WITH_NEMEA
	virtual void fillUnirec(ur_template_t* tmplt, void* record)
	{
		ur_set(tmplt, record, F_IP_TTL, ipTtl[0]);
		ur_set(tmplt, record, F_IP_TTL_REV, ipTtl[1]);
		ur_set(tmplt, record, F_IP_FLG, ipFlg[0]);
		ur_set(tmplt, record, F_IP_FLG_REV, ipFlg[1]);
		ur_set(tmplt, record, F_TCP_WIN, tcpWin[0]);
		ur_set(tmplt, record, F_TCP_WIN_REV, tcpWin[1]);
		ur_set(tmplt, record, F_TCP_OPT, tcpOpt[0]);
		ur_set(tmplt, record, F_TCP_OPT_REV, tcpOpt[1]);
		ur_set(tmplt, record, F_TCP_MSS, tcpMss[0]);
		ur_set(tmplt, record, F_TCP_MSS_REV, tcpMss[1]);
		ur_set(tmplt, record, F_TCP_SYN_SIZE, tcpSynSize);
	}

	const char* getUnirecTmplt() const
	{
		return BASICPLUS_UNIREC_TEMPLATE;
	}
#endif // ifdef WITH_NEMEA

	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		if (size < 34) {
			return -1;
		}

		buffer[0] = ipTtl[0];
		buffer[1] = ipTtl[1];
		buffer[2] = ipFlg[0];
		buffer[3] = ipFlg[1];
		*(uint16_t*) (buffer + 4) = ntohs(tcpWin[0]);
		*(uint16_t*) (buffer + 6) = ntohs(tcpWin[1]);
		*(uint64_t*) (buffer + 8) = swapUint64(tcpOpt[0]);
		*(uint64_t*) (buffer + 16) = swapUint64(tcpOpt[1]);
		*(uint32_t*) (buffer + 24) = ntohl(tcpMss[0]);
		*(uint32_t*) (buffer + 28) = ntohl(tcpMss[1]);
		*(uint16_t*) (buffer + 32) = ntohs(tcpSynSize);

		return 34;
	}

	const char** getIpfixTmplt() const
	{
		static const char* ipfixTmplt[] = {IPFIX_BASICPLUS_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};
		return ipfixTmplt;
	}

	std::string getText() const
	{
		std::ostringstream out;
		out << "sttl=" << (uint16_t) ipTtl[0] << ",dttl=" << (uint16_t) ipTtl[1]
			<< ",sflg=" << (uint16_t) ipFlg[0] << ",dflg=" << (uint16_t) ipFlg[1]
			<< ",stcpw=" << tcpWin[0] << ",dtcpw=" << tcpWin[1] << ",stcpo=" << tcpOpt[0]
			<< ",dtcpo=" << tcpOpt[1] << ",stcpm=" << tcpMss[0] << ",dtcpm=" << tcpMss[1]
			<< ",tcpsynsize=" << tcpSynSize;
		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing BASICPLUS packets.
 */
class BASICPLUSPlugin : public ProcessPlugin {
public:
	BASICPLUSPlugin();
	~BASICPLUSPlugin();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const
	{
		return new OptionsParser(
			"basicplus",
			"Extend basic fields with TTL, TCP window, options, MSS and SYN size");
	}
	std::string getName() const { return "basicplus"; }
	RecordExt* getExt() const { return new RecordExtBASICPLUS(); }
	ProcessPlugin* copy();

	int postCreate(Flow& rec, const Packet& pkt);
	int preUpdate(Flow& rec, Packet& pkt);
};

} // namespace ipxp
#endif /* IPXP_PROCESS_BASICPLUS_HPP */
