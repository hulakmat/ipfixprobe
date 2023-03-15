/**
 * \file pstats.cpp
 * \brief Plugin for parsing pstats traffic.
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Karel Hynek <hynekkar@cesnet.cz>
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

#include <algorithm>
#include <cctype>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "pstats.hpp"

namespace Ipxp {

int RecordExtPSTATS::s_registeredId = -1;

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("pstats", []() { return new PSTATSPlugin(); });
	registerPlugin(&rec);
	RecordExtPSTATS::s_registeredId = registerExtension();
}

//#define DEBUG_PSTATS

// Print debug message if debugging is allowed.
#ifdef DEBUG_PSTATS
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

PSTATSPlugin::PSTATSPlugin()
	: m_use_zeros(false)
	, m_skip_dup_pkts(false)
{
}

PSTATSPlugin::~PSTATSPlugin()
{
	close();
}

void PSTATSPlugin::init(const char* params)
{
	PSTATSOptParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	m_use_zeros = parser.mIncludeZeroes;
	m_skip_dup_pkts = parser.mSkipdup;
}

void PSTATSPlugin::close() {}

ProcessPlugin* PSTATSPlugin::copy()
{
	return new PSTATSPlugin(*this);
}

inline bool seqOverflowed(uint32_t curr, uint32_t prev)
{
	return (int64_t) curr - (int64_t) prev < -4252017623LL;
}

void PSTATSPlugin::updateRecord(RecordExtPSTATS* pstatsData, const Packet& pkt)
{
	/**
	 * 0 - client -> server
	 * 1 - server -> client
	 */
	int8_t dir = pkt.sourcePkt ? 0 : 1;
	if (m_skip_dup_pkts && pkt.ipProto == IPPROTO_TCP) {
		// Current seq <= previous ack?
		bool seqSusp = (pkt.tcpSeq <= pstatsData->tcpSeq[dir]
						 && !seqOverflowed(pkt.tcpSeq, pstatsData->tcpSeq[dir]))
			|| (pkt.tcpSeq > pstatsData->tcpSeq[dir]
				&& seqOverflowed(pkt.tcpSeq, pstatsData->tcpSeq[dir]));
		// Current ack <= previous ack?
		bool ackSusp = (pkt.tcpAck <= pstatsData->tcpAck[dir]
						 && !seqOverflowed(pkt.tcpAck, pstatsData->tcpAck[dir]))
			|| (pkt.tcpAck > pstatsData->tcpAck[dir]
				&& seqOverflowed(pkt.tcpAck, pstatsData->tcpAck[dir]));
		if (seqSusp && ackSusp && pkt.payloadLen == pstatsData->tcpLen[dir]
			&& pkt.tcpFlags == pstatsData->tcpFlg[dir] && pstatsData->pktCount != 0) {
			return;
		}
	}
	pstatsData->tcpSeq[dir] = pkt.tcpSeq;
	pstatsData->tcpAck[dir] = pkt.tcpAck;
	pstatsData->tcpLen[dir] = pkt.payloadLen;
	pstatsData->tcpFlg[dir] = pkt.tcpFlags;

	if (pkt.payloadLen == 0 && m_use_zeros == false) {
		return;
	}

	/*
	 * dir =  1 iff client -> server
	 * dir = -1 iff server -> client
	 */
	dir = pkt.sourcePkt ? 1 : -1;
	if (pstatsData->pktCount < PSTATS_MAXELEMCOUNT) {
		uint16_t pktCnt = pstatsData->pktCount;
		pstatsData->pktSizes[pktCnt] = pkt.payloadLenWire;
		pstatsData->pktTcpFlgs[pktCnt] = pkt.tcpFlags;

		pstatsData->pktTimestamps[pktCnt] = pkt.ts;

		DEBUG_MSG(
			"PSTATS processed packet %d: Size: %d Timestamp: %ld.%ld\n",
			pkt_cnt,
			pstats_data->pkt_sizes[pkt_cnt],
			pstats_data->pkt_timestamps[pkt_cnt].tv_sec,
			pstats_data->pkt_timestamps[pkt_cnt].tv_usec);

		pstatsData->pktDirs[pktCnt] = dir;
		pstatsData->pktCount++;
	} else {
		/* Do not count more than PSTATS_MAXELEMCOUNT packets */
	}
}

int PSTATSPlugin::postCreate(Flow& rec, const Packet& pkt)
{
	RecordExtPSTATS* pstatsData = new RecordExtPSTATS();
	rec.addExtension(pstatsData);

	updateRecord(pstatsData, pkt);
	return 0;
}

void PSTATSPlugin::preExport(Flow& rec)
{
	// do not export pstats for single packets flows, usually port scans
	uint32_t packets = rec.srcPackets + rec.dstPackets;
	uint8_t flags = rec.srcTcpFlags | rec.dstTcpFlags;
	if (packets <= PSTATS_MINLEN && (flags & 0x02)) { // tcp SYN set
		rec.removeExtension(RecordExtPSTATS::s_registeredId);
	}
}

int PSTATSPlugin::postUpdate(Flow& rec, const Packet& pkt)
{
	RecordExtPSTATS* pstatsData
		= (RecordExtPSTATS*) rec.getExtension(RecordExtPSTATS::s_registeredId);
	updateRecord(pstatsData, pkt);
	return 0;
}

} // namespace ipxp
