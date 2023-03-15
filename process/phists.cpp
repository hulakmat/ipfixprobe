/**
 * \file phists.cpp
 * \brief Plugin for parsing phists traffic.
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
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

#include <algorithm>
#include <iostream>
#include <limits>
#include <math.h>
#include <sstream>
#include <string>
#include <vector>

#include "phists.hpp"

namespace Ipxp {

int RecordExtPHISTS::s_registeredId = -1;

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("phists", []() { return new PHISTSPlugin(); });
	registerPlugin(&rec);
	RecordExtPHISTS::s_registeredId = registerExtension();
}

#define PHISTS_INCLUDE_ZEROS_OPT "includezeros"

#ifdef DEBUG_PHISTS
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

const uint32_t PHISTSPlugin::LOG2_LOOKUP32[32]
	= {0, 9,  1,  10, 13, 21, 2,  29, 11, 14, 16, 18, 22, 25, 3, 30,
	   8, 12, 20, 28, 15, 17, 24, 7,  19, 27, 23, 6,  26, 5,  4, 31};

PHISTSPlugin::PHISTSPlugin()
	: m_use_zeros(false)
{
}

PHISTSPlugin::~PHISTSPlugin()
{
	close();
}

void PHISTSPlugin::init(const char* params)
{
	PHISTSOptParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	m_use_zeros = parser.mIncludeZeroes;
}

void PHISTSPlugin::close() {}

ProcessPlugin* PHISTSPlugin::copy()
{
	return new PHISTSPlugin(*this);
}

/*
 * 0-15     1. bin
 * 16-31    2. bin
 * 32-63    3. bin
 * 64-127   4. bin
 * 128-255  5. bin
 * 256-511  6. bin
 * 512-1023 7. bin
 * 1024 >   8. bin
 */
void PHISTSPlugin::updateHist(RecordExtPHISTS* phistsData, uint32_t value, uint32_t* histogram)
{
	if (value < 16) {
		histogram[0] = noOverflowIncrement(histogram[0]);
	} else if (value > 1023) {
		histogram[HISTOGRAM_SIZE - 1] = noOverflowIncrement(histogram[HISTOGRAM_SIZE - 1]);
	} else {
		histogram[fastlog232(value) - 2 - 1] = noOverflowIncrement(
			histogram[fastlog232(value) - 2 - 1]); // -2 means shift cause first bin corresponds to
													// 2^4
	}
	return;
}

uint64_t PHISTSPlugin::calculateIpt(
	RecordExtPHISTS* phistsData,
	const struct timeval tv,
	uint8_t direction)
{
	int64_t ts = IpfixBasicList::tv2Ts(tv);

	if (phistsData->lastTs[direction] == 0) {
		phistsData->lastTs[direction] = ts;
		return -1;
	}
	int64_t diff = ts - phistsData->lastTs[direction];

	phistsData->lastTs[direction] = ts;
	return diff;
}

void PHISTSPlugin::updateRecord(RecordExtPHISTS* phistsData, const Packet& pkt)
{
	if (pkt.payloadLenWire == 0 && m_use_zeros == false) {
		return;
	}
	uint8_t direction = (uint8_t) !pkt.sourcePkt;
	updateHist(phistsData, (uint32_t) pkt.payloadLenWire, phistsData->sizeHist[direction]);
	int32_t iptDiff = (uint32_t) calculateIpt(phistsData, pkt.ts, direction);
	if (iptDiff != -1) {
		updateHist(phistsData, (uint32_t) iptDiff, phistsData->iptHist[direction]);
	}
}

void PHISTSPlugin::preExport(Flow& rec)
{
	// do not export phists for single packets flows, usually port scans
	uint32_t packets = rec.srcPackets + rec.dstPackets;
	uint8_t flags = rec.srcTcpFlags | rec.dstTcpFlags;

	if (packets <= PHISTS_MINLEN && (flags & 0x02)) { // tcp SYN set
		rec.removeExtension(RecordExtPHISTS::s_registeredId);
	}
}

int PHISTSPlugin::postCreate(Flow& rec, const Packet& pkt)
{
	RecordExtPHISTS* phistsData = new RecordExtPHISTS();

	rec.addExtension(phistsData);

	updateRecord(phistsData, pkt);
	return 0;
}

int PHISTSPlugin::postUpdate(Flow& rec, const Packet& pkt)
{
	RecordExtPHISTS* phistsData
		= (RecordExtPHISTS*) rec.getExtension(RecordExtPHISTS::s_registeredId);

	updateRecord(phistsData, pkt);
	return 0;
}

} // namespace ipxp
