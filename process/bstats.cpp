/**
 * \file bstats.cpp
 * \brief Plugin for parsing bstats traffic.
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
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

#include "bstats.hpp"

namespace Ipxp {

int RecordExtBSTATS::s_registeredId = -1;

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("bstats", []() { return new BSTATSPlugin(); });
	registerPlugin(&rec);
	RecordExtBSTATS::s_registeredId = registerExtension();
}

const struct timeval BSTATSPlugin::MIN_PACKET_IN_BURST
	= {MAXIMAL_INTERPKT_TIME / 1000, (MAXIMAL_INTERPKT_TIME % 1000) * 1000};

BSTATSPlugin::BSTATSPlugin() {}

BSTATSPlugin::~BSTATSPlugin()
{
	close();
}

void BSTATSPlugin::init(const char* params) {}

void BSTATSPlugin::close() {}

ProcessPlugin* BSTATSPlugin::copy()
{
	return new BSTATSPlugin(*this);
}

int BSTATSPlugin::preCreate(Packet& pkt)
{
	return 0;
}

#define BCOUNT burst_count[direction]
void BSTATSPlugin::initializeNewBurst(
	RecordExtBSTATS* bstatsRecord,
	uint8_t direction,
	const Packet& pkt)
{
	bstatsRecord->brstPkts[direction][bstatsRecord->BCOUNT] = 1;
	bstatsRecord->brstBytes[direction][bstatsRecord->BCOUNT] = pkt.payloadLenWire;
	bstatsRecord->brstStart[direction][bstatsRecord->BCOUNT] = pkt.ts;
	bstatsRecord->brstEnd[direction][bstatsRecord->BCOUNT] = pkt.ts;
}

bool BSTATSPlugin::belogsToLastRecord(
	RecordExtBSTATS* bstatsRecord,
	uint8_t direction,
	const Packet& pkt)
{
	struct timeval timediff;

	timersub(&pkt.ts, &bstatsRecord->brstEnd[direction][bstatsRecord->BCOUNT], &timediff);
	if (timercmp(&timediff, &MIN_PACKET_IN_BURST, <)) {
		return true;
	}
	return false;
}

bool BSTATSPlugin::isLastRecordBurst(RecordExtBSTATS* bstatsRecord, uint8_t direction)
{
	if (bstatsRecord->brstPkts[direction][bstatsRecord->BCOUNT] < MINIMAL_PACKETS_IN_BURST) {
		return false;
	}
	return true;
}

void BSTATSPlugin::processBursts(
	RecordExtBSTATS* bstatsRecord,
	uint8_t direction,
	const Packet& pkt)
{
	if (belogsToLastRecord(bstatsRecord, direction, pkt)) { // does it belong to previous burst?
		bstatsRecord->brstPkts[direction][bstatsRecord->BCOUNT]++;
		bstatsRecord->brstBytes[direction][bstatsRecord->BCOUNT] += pkt.payloadLenWire;
		bstatsRecord->brstEnd[direction][bstatsRecord->BCOUNT] = pkt.ts;
		return;
	}
	// the packet does not belong to previous burst
	if (isLastRecordBurst(bstatsRecord, direction)) {
		bstatsRecord->BCOUNT++;
	}
	if (bstatsRecord->BCOUNT < BSTATS_MAXELENCOUNT) {
		initializeNewBurst(bstatsRecord, direction, pkt);
	}
}

void BSTATSPlugin::updateRecord(RecordExtBSTATS* bstatsRecord, const Packet& pkt)
{
	uint8_t direction = (uint8_t) !pkt.sourcePkt;

	if (pkt.payloadLenWire == 0 || bstatsRecord->BCOUNT >= BSTATS_MAXELENCOUNT) {
		// zero-payload or burst array is full
		return;
	}
	if (bstatsRecord->burstEmpty[direction] == 0) {
		bstatsRecord->burstEmpty[direction] = 1;
		initializeNewBurst(bstatsRecord, direction, pkt);
	} else {
		processBursts(bstatsRecord, direction, pkt);
	}
}

int BSTATSPlugin::postCreate(Flow& rec, const Packet& pkt)
{
	RecordExtBSTATS* bstatsRecord = new RecordExtBSTATS();

	rec.addExtension(bstatsRecord);
	updateRecord(bstatsRecord, pkt);
	return 0;
}

int BSTATSPlugin::preUpdate(Flow& rec, Packet& pkt)
{
	RecordExtBSTATS* bstatsRecord
		= static_cast<RecordExtBSTATS*>(rec.getExtension(RecordExtBSTATS::s_registeredId));

	updateRecord(bstatsRecord, pkt);
	return 0;
}

int BSTATSPlugin::postUpdate(Flow& rec, const Packet& pkt)
{
	return 0;
}

void BSTATSPlugin::preExport(Flow& rec)
{
	RecordExtBSTATS* bstatsRecord
		= static_cast<RecordExtBSTATS*>(rec.getExtension(RecordExtBSTATS::s_registeredId));

	for (int direction = 0; direction < 2; direction++) {
		if (bstatsRecord->BCOUNT < BSTATS_MAXELENCOUNT
			&& isLastRecordBurst(bstatsRecord, direction)) {
			bstatsRecord->BCOUNT++;
		}
	}
}

} // namespace ipxp
