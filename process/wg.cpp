/**
 * \file wg.cpp
 * \brief Plugin for parsing wg traffic.
 * \author Pavel Valach <valacpav@fit.cvut.cz>
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

#include <cstring>
#include <iostream>

#include "wg.hpp"

namespace Ipxp {

int RecordExtWG::s_registeredId = -1;

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("wg", []() { return new WGPlugin(); });
	registerPlugin(&rec);
	RecordExtWG::s_registeredId = registerExtension();
}

WGPlugin::WGPlugin()
	: m_preallocated_record(nullptr)
	, m_flow_flush(false)
	, m_total(0)
	, m_identified(0)
{
}

WGPlugin::~WGPlugin()
{
	close();
}

void WGPlugin::init(const char* params) {}

void WGPlugin::close()
{
	if (m_preallocated_record != nullptr) {
		delete m_preallocated_record;
		m_preallocated_record = nullptr;
	}
}

ProcessPlugin* WGPlugin::copy()
{
	return new WGPlugin(*this);
}

int WGPlugin::postCreate(Flow& rec, const Packet& pkt)
{
	if (pkt.ipProto == IPPROTO_UDP) {
		addExtWg(
			reinterpret_cast<const char*>(pkt.payload),
			pkt.payloadLen,
			pkt.sourcePkt,
			rec);
	}

	return 0;
}

int WGPlugin::preUpdate(Flow& rec, Packet& pkt)
{
	RecordExtWG* vpnData = (RecordExtWG*) rec.getExtension(RecordExtWG::s_registeredId);
	if (vpnData != nullptr && vpnData->possibleWg) {
		bool res = parseWg(
			reinterpret_cast<const char*>(pkt.payload),
			pkt.payloadLen,
			pkt.sourcePkt,
			vpnData);
		// In case of new flow, flush
		if (m_flow_flush) {
			m_flow_flush = false;
			return FLOW_FLUSH_WITH_REINSERT;
		}
		// In other cases, when WG was not detected
		if (!res) {
			vpnData->possibleWg = 0;
		}
	}

	return 0;
}

void WGPlugin::preExport(Flow& rec) {}

void WGPlugin::finish(bool printStats)
{
	if (printStats) {
		std::cout << "WG plugin stats:" << std::endl;
		std::cout << "   Identified WG packets: " << m_identified << std::endl;
		std::cout << "   Total packets processed: " << m_total << std::endl;
	}
}

bool WGPlugin::parseWg(
	const char* data,
	unsigned int payloadLen,
	bool sourcePkt,
	RecordExtWG* ext)
{
	uint32_t cmpPeer;
	uint32_t cmpNewPeer;

	static const char dnsQueryMask[4] = {0x00, 0x01, 0x00, 0x00};

	m_total++;

	// The smallest message (according to specs) is the data message (0x04) with 16 header bytes
	// and 16 bytes of (empty) data authentication.
	// Anything below that is not a valid WireGuard message.
	if (payloadLen < WG_PACKETLEN_MIN_TRANSPORT_DATA) {
		return false;
	}

	// Let's try to parse according to the first 4 bytes, and see if that is enough.
	// The first byte is 0x01-0x04, the following three bytes are reserved (0x00).
	uint8_t pktType = data[0];
	if (pktType < WG_PACKETTYPE_INIT_TO_RESP || pktType > WG_PACKETTYPE_TRANSPORT_DATA) {
		return false;
	}
	if (data[1] != 0x0 || data[2] != 0x0 || data[3] != 0x0) {
		return false;
	}

	// Next, check the packet contents based on the message type.
	switch (pktType) {
	case WG_PACKETTYPE_INIT_TO_RESP:
		if (payloadLen != WG_PACKETLEN_INIT_TO_RESP) {
			return false;
		}

		// compare the current dst_peer and see if it matches the original source.
		// If not, the flow flush may be needed to create a new flow.
		cmpPeer = sourcePkt ? ext->srcPeer : ext->dstPeer;
		memcpy(&cmpNewPeer, (data + 4), sizeof(uint32_t));

		if (cmpPeer != 0 && cmpPeer != cmpNewPeer) {
			m_flow_flush = true;
			return false;
		}

		memcpy(sourcePkt ? &(ext->srcPeer) : &(ext->dstPeer), (data + 4), sizeof(uint32_t));
		break;

	case WG_PACKETTYPE_RESP_TO_INIT:
		if (payloadLen != WG_PACKETLEN_RESP_TO_INIT) {
			return false;
		}

		memcpy(&(ext->srcPeer), (data + 4), sizeof(uint32_t));
		memcpy(&(ext->dstPeer), (data + 8), sizeof(uint32_t));

		// let's swap for the opposite direction
		if (!sourcePkt) {
			std::swap(ext->srcPeer, ext->dstPeer);
		}
		break;

	case WG_PACKETTYPE_COOKIE_REPLY:
		if (payloadLen != WG_PACKETLEN_COOKIE_REPLY) {
			return false;
		}

		memcpy(sourcePkt ? &(ext->dstPeer) : &(ext->srcPeer), (data + 4), sizeof(uint32_t));
		break;

	case WG_PACKETTYPE_TRANSPORT_DATA:
		// Each packet of transport data is zero-padded to the multiple of 16 bytes in length.
		if (payloadLen < WG_PACKETLEN_MIN_TRANSPORT_DATA || (payloadLen % 16) != 0) {
			return false;
		}

		memcpy(sourcePkt ? &(ext->dstPeer) : &(ext->srcPeer), (data + 4), sizeof(uint32_t));
		break;
	}

	// Possible misdetection
	// - DNS request
	//   Can happen when transaction ID is >= 1 and <= 4, the query is non-recursive
	//   and other flags are zeros, too.
	//   2B transaction ID, 2B flags, 2B questions count, 2B answers count
	if (!memcmp((data + 4), dnsQueryMask, sizeof(dnsQueryMask))) {
		ext->possibleWg = 1;
	} else {
		ext->possibleWg = 100;
	}
	m_identified++;
	return true;
}

int WGPlugin::addExtWg(const char* data, unsigned int payloadLen, bool sourcePkt, Flow& rec)
{
	if (m_preallocated_record == nullptr) {
		m_preallocated_record = new RecordExtWG();
	}
	// try to parse WireGuard packet
	if (!parseWg(data, payloadLen, sourcePkt, m_preallocated_record)) {
		return 0;
	}

	rec.addExtension(m_preallocated_record);
	m_preallocated_record = nullptr;
	return 0;
}

} // namespace ipxp
