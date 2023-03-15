/**
 * \file ovpn.cpp
 * \brief Plugin for parsing ovpn traffic.
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
 * \author Martin Ctrnacty <ctrnama2@fit.cvut.cz>
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

#include <cstring>
#include <iostream>

#include "ovpn.hpp"

namespace Ipxp {

int RecordExtOVPN::s_registeredId = -1;

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("ovpn", []() { return new OVPNPlugin(); });
	registerPlugin(&rec);
	RecordExtOVPN::s_registeredId = registerExtension();
}

OVPNPlugin::OVPNPlugin() {}

OVPNPlugin::~OVPNPlugin()
{
	close();
}

void OVPNPlugin::init(const char* params) {}

void OVPNPlugin::close() {}

ProcessPlugin* OVPNPlugin::copy()
{
	return new OVPNPlugin(*this);
}

void OVPNPlugin::updateRecord(RecordExtOVPN* vpnData, const Packet& pkt)
{
	uint8_t opcode = 0;
	uint8_t opcodeindex = 0;
	switch (static_cast<e_ip_proto_nbr>(pkt.ipProto)) {
	case UDP:
		if (pkt.payloadLen == 0) {
			return;
		}
		opcodeindex = C_UDP_OPCODE_INDEX;
		opcode = (pkt.payload[opcodeindex] >> 3);
		break;
	case TCP:
		if (pkt.payloadLen < C_TCP_OPCODE_INDEX) {
			return;
		}
		opcodeindex = C_TCP_OPCODE_INDEX;
		opcode = (pkt.payload[opcodeindex] >> 3);
		break;
	}

	switch (opcode) {
	// p_control_hard_reset_client
	case P_CONTROL_HARD_RESET_CLIENT_V1:
	case P_CONTROL_HARD_RESET_CLIENT_V2:
	case P_CONTROL_HARD_RESET_CLIENT_V3:
		vpnData->status = STATUS_RESET_CLIENT; // client to server
		vpnData->invalidPktCnt = -1;
		vpnData->clientIp = pkt.srcIp;
		break;

		// p_control_hard_reset_server
	case P_CONTROL_HARD_RESET_SERVER_V1:
	case P_CONTROL_HARD_RESET_SERVER_V2:
		if (vpnData->status == STATUS_RESET_CLIENT
			&& compareIp(vpnData->clientIp, pkt.dstIp, pkt.ipVersion)) { // server to client
			vpnData->status = STATUS_RESET_SERVER;
			vpnData->invalidPktCnt = -1;
		} else {
			vpnData->invalidPktCnt++;
			if (vpnData->invalidPktCnt == INVALID_PCKT_TRESHOLD) {
				vpnData->status = STATUS_NULL;
			}
		}
		break;

		// p_control_soft_reset
	case P_CONTROL_SOFT_RESET_V1:
		break;

		// p_control
	case P_CONTROL_V1:
		if (vpnData->status == STATUS_ACK
			&& compareIp(vpnData->clientIp, pkt.srcIp, pkt.ipVersion)
			&& checkSslClientHello(pkt, opcodeindex)) { // client to server
			vpnData->status = STATUS_CLIENT_HELLO;
			vpnData->invalidPktCnt = -1;
		} else if (
			vpnData->status == STATUS_CLIENT_HELLO
			&& compareIp(vpnData->clientIp, pkt.dstIp, pkt.ipVersion)
			&& checkSslServerHello(pkt, opcodeindex)) { // server to client
			vpnData->status = STATUS_SERVER_HELLO;
			vpnData->invalidPktCnt = -1;
		} else if (
			vpnData->status == STATUS_SERVER_HELLO || vpnData->status == STATUS_CONTROL_ACK) {
			vpnData->status = STATUS_CONTROL_ACK;
			vpnData->invalidPktCnt = -1;
		} else {
			vpnData->invalidPktCnt++;
			if (vpnData->invalidPktCnt == INVALID_PCKT_TRESHOLD) {
				vpnData->status = STATUS_NULL;
			}
		}
		break;

		// p_ack
	case P_ACK_V1:
		if (vpnData->status == STATUS_RESET_SERVER
			&& compareIp(vpnData->clientIp, pkt.srcIp, pkt.ipVersion)) { // client to server
			vpnData->status = STATUS_ACK;
			vpnData->invalidPktCnt = -1;
		} else if (
			vpnData->status == STATUS_SERVER_HELLO || vpnData->status == STATUS_CONTROL_ACK) {
			vpnData->status = STATUS_CONTROL_ACK;
			vpnData->invalidPktCnt = -1;
		}
		break;

		// p_data
	case P_DATA_V1:
	case P_DATA_V2:
		if (vpnData->status == STATUS_CONTROL_ACK || vpnData->status == STATUS_DATA) {
			vpnData->status = STATUS_DATA;
			vpnData->invalidPktCnt = -1;
		}
		vpnData->dataPktCnt++;
		break;

		// no opcode
	default:
		break;
	}

	vpnData->pktCnt++;

	// packets that did not make a valid transition
	if (vpnData->invalidPktCnt >= INVALID_PCKT_TRESHOLD) {
		vpnData->status = STATUS_NULL;
		vpnData->invalidPktCnt = -1;
	}
	vpnData->invalidPktCnt++;
	return;
}

int OVPNPlugin::postCreate(Flow& rec, const Packet& pkt)
{
	RecordExtOVPN* vpnData = new RecordExtOVPN();
	rec.addExtension(vpnData);

	updateRecord(vpnData, pkt);
	return 0;
}

int OVPNPlugin::preUpdate(Flow& rec, Packet& pkt)
{
	RecordExtOVPN* vpnData = (RecordExtOVPN*) rec.getExtension(RecordExtOVPN::s_registeredId);
	updateRecord(vpnData, pkt);
	return 0;
}

void OVPNPlugin::preExport(Flow& rec)
{
	RecordExtOVPN* vpnData = (RecordExtOVPN*) rec.getExtension(RecordExtOVPN::s_registeredId);
	if (vpnData->pktCnt > MIN_PCKT_TRESHOLD && vpnData->status == STATUS_DATA) {
		vpnData->possibleVpn = 100;
	} else if (
		vpnData->pktCnt > MIN_PCKT_TRESHOLD
		&& ((double) vpnData->dataPktCnt / (double) vpnData->pktCnt) >= DATA_PCKT_TRESHOLD) {
		vpnData->possibleVpn
			= (uint8_t) ((vpnData->dataPktCnt / (double) vpnData->pktCnt) * 80);
	}
	return;
}

bool OVPNPlugin::compareIp(ipaddr_t ip1, ipaddr_t ip2, uint8_t ipVersion)
{
	if (ipVersion == IP::V4 && !memcmp(&ip1, &ip2, 4)) {
		return 1;
	} else if (ipVersion == IP::V6 && !memcmp(&ip1, &ip2, 16)) {
		return 1;
	}
	return 0;
}

bool OVPNPlugin::checkSslClientHello(const Packet& pkt, uint8_t opcodeindex)
{
	if (pkt.payloadLen > opcodeindex + 19 && pkt.payload[opcodeindex + 14] == 0x16
		&& pkt.payload[opcodeindex + 19] == 0x01) {
		return 1;
	} else if (
		pkt.payloadLen > opcodeindex + 47 && pkt.payload[opcodeindex + 42] == 0x16
		&& pkt.payload[opcodeindex + 47] == 0x01) {
		return 1;
	}
	return 0;
}

bool OVPNPlugin::checkSslServerHello(const Packet& pkt, uint8_t opcodeindex)
{
	if (pkt.payloadLen > opcodeindex + 31 && pkt.payload[opcodeindex + 26] == 0x16
		&& pkt.payload[opcodeindex + 31] == 0x02) {
		return 1;
	} else if (
		pkt.payloadLen > opcodeindex + 59 && pkt.payload[opcodeindex + 54] == 0x16
		&& pkt.payload[opcodeindex + 59] == 0x02) {
		return 1;
	}
	return 0;
}

} // namespace ipxp
