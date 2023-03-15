/**
 * \file packet.hpp
 * \brief Structs/classes for communication between packet reader and flow cache
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2014
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

#ifndef IPXP_PACKET_HPP
#define IPXP_PACKET_HPP

#include <stdint.h>
#include <stdlib.h>

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipaddr.hpp>

namespace Ipxp {

/**
 * \brief Structure for storing parsed packet fields
 */
struct Packet : public Record {
	struct timeval ts;

	uint8_t dstMac[6];
	uint8_t srcMac[6];
	uint16_t ethertype;

	uint16_t ipLen; /**< Length of IP header + its payload */
	uint16_t ipPayloadLen; /**< Length of IP payload */
	uint8_t ipVersion;
	uint8_t ipTtl;
	uint8_t ipProto;
	uint8_t ipTos;
	uint8_t ipFlags;
	ipaddr_t srcIp;
	ipaddr_t dstIp;

	uint16_t srcPort;
	uint16_t dstPort;
	uint8_t tcpFlags;
	uint16_t tcpWindow;
	uint64_t tcpOptions;
	uint32_t tcpMss;
	uint32_t tcpSeq;
	uint32_t tcpAck;

	const uint8_t* packet; /**< Pointer to begin of packet, if available */
	uint16_t packetLen; /**< Length of data in packet buffer, packet_len <= packet_len_wire */
	uint16_t packetLenWire; /**< Original packet length on wire */

	const uint8_t* payload; /**< Pointer to begin of payload, if available */
	uint16_t payloadLen; /**< Length of data in payload buffer, payload_len <= payload_len_wire */
	uint16_t payloadLenWire; /**< Original payload length computed from headers */

	uint8_t* custom; /**< Pointer to begin of custom data, if available */
	uint16_t customLen; /**< Length of data in custom buffer */

	// TODO REMOVE
	uint8_t* buffer; /**< Buffer for packet, payload and custom data */
	uint16_t bufferSize; /**< Size of buffer */

	bool sourcePkt; /**< Direction of packet from flow point of view */

	/**
	 * \brief Constructor.
	 */
	Packet()
		: ts({0})
		, dstMac()
		, srcMac()
		, ethertype(0)
		, ipLen(0)
		, ipPayloadLen(0)
		, ipVersion(0)
		, ipTtl(0)
		, ipProto(0)
		, ipTos(0)
		, ipFlags(0)
		, srcIp({0})
		, dstIp({0})
		, srcPort(0)
		, dstPort(0)
		, tcpFlags(0)
		, tcpWindow(0)
		, tcpOptions(0)
		, tcpMss(0)
		, tcpSeq(0)
		, tcpAck(0)
		, packet(nullptr)
		, packetLen(0)
		, packetLenWire(0)
		, payload(nullptr)
		, payloadLen(0)
		, payloadLenWire(0)
		, custom(nullptr)
		, customLen(0)
		, buffer(nullptr)
		, bufferSize(0)
		, sourcePkt(true)
	{
	}
};

struct PacketBlock {
	Packet* pkts;
	size_t cnt;
	size_t bytes;
	size_t size;

	PacketBlock(size_t pktsSize)
		: cnt(0)
		, bytes(0)
		, size(pktsSize)
	{
		pkts = new Packet[pktsSize];
	}

	~PacketBlock() { delete[] pkts; }
};

} // namespace ipxp
#endif /* IPXP_PACKET_HPP */
