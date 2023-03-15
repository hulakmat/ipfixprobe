/**
 * \file benchmark.cpp
 * \brief Plugin for generating packets
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

#include <chrono>
#include <cstdint>
#include <random>
#include <sys/time.h>

#include "benchmark.hpp"
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/plugin.hpp>
#include <ipfixprobe/utils.hpp>

namespace Ipxp {

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("benchmark", []() { return new Benchmark(); });
	registerPlugin(&rec);
}

Benchmark::Benchmark()
	: m_generatePacketFunc(nullptr)
	, m_flowMode(BenchmarkMode::FLOW_1)
	, m_maxDuration(BENCHMARK_DEFAULT_DURATION)
	, m_maxPktCnt(BENCHMARK_DEFAULT_PKT_CNT)
	, m_packetSizeFrom(BENCHMARK_DEFAULT_SIZE_FROM)
	, m_packetSizeTo(BENCHMARK_DEFAULT_SIZE_TO)
	, m_firstTs({0})
	, m_currentTs({0})
	, m_pktCnt(0)
{
}

Benchmark::~Benchmark()
{
	close();
}

void Benchmark::init(const char* params)
{
	BenchmarkOptParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	if (parser.mMode == "1f") {
		generatePacket(&m_pkt);
		m_flowMode = BenchmarkMode::FLOW_1;
		m_generatePacketFunc = &Benchmark::generatePacketFlow1;
	} else if (parser.mMode == "nf") {
		m_flowMode = BenchmarkMode::FLOW_N;
		m_generatePacketFunc = &Benchmark::generatePacketFlowN;
	} else {
		throw PluginError("invalid benchmark mode specified");
	}

	m_maxDuration = parser.mDuration;
	m_maxPktCnt = parser.mPktCnt;
	m_packetSizeFrom = parser.mPktSize;
	m_packetSizeTo = parser.mPktSize;
	if (m_packetSizeFrom < 64) {
		throw PluginError("minimal packet size is 64 bytes");
	}

	if (parser.mSeed.empty()) {
		std::random_device rd;
		m_rndGen = std::mt19937(rd());
	} else {
		std::seed_seq seed(parser.mSeed.begin(), parser.mSeed.end());
		m_rndGen = std::mt19937(seed);
	}
	gettimeofday(&m_firstTs, nullptr);
}

void Benchmark::close() {}

InputPlugin::Result Benchmark::get(PacketBlock& packets)
{
	gettimeofday(&m_currentTs, nullptr);
	InputPlugin::Result res = checkConstraints();
	if (res != InputPlugin::Result::PARSED) {
		return res;
	}

	packets.cnt = 0;
	packets.bytes = 0;
	for (size_t i = 0; i < packets.size; i++) {
		(this->*m_generatePacketFunc)(&(packets.pkts[i]));
		packets.cnt++;
		packets.bytes += packets.pkts[i].packetLenWire;
		m_pktCnt++;
		if (m_maxPktCnt && m_pktCnt >= m_maxPktCnt) {
			break;
		}
	}
	mSeen += packets.cnt;
	mParsed += packets.cnt;
	return res;
}

InputPlugin::Result Benchmark::checkConstraints() const
{
	int tmp = m_currentTs.tv_usec - m_firstTs.tv_usec;
	uint64_t duration = m_currentTs.tv_sec - m_firstTs.tv_sec + (tmp < 0 ? -1 : 0);

	if ((m_maxPktCnt != BENCHMARK_PKT_CNT_INF && m_pktCnt >= m_maxPktCnt)
		|| (m_maxDuration != BENCHMARK_DURATION_INF && duration >= m_maxDuration)) {
		return InputPlugin::Result::END_OF_FILE;
	}
	return InputPlugin::Result::PARSED;
}

void Benchmark::swapEndpoints(Packet* pkt)
{
	std::swap(pkt->srcMac, pkt->dstMac);
	std::swap(pkt->srcIp, pkt->dstIp);
	std::swap(pkt->srcPort, pkt->dstPort);
}

void Benchmark::generatePacket(Packet* pkt)
{
	std::uniform_int_distribution<uint32_t> distrib;

	pkt->ts = m_currentTs;
	pkt->packetLen
		= std::uniform_int_distribution<uint16_t>(m_packetSizeFrom, m_packetSizeTo)(m_rndGen);
	pkt->packetLenWire = pkt->packetLen;
	if (distrib(m_rndGen) & 1) {
		pkt->ethertype = 0x0800;
		pkt->ipVersion = IP::V4;
		pkt->srcIp.v4 = distrib(m_rndGen);
		pkt->dstIp.v4 = distrib(m_rndGen);
	} else {
		pkt->ethertype = 0x86DD;
		pkt->ipVersion = IP::V6;
		for (int i = 0; i < 4; i++) {
			reinterpret_cast<uint32_t*>(pkt->srcIp.v6)[i] = distrib(m_rndGen);
			reinterpret_cast<uint32_t*>(pkt->dstIp.v6)[i] = distrib(m_rndGen);
		}
	}

	pkt->srcPort = distrib(m_rndGen);
	pkt->dstPort = distrib(m_rndGen);
	if (distrib(m_rndGen) & 1) {
		pkt->ipProto = IPPROTO_TCP;
		pkt->tcpFlags = 0x18; // PSH ACK
		pkt->ipPayloadLen = BENCHMARK_L4_SIZE_TCP;
	} else {
		pkt->ipProto = IPPROTO_UDP;
		pkt->tcpFlags = 0;
		pkt->ipPayloadLen = BENCHMARK_L4_SIZE_UDP;
	}
	int tmp = pkt->ipPayloadLen + BENCHMARK_L2_SIZE + BENCHMARK_L3_SIZE;

	pkt->payloadLen
		= std::uniform_int_distribution<uint16_t>(m_packetSizeFrom - tmp, m_packetSizeTo - tmp)(
			m_rndGen);
	pkt->ipPayloadLen += pkt->payloadLen;
	pkt->ipLen = pkt->ipPayloadLen + BENCHMARK_L3_SIZE;
	pkt->packetLen = pkt->ipLen + BENCHMARK_L2_SIZE;

	pkt->packet = pkt->buffer;
	pkt->payload = pkt->packet + (pkt->packetLen - pkt->payloadLen);

	static_assert(
		BENCHMARK_L2_SIZE + BENCHMARK_L3_SIZE + max(BENCHMARK_L4_SIZE_TCP, BENCHMARK_L4_SIZE_UDP)
			<= BENCHMARK_MIN_PACKET_SIZE,
		"minimal packet size is too low");
}

void Benchmark::generatePacketFlow1(Packet* pkt)
{
	int tmp = m_pkt.packetLen - m_pkt.payloadLen; // Non payload size
	int newPayloadLength
		= std::uniform_int_distribution<uint16_t>(m_packetSizeFrom - tmp, m_packetSizeTo - tmp)(
			m_rndGen);
	int diff = newPayloadLength - m_pkt.payloadLen;

	m_pkt.payloadLen += diff;
	m_pkt.payloadLenWire += diff;
	m_pkt.ipPayloadLen += diff;
	m_pkt.ipLen += diff;
	m_pkt.packetLen += diff;
	m_pkt.packetLenWire += diff;

	m_pkt.ts = m_currentTs;
	swapEndpoints(&m_pkt);

	m_pkt.buffer = pkt->buffer;
	m_pkt.packet = m_pkt.buffer;
	m_pkt.payload = m_pkt.packet + (pkt->packetLen - pkt->payloadLen);
	*pkt = m_pkt;
}

void Benchmark::generatePacketFlowN(Packet* pkt)
{
	generatePacket(pkt);
}

} // namespace ipxp
