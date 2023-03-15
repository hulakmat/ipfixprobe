/**
 * \file benchmark.hpp
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
#ifndef IPXP_INPUT_BENCHMARK_HPP
#define IPXP_INPUT_BENCHMARK_HPP

#include <chrono>
#include <cstdint>
#include <random>
#include <string>

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/utils.hpp>

namespace Ipxp {

#define BENCHMARK_L2_SIZE 14
#define BENCHMARK_L3_SIZE 20
#define BENCHMARK_L4_SIZE_TCP 20
#define BENCHMARK_L4_SIZE_UDP 8

#define BENCHMARK_MIN_PACKET_SIZE 64
#define BENCHMARK_PKT_CNT_INF 0
#define BENCHMARK_FLOW_CNT_INF 0
#define BENCHMARK_DURATION_INF 0

#define BENCHMARK_DEFAULT_DURATION 10 // 10s
#define BENCHMARK_DEFAULT_FLOW_CNT BENCHMARK_FLOW_CNT_INF
#define BENCHMARK_DEFAULT_PKT_CNT BENCHMARK_PKT_CNT_INF
#define BENCHMARK_DEFAULT_SIZE_FROM 512
#define BENCHMARK_DEFAULT_SIZE_TO 512

class BenchmarkOptParser : public OptionsParser {
public:
	std::string mMode;
	std::string mSeed;
	uint64_t mDuration;
	uint64_t mPktCnt;
	uint16_t mPktSize;
	uint64_t mLink;

	BenchmarkOptParser()
		: OptionsParser("benchmark", "Input plugin for various benchmarking purposes")
		, mMode("1f")
		, mSeed("")
		, mDuration(0)
		, mPktCnt(0)
		, mPktSize(BENCHMARK_DEFAULT_SIZE_FROM)
		, mLink(0)
	{
		registerOption(
			"m",
			"mode",
			"STR",
			"Benchmark mode 1f (1x N-packet flow) or nf (Nx 1-packet flow)",
			[this](const char* arg) {
				mMode = arg;
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"S",
			"seed",
			"STR",
			"String seed for random generator",
			[this](const char* arg) {
				mSeed = arg;
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"d",
			"duration",
			"TIME",
			"Duration in seconds",
			[this](const char* arg) {
				try {
					mDuration = str2num<decltype(mDuration)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"p",
			"count",
			"SIZE",
			"Packet count",
			[this](const char* arg) {
				try {
					mPktCnt = str2num<decltype(mPktCnt)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"s",
			"size",
			"SIZE",
			"Packet size",
			[this](const char* arg) {
				try {
					mPktSize = str2num<decltype(mPktSize)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"I",
			"id",
			"NUM",
			"Link identifier number",
			[this](const char* arg) {
				try {
					mLink = str2num<decltype(mLink)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
	}
};

class Benchmark : public InputPlugin {
public:
	enum class BenchmarkMode {
		FLOW_1, /* 1x N-packet flow */
		FLOW_N /* Nx 1-packet flows */
	};
	Benchmark();
	~Benchmark();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const { return new BenchmarkOptParser(); }
	std::string getName() const { return "benchmark"; }

	InputPlugin::Result get(PacketBlock& packets);

private:
	void (Benchmark::*m_generatePacketFunc)(Packet*);
	BenchmarkMode m_flowMode;
	uint64_t m_maxDuration;
	uint64_t m_maxPktCnt;
	uint16_t m_packetSizeFrom;
	uint16_t m_packetSizeTo;

	std::mt19937 m_rndGen;
	Packet m_pkt;
	struct timeval m_firstTs;
	struct timeval m_currentTs;
	uint64_t m_pktCnt;

	InputPlugin::Result checkConstraints() const;
	void swapEndpoints(Packet* pkt);
	void generatePacket(Packet* pkt);
	void generatePacketFlow1(Packet* pkt);
	void generatePacketFlowN(Packet* pkt);
};

} // namespace ipxp
#endif /* IPXP_INPUT_BENCHMARK_HPP */
