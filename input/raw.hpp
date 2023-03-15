/**
 * \file raw.hpp
 * \brief Packet reader using raw sockets
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

#ifndef IPXP_INPUT_RAW_HPP
#define IPXP_INPUT_RAW_HPP

#include <config.h>

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/utils.hpp>

namespace Ipxp {

class RawOptParser : public OptionsParser {
public:
	std::string mIfc;
	uint16_t mFanout;
	uint32_t mBlockCnt;
	uint32_t mPktCnt;
	bool mList;

	RawOptParser()
		: OptionsParser("raw", "Input plugin for reading packets from a raw socket")
		, mIfc("")
		, mFanout(0)
		, mBlockCnt(2048)
		, mPktCnt(32)
		, mList(false)
	{
		registerOption(
			"i",
			"ifc",
			"IFC",
			"Network interface name",
			[this](const char* arg) {
				mIfc = arg;
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"f",
			"fanout",
			"ID",
			"Enable packet fanout",
			[this](const char* arg) {
				if (arg) {
					try {
						mFanout = str2num<decltype(mFanout)>(arg);
						if (!mFanout) {
							return false;
						}
					} catch (std::invalid_argument& e) {
						return false;
					}
				} else {
					mFanout = getpid() & 0xFFFF;
				}
				return true;
			},
			OptionFlags::OPTIONAL_ARGUMENT);
		registerOption(
			"b",
			"blocks",
			"SIZE",
			"Number of packet blocks (should be power of two num)",
			[this](const char* arg) {
				try {
					mBlockCnt = str2num<decltype(mBlockCnt)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"p",
			"pkts",
			"SIZE",
			"Number of packets in block (should be power of two num)",
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
			"l",
			"list",
			"",
			"Print list of available interfaces",
			[this](const char* arg) {
				mList = true;
				return true;
			},
			OptionFlags::NO_ARGUMENT);
	}
};

class RawReader : public InputPlugin {
public:
	RawReader();
	~RawReader();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const { return new RawOptParser(); }
	std::string getName() const { return "raw"; }
	InputPlugin::Result get(PacketBlock& packets);

private:
	int m_sock;
	uint16_t m_fanout;
	struct iovec* m_rd;
	struct pollfd m_pfd;

	uint8_t* m_buffer;
	uint32_t m_buffer_size;

	uint32_t m_block_idx;
	uint32_t m_blocksize;
	uint32_t m_framesize;
	uint32_t m_blocknum;

	struct tpacket3_hdr* m_last_ppd;
	struct tpacket_block_desc* m_pbd;
	uint32_t m_pkts_left;

	void openIfc(const std::string& ifc);
	bool getBlock();
	void returnBlock();
	int readPackets(PacketBlock& packets);
	int processPackets(struct tpacket_block_desc* pbd, PacketBlock& packets);
	void printAvailableIfcs();
};

void packetHandler(u_char* arg, const struct pcap_pkthdr* h, const u_char* data);

} // namespace ipxp
#endif /* IPXP_INPUT_RAW_HPP */
