/**
 * \file pcap.hpp
 * \brief Pcap reader based on libpcap
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

#ifndef IPXP_INPUT_PCAP_HPP
#define IPXP_INPUT_PCAP_HPP

#include <pcap/pcap.h>

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/utils.hpp>

namespace Ipxp {

/*
 * \brief Minimum snapshot length of pcap handle.
 */
#define MIN_SNAPLEN 120

/*
 * \brief Maximum snapshot length of pcap handle.
 */
#define MAX_SNAPLEN 65535

// Read timeout in miliseconds for pcap_open_live function.
#define READ_TIMEOUT 1000

class PcapOptParser : public OptionsParser {
public:
	std::string mFile;
	std::string mIfc;
	std::string mFilter;
	uint16_t mSnaplen;
	uint64_t mId;
	bool mList;

	PcapOptParser()
		: OptionsParser(
			"pcap",
			"Input plugin for reading packets from a pcap file or a network interface")
		, mFile("")
		, mIfc("")
		, mFilter("")
		, mSnaplen(-1)
		, mId(0)
		, mList(false)
	{
		registerOption(
			"f",
			"file",
			"PATH",
			"Path to a pcap file",
			[this](const char* arg) {
				mFile = arg;
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
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
			"F",
			"filter",
			"STR",
			"Filter string",
			[this](const char* arg) {
				mFilter = arg;
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"s",
			"snaplen",
			"SIZE",
			"Snapshot length in bytes (live capture only)",
			[this](const char* arg) {
				try {
					mSnaplen = str2num<decltype(mSnaplen)>(arg);
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

/**
 * \brief Class for reading packets from file or network interface.
 */
class PcapReader : public InputPlugin {
public:
	PcapReader();
	~PcapReader();

	void init(const char* params);
	void close();
	OptionsParser* getParser() const { return new PcapOptParser(); }
	std::string getName() const { return "pcap"; }
	InputPlugin::Result get(PacketBlock& packets);

private:
	pcap_t* m_handle; /**< libpcap file handle */
	uint16_t m_snaplen;
	int m_datalink;
	bool m_live; /**< Capturing from network interface */
	bpf_u_int32 m_netmask; /**< Network mask. Used when setting filter */

	void openFile(const std::string& file);
	void openIfc(const std::string& ifc);
	void setFilter(const std::string& filterStr);

	void checkDatalink(int datalink);
	void printAvailableIfcs();
};

void packetHandler(u_char* arg, const struct pcap_pkthdr* h, const u_char* data);

} // namespace ipxp
#endif /* IPXP_INPUT_PCAP_HPP */
