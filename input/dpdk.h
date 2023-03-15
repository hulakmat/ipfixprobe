/**
 * \file dpdk.h
 * \brief DPDK input interface for ipfixprobe.
 * \author Roman Vrana <ivrana@fit.vutbr.cz>
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
#include <config.h>
#ifdef WITH_DPDK

#ifndef IPXP_DPDK_READER_H
#define IPXP_DPDK_READER_H

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/utils.hpp>

#include <memory>
#include <rte_mbuf.h>
#include <sstream>

namespace Ipxp {
class DpdkOptParser : public OptionsParser {
private:
	static constexpr size_t DEFAULT_MBUF_BURST_SIZE = 256;
	static constexpr size_t DEFAULT_MBUF_POOL_SIZE = 16384;
	size_t m_pkt_buffer_size;
	size_t m_pkt_mempool_size;
	std::uint16_t m_port_num;
	uint16_t m_rx_queues = 1;
	std::string m_eal;

public:
	DpdkOptParser()
		: OptionsParser("dpdk", "Input plugin for reading packets using DPDK interface")
		, m_pkt_buffer_size(DEFAULT_MBUF_BURST_SIZE)
		, m_pkt_mempool_size(DEFAULT_MBUF_POOL_SIZE)
	{
		registerOption(
			"b",
			"bsize",
			"SIZE",
			"Size of the MBUF packet buffer. Default: " + std::to_string(DEFAULT_MBUF_BURST_SIZE),
			[this](const char* arg) {
				try {
					m_pkt_buffer_size = str2num<decltype(m_pkt_buffer_size)>(arg);
				} catch (std::invalid_argument&) {
					return false;
				}
				return true;
			},
			REQUIRED_ARGUMENT);
		registerOption(
			"p",
			"port",
			"PORT",
			"DPDK port to be used as an input interface",
			[this](const char* arg) {
				try {
					m_port_num = str2num<decltype(m_port_num)>(arg);
				} catch (std::invalid_argument&) {
					return false;
				}
				return true;
			},
			REQUIRED_ARGUMENT);
		registerOption(
			"m",
			"mem",
			"SIZE",
			"Size of the memory pool for received packets. Default: "
				+ std::to_string(DEFAULT_MBUF_POOL_SIZE),
			[this](const char* arg) {
				try {
					m_pkt_mempool_size = str2num<decltype(m_pkt_mempool_size)>(arg);
				} catch (std::invalid_argument&) {
					return false;
				}
				return true;
			},
			REQUIRED_ARGUMENT);
		registerOption(
			"q",
			"queue",
			"COUNT",
			"Number of RX queues. Default: 1",
			[this](const char* arg) {
				try {
					m_rx_queues = str2num<decltype(m_rx_queues)>(arg);
				} catch (std::invalid_argument&) {
					return false;
				}
				return true;
			},
			REQUIRED_ARGUMENT);
		registerOption(
			"e",
			"eal",
			"EAL",
			"DPDK eal",
			[this](const char* arg) {
				m_eal = arg;
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
	}

	size_t pktBufferSize() const { return m_pkt_buffer_size; }

	size_t pktMempoolSize() const { return m_pkt_mempool_size; }

	std::uint16_t portNum() const { return m_port_num; }

	std::string ealParams() const { return m_eal; }

	uint16_t rxQueues() const { return m_rx_queues; }
};

class DpdkCore {
public:
	/**
	 * @brief Configure dpdk port using user parameters
	 *
	 * @param params user paramameters
	 */
	void configure(const char* params);

	/**
	 * @brief Get the DpdkReader Queue Id
	 *
	 * @return uint16_t rx queue id
	 */
	uint16_t getRxQueueId();

	int getRxTimestampOffset();

	bool isNfbDpdkDriver();

	/**
	 * @brief Start receiving on port when all lcores are ready
	 *
	 */
	void startIfReady();

	void deinit();

	// ready flag
	bool isIfcReady;

	/**
	 * @brief Get the singleton dpdk core instance
	 */
	static DpdkCore& getInstance();

	DpdkOptParser parser;

private:
	void initInterface();
	void validatePort();
	struct rte_eth_conf createPortConfig();
	void configurePort(const struct rte_eth_conf& portConfig);
	void configureRSS();
	void registerRxTimestamp();
	void enablePort();
	std::vector<char*> convertStringToArgvFormat(const std::string& ealParams);
	void recognizeDriver();
	void configureEal(const std::string& ealParams);

	~DpdkCore();

	uint16_t m_portId;
	uint16_t m_rxQueueCount;
	uint16_t m_txQueueCount;
	uint16_t m_currentRxId;
	int m_rxTimestampOffset;
	bool m_isNfbDpdkDriver;
	bool m_supportedRSS;
	bool m_supportedHWTimestamp;

	bool m_isConfigured = false;
	static DpdkCore* s_mInstance;
};

class DpdkReader : public InputPlugin {
public:
	Result get(PacketBlock& packets) override;

	void init(const char* params) override;

	OptionsParser* getParser() const override { return new DpdkOptParser(); }

	std::string getName() const override { return "dpdk"; }

	~DpdkReader();
	DpdkReader();

private:
	rte_mempool* m_rteMempool;
	std::vector<rte_mbuf*> m_mbufs;

	std::uint16_t m_pkts_read;
	uint16_t m_rx_queue_id;
	uint16_t m_total_queues_cnt;

	uint16_t m_rxQueueId;
	uint16_t m_portId;
	int m_rxTimestampOffset;

	bool m_useHwRxTimestamp;

	void createRteMempool(uint16_t mempoolSize);
	void createRteMbufs(uint16_t mbufsSize);
	void setupRxQueue();
	struct timeval getTimestamp(rte_mbuf* mbuf);

	DpdkCore& m_dpdkCore;
};
} // namespace ipxp

#endif // IPXP_DPDK_READER_H
#endif
