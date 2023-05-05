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

#include <cstring>
#include <mutex>
#include <rte_ethdev.h>
#include <rte_version.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_errno.h>

#include "dpdk.h"
#include "parser.hpp"

#define MEMPOOL_CACHE_SIZE 256

namespace ipxp {
__attribute__((constructor)) static void register_this_plugin()
{
    static PluginRecord rec = PluginRecord("dpdk", []() { return new DpdkReader(); });
    register_plugin(&rec);
}

DpdkCore* DpdkCore::m_instance = nullptr;

DpdkCore& DpdkCore::getInstance()
{
    if (!m_instance) {
        m_instance = new DpdkCore();
    }
    return *m_instance;
}

DpdkCore::~DpdkCore()
{
    rte_eth_dev_stop(m_portId);
    rte_eth_dev_close(m_portId);
    rte_eal_cleanup();
    m_instance = nullptr;
}

void DpdkCore::deinit()
{
    if (m_instance) {
        delete m_instance;
        m_instance = nullptr;
    }
}

void DpdkCore::initInterface()
{
    validatePort();
    auto portConfig = createPortConfig();
    configurePort(portConfig);
}

void DpdkCore::validatePort()
{
    if (!rte_eth_dev_is_valid_port(m_portId)) {
        throw PluginError("Invalid DPDK port specified");
    }
}

struct rte_eth_conf DpdkCore::createPortConfig()
{
    if (m_rxQueueCount > 1 && !m_supportedRSS) {
        std::cerr << "RSS is not supported by card, multiple queues will not work as expected." << std::endl;
        throw PluginError("Required RSS for q>1 is not supported.");
    }

#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
    rte_eth_conf portConfig {.rxmode = {.mtu = RTE_ETHER_MAX_LEN}};
#else
    rte_eth_conf portConfig {.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}};
#endif

    if (m_supportedRSS) {
        portConfig.rxmode.mq_mode = ETH_MQ_RX_RSS;
    } else {
        portConfig.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    }

    if (m_supportedHWTimestamp) {
        portConfig.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TIMESTAMP;
    }
    return portConfig;
}

void DpdkCore::configurePort(const struct rte_eth_conf& portConfig)
{
    if (rte_eth_dev_configure(m_portId, m_rxQueueCount, m_txQueueCount, &portConfig)) {
        throw PluginError("Unable to configure interface");
    }
}

void DpdkCore::configureRSS()
{
    if (!m_supportedRSS) {
        std::cerr << "SKipped RSS hash setting for port " << m_portId << "." << std::endl;
        return;
    }

    constexpr size_t RSS_KEY_LEN = 40;
    // biflow hash key
    static uint8_t rssKey[RSS_KEY_LEN] = {
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
    };

    struct rte_eth_rss_conf rssConfig = {
        .rss_key = rssKey,
        .rss_key_len = RSS_KEY_LEN,
        .rss_hf = ETH_RSS_IP,
    };

    if (rte_eth_dev_rss_hash_update(m_portId, &rssConfig)) {
        std::cerr << "Setting RSS hash for port " << m_portId << "." << std::endl;
    }
}

void DpdkCore::enablePort()
{
    if (rte_eth_dev_start(m_portId) < 0) {
        throw PluginError("Unable to start DPDK port");
    }

    if (rte_eth_promiscuous_enable(m_portId)) {
        throw PluginError("Unable to set promiscuous mode");
    }
}

void DpdkCore::registerRxTimestamp()
{
    if (rte_mbuf_dyn_rx_timestamp_register(&m_rxTimestampOffset, NULL)) {
        throw PluginError("Unable to get Rx timestamp offset");
    }
}

void DpdkCore::configure(const char* params)
{
    if (isConfigured) {
        return;
    }


    try {
        parser.parse(params);
    } catch (ParserError& e) {
        throw PluginError(e.what());
    }
   
    m_portId = parser.port_num();
    m_rxQueueCount = parser.rx_queues();
    configureEal(parser.eal_params());

    /* recognize NIC driver and check capabilities */
    recognizeDriver();
    registerRxTimestamp();
    initInterface();
    isConfigured = true;
}

void DpdkCore::recognizeDriver()
{
    rte_eth_dev_info rteDevInfo;
    if (rte_eth_dev_info_get(m_portId, &rteDevInfo)) {
        throw PluginError("Unable to get rte dev info");
    }

    if (std::strcmp(rteDevInfo.driver_name, "net_nfb") == 0) {
        m_isNfbDpdkDriver = true;
    }

    std::cerr << "Capabilities of the port " << m_portId << " with driver " << rteDevInfo.driver_name << ":" << std::endl;
    std::cerr << "\tRX offload: " << rteDevInfo.rx_offload_capa << std::endl;
    std::cerr << "\tflow type RSS offloads: " << rteDevInfo.flow_type_rss_offloads << std::endl;

    /* Check if RSS hashing is supported in NIC */
    m_supportedRSS = (rteDevInfo.flow_type_rss_offloads & RTE_ETH_RSS_IP) != 0;
    std::cerr << "\tDetected RSS offload capability: " << (m_supportedRSS ? "yes" : "no") << std::endl;

    /* Check if HW timestamps are supported, we support NFB cards only */
    if (m_isNfbDpdkDriver) {
        m_supportedHWTimestamp = (rteDevInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP) != 0;
    } else {
        m_supportedHWTimestamp = false;
    }
    std::cerr << "\tDetected HW timestamp capability: " << (m_supportedHWTimestamp ? "yes" : "no") << std::endl;
}

bool DpdkCore::isNfbDpdkDriver()
{
	return m_isNfbDpdkDriver;
}

std::vector<char *> DpdkCore::convertStringToArgvFormat(const std::string& ealParams)
{
    // set first value as program name (argv[0])
    std::vector<char *> args = {"ipfixprobe"};
    std::istringstream iss(ealParams);
    std::string token;

    while(iss >> token) {
        char *arg = new char[token.size() + 1];
        copy(token.begin(), token.end(), arg);
        arg[token.size()] = '\0';
        args.push_back(arg);
    }
    return args;
}

void DpdkCore::configureEal(const std::string& ealParams)
{
    std::vector<char *> args = convertStringToArgvFormat(ealParams);

    if (rte_eal_init(args.size(), args.data()) < 0) {
        rte_exit(EXIT_FAILURE, "Cannot initialize RTE_EAL: %s\n", rte_strerror(rte_errno));
    }
}

uint16_t DpdkCore::getRxQueueId()
{
    return m_currentRxId++;
}

void DpdkCore::startIfReady()
{
    if (m_rxQueueCount == m_currentRxId) {
        configureRSS();
        enablePort();
        is_ifc_ready = true;

        std::cerr << "DPDK input at port " << m_portId << " started." << std::endl;
    }
}

int DpdkCore::getRxTimestampOffset()
{
    return m_rxTimestampOffset;
}

DpdkReader::DpdkReader()
    : m_dpdkCore(DpdkCore::getInstance())
{
    pkts_read_ = 0;
    m_useHwRxTimestamp = false;
}

DpdkReader::~DpdkReader()
{
    m_dpdkCore.deinit();
}

void DpdkReader::init(const char* params)
{
    m_dpdkCore.configure(params);
    m_rxQueueId = m_dpdkCore.getRxQueueId();
    m_portId = m_dpdkCore.parser.port_num();
    m_rxTimestampOffset = m_dpdkCore.getRxTimestampOffset();
    m_useHwRxTimestamp = m_dpdkCore.isNfbDpdkDriver();

    createRteMempool(m_dpdkCore.parser.pkt_mempool_size());
    createRteMbufs(m_dpdkCore.parser.pkt_buffer_size());
    setupRxQueue();   

    m_dpdkCore.startIfReady();
}

void DpdkReader::createRteMempool(uint16_t mempoolSize)
{
    std::string mpool_name = "mbuf_pool_" + std::to_string(m_rxQueueId);
    rteMempool = rte_pktmbuf_pool_create(
        mpool_name.c_str(), 
        mempoolSize, 
        MEMPOOL_CACHE_SIZE, 
        0, 
        RTE_MBUF_DEFAULT_BUF_SIZE, 
        rte_lcore_to_socket_id(m_rxQueueId));
    if (!rteMempool) {
        throw PluginError("Unable to create memory pool. " + std::string(rte_strerror(rte_errno)));
    }
}

void DpdkReader::createRteMbufs(uint16_t mbufsSize)
{
    try {
        mbufs_.resize(mbufsSize);
    } catch (const std::exception& e) {
        throw PluginError(e.what());
    }
}

void DpdkReader::setupRxQueue()
{
    int ret = rte_eth_rx_queue_setup(
        m_portId, 
        m_rxQueueId, 
        mbufs_.size(), 
        rte_eth_dev_socket_id(m_portId), 
        nullptr, 
        rteMempool);
    if (ret < 0) {
        throw PluginError("Unable to set up RX queues");
    }
}

struct timeval DpdkReader::getTimestamp(rte_mbuf* mbuf)
{
	struct timeval tv;
    if (m_useHwRxTimestamp) {
        static constexpr time_t nanosecInSec = 1000000000;
        static constexpr time_t nsecInUsec = 1000;
        
        rte_mbuf_timestamp_t timestamp = *RTE_MBUF_DYNFIELD(mbuf, m_rxTimestampOffset, rte_mbuf_timestamp_t *);
        tv.tv_sec = timestamp / nanosecInSec; 
        tv.tv_usec = (timestamp - ((tv.tv_sec) * nanosecInSec)) / nsecInUsec; 

        return tv;
    } else {
        auto now = std::chrono::system_clock::now();
        auto now_t = std::chrono::system_clock::to_time_t(now);

        auto dur = now - std::chrono::system_clock::from_time_t(now_t);
        auto micros = std::chrono::duration_cast<std::chrono::microseconds>(dur).count();

	    tv.tv_sec = now_t;
		tv.tv_usec = micros;
        return tv;	
    }

} 

InputPlugin::Result DpdkReader::get(PacketBlock& packets)
{
    while (m_dpdkCore.is_ifc_ready == false) {
        usleep(1000);
    }
    parser_opt_t opt {&packets, false, false, 0};
    packets.cnt = 0;
    for (auto i = 0; i < pkts_read_; i++) {
        rte_pktmbuf_free(mbufs_[i]);
    }
    pkts_read_ = rte_eth_rx_burst(m_portId, m_rxQueueId, mbufs_.data(), mbufs_.size());
    if (pkts_read_ == 0) {
        return Result::TIMEOUT;
    }
    for (auto i = 0; i < pkts_read_; i++) {
        parse_packet(&opt,
            getTimestamp(mbufs_[i]),
            rte_pktmbuf_mtod(mbufs_[i], const std::uint8_t*),
            rte_pktmbuf_data_len(mbufs_[i]),
            rte_pktmbuf_data_len(mbufs_[i]));
        m_seen++;
        m_parsed++;
    }
    return Result::PARSED;
}
}
