/**
 * \file flexprobe.cpp
 * \brief DPDK input interface for ipfixprobe with flexprobe.
 * \author Roman Vrana <ivrana@fit.vutbr.cz>
 * \date 2023
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

#include "flexprobe.h"
#include "parser.hpp"

#include <process/flexprobe-data.h>

#define MEMPOOL_CACHE_SIZE 256

namespace ipxp {
__attribute__((constructor)) static void register_this_plugin()
{
    static PluginRecord rec = PluginRecord("flexprobe", []() { return new FlexprobeReader(); });
    register_plugin(&rec);
}

bool FlexprobeReader::convert_from_flexprobe(const rte_mbuf* mbuf, Packet& pkt)
{
    static constexpr unsigned DATA_OFFSET = 14; // size of preceeding header
    auto data_view = reinterpret_cast<const Flexprobe::FlexprobeData*>(rte_pktmbuf_mtod(mbuf, const uint8_t*) + DATA_OFFSET);
    pkt.ts = { data_view->arrival_time.sec, data_view->arrival_time.nsec / 1000 };
    std::memset(pkt.dst_mac, 0, sizeof(pkt.dst_mac));
    std::memset(pkt.src_mac, 0, sizeof(pkt.src_mac));
    pkt.ethertype = 0;

    size_t vlan_cnt = (data_view->vlan_0 ? 1 : 0) + (data_view->vlan_1 ? 1 : 0);
    size_t ip_offset = 14 + vlan_cnt * 4;

    pkt.ip_len = data_view->packet_size - ip_offset;
    pkt.ip_version = data_view->ip_version; // Get ip version
    pkt.ip_ttl = 0;
    pkt.ip_proto = data_view->l4_protocol;
    pkt.ip_tos = 0;
    pkt.ip_flags = 0;
    if (pkt.ip_version == IP::v4) {
        // IPv4 is in last 4 bytes
        pkt.src_ip.v4 = *reinterpret_cast<const uint32_t*>(data_view->src_ip.data() + 12);
        pkt.dst_ip.v4 = *reinterpret_cast<const uint32_t*>(data_view->dst_ip.data() + 12);
        pkt.ip_payload_len = pkt.ip_len - 20; // default size of IPv4 header without any options
    } else {
        std::copy(data_view->src_ip.begin(), data_view->src_ip.end(), pkt.src_ip.v6);
        std::copy(data_view->dst_ip.begin(), data_view->dst_ip.end(), pkt.dst_ip.v6);
        pkt.ip_payload_len = pkt.ip_len - 40; // size of IPv6 header without extension headers
    }
    pkt.src_port = ntohs(data_view->src_port);
    pkt.dst_port = ntohs(data_view->dst_port);
    pkt.tcp_flags = data_view->l4_flags;
    pkt.tcp_window = 0;
    pkt.tcp_options = 0;
    pkt.tcp_mss = 0;
    pkt.tcp_seq = data_view->tcp_sequence_no;
    pkt.tcp_ack = data_view->tcp_acknowledge_no;

    std::uint16_t datalen = rte_pktmbuf_pkt_len(mbuf) - DATA_OFFSET;
    pkt.packet = (uint8_t*)rte_pktmbuf_mtod(mbuf, const char*) + DATA_OFFSET;

    pkt.packet_len = 0;
    pkt.packet_len_wire = datalen;

    pkt.custom = (uint8_t*)pkt.packet;
    pkt.custom_len = datalen;

    pkt.payload = pkt.packet + data_view->size();
    pkt.payload_len = datalen < data_view->size() ? 0 : datalen - data_view->size();
    pkt.payload_len_wire = rte_pktmbuf_pkt_len(mbuf) - data_view->size();

    return true;
}

InputPlugin::Result FlexprobeReader::get(PacketBlock& packets)
{
    while (m_dpdkCore.is_ifc_ready == false) {
        usleep(1000);
    }
    packets.cnt = 0;
    for (auto i = 0; i < pkts_read_; i++) {
        rte_pktmbuf_free(mbufs_[i]);
    }
    pkts_read_ = rte_eth_rx_burst(m_portId, m_rxQueueId, mbufs_.data(), mbufs_.size());
    if (pkts_read_ == 0) {
        return Result::TIMEOUT;
    }
    for (auto i = 0; i < pkts_read_; i++) {
        // Convert Flexprobe pre-parsed packet into IPFIXPROBE packet
        auto conv_result = convert_from_flexprobe(mbufs_[i], packets.pkts[packets.cnt]);
        packets.bytes += packets.pkts[packets.cnt].packet_len_wire;
        m_seen++;

        if (!conv_result) {
            continue;
        }
        m_parsed++;
        packets.cnt++;
    }
    return Result::PARSED;
}
} // namespace