/**
 * \file cache.hpp
 * \brief "FlowStore" Flow store abstraction
 * \author Tomas Benes <tomasbenes@cesnet.cz>
 * \date 2021
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
#ifndef IPXP_FLOW_STORE_MONITOR_HPP
#define IPXP_FLOW_STORE_MONITOR_HPP

#include <string>
#include <fstream>

#include "flowstoreproxy.hpp"
#include <ipfixprobe/options.hpp>


namespace ipxp {

template <typename F>
class FlowStoreMonitor : public FlowStoreProxySimple<F>
{
    struct {
        uint32_t prepared;
        uint32_t lookups;
        uint32_t lookups_failed;
        uint32_t lookups_empty;
        uint32_t lookups_empty_failed;
        uint32_t free;
        uint32_t free_failed;
        uint32_t index_export;
        uint32_t iter_export;
    } monitorStats = {
        0
    };
public:
    typedef typename F::packet_info PacketInfo;
    typedef typename F::accessor Access;
    typedef typename F::iterator Iter;
    typedef typename F::parser Parser;

    PacketInfo prepare(Packet &pkt, bool inverse = false) { monitorStats.prepared++; return this->m_flowstore.prepare(pkt, inverse); }
    Access lookup(PacketInfo &pkt) {
        monitorStats.lookups++;
        auto it = this->m_flowstore.lookup(pkt);
        if(it == lookup_end()) {
            monitorStats.lookups_failed++;
        }
        return it;
    };
    Access lookup_empty(PacketInfo &pkt) {
        monitorStats.lookups_empty++;
        auto it = this->m_flowstore.lookup_empty(pkt);
        if(it == lookup_end()) {
            monitorStats.lookups_empty_failed++;
        }
        return it;
    }
    Access lookup_end() { return this->m_flowstore.lookup_end(); }
    Access free(PacketInfo &pkt) {
        monitorStats.free++;
        auto it = this->m_flowstore.free(pkt);
        if(it == lookup_end()){
            monitorStats.free_failed++;
        }
        return it;
    }
    Access index_export(const Access &index, FlowRingBuffer &rb) { monitorStats.index_export++; return this->m_flowstore.index_export(index, rb); }
    Access iter_export(const Iter &iter, FlowRingBuffer &rb) { monitorStats.iter_export++; return this->m_flowstore.iter_export(iter, rb); }

    FlowStoreStat::Ptr stats_export() {
        auto ptr = this->m_flowstore.stats_export();
        FlowStoreStat::PtrVector statVec = {
            make_FSStatPrimitive("prepared" , monitorStats.prepared),
            make_FSStatPrimitive("lookups" , monitorStats.lookups),
            make_FSStatPrimitive("lookups_failed" , monitorStats.lookups_failed),
            make_FSStatPrimitive("lookups_empty" , monitorStats.lookups_empty),
            make_FSStatPrimitive("lookups_empty_failed" , monitorStats.lookups_empty_failed),
            make_FSStatPrimitive("free" , monitorStats.free),
            make_FSStatPrimitive("free_failed" , monitorStats.free_failed),
            make_FSStatPrimitive("index_export" , monitorStats.index_export),
            make_FSStatPrimitive("iter_export" , monitorStats.iter_export)
        };
        FlowStoreStat::PtrVector monitorVec = { std::make_shared<FlowStoreStatVector>("monitor", statVec) };
        return FlowStoreStatExpand(ptr, monitorVec);
    };
};

}
#endif /* IPXP_FLOW_STORE_MONITOR_HPP */
