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

#include "flowstorestats.hpp"
#include "flowstoreproxy.hpp"
#include <ipfixprobe/options.hpp>


namespace ipxp {

template <typename F>
class FlowStoreMonitor : public FlowStoreProxySimple<F>
{
    struct FlowStoreMonitorStats {
        uint64_t prepared = 0;
        uint64_t lookups = 0;
        uint64_t lookups_failed = 0;
        uint64_t lookups_empty = 0;
        uint64_t lookups_empty_failed = 0;
        uint64_t free = 0;
        uint64_t free_failed = 0;
        uint64_t index_export = 0;
        uint64_t iter_export = 0;
    };
    GuardedStruct<FlowStoreMonitorStats> monitorStats;
    typedef GuardedStructGuard<FlowStoreMonitorStats> StatsGuard;
public:
    typedef typename F::packet_info PacketInfo;
    typedef typename F::accessor Access;
    typedef typename F::iterator Iter;
    typedef typename F::parser Parser;
    
    PacketInfo prepare(Packet &pkt, bool inverse = false) { StatsGuard stats(monitorStats); stats->prepared++; return this->m_flowstore.prepare(pkt, inverse); }
    Access lookup(PacketInfo &pkt) {
        StatsGuard stats(monitorStats);
        stats->lookups++;
        auto it = this->m_flowstore.lookup(pkt);
        if(it == lookup_end()) {
            stats->lookups_failed++;
        }
        return it;
    };
    Access lookup_empty(PacketInfo &pkt) {
        StatsGuard stats(monitorStats);
        stats->lookups_empty++;
        auto it = this->m_flowstore.lookup_empty(pkt);
        if(it == lookup_end()) {
            stats->lookups_empty_failed++;
        }
        return it;
    }
    Access lookup_end() { return this->m_flowstore.lookup_end(); }
    Access free(PacketInfo &pkt) {
        StatsGuard stats(monitorStats);
        stats->free++;
        auto it = this->m_flowstore.free(pkt);
        if(it == lookup_end()){
            stats->free_failed++;
        }
        return it;
    }
    Access index_export(const Access &index, FlowRingBuffer &rb) {
        StatsGuard stats(monitorStats); stats->index_export++; return this->m_flowstore.index_export(index, rb); }
    Access iter_export(const Iter &iter, FlowRingBuffer &rb) {
        StatsGuard stats(monitorStats); stats->iter_export++; return this->m_flowstore.iter_export(iter, rb); }

    FlowStoreStat::Ptr stats_export() {
        StatsGuard stats(monitorStats);
        auto ptr = this->m_flowstore.stats_export();
        FlowStoreStat::PtrVector statVec = {
            make_FSStatPrimitive("prepared" , stats->prepared),
            make_FSStatPrimitive("lookups" , stats->lookups),
            make_FSStatPrimitive("lookups_failed" , stats->lookups_failed),
            make_FSStatPrimitive("lookups_empty" , stats->lookups_empty),
            make_FSStatPrimitive("lookups_empty_failed" , stats->lookups_empty_failed),
            make_FSStatPrimitive("free" , stats->free),
            make_FSStatPrimitive("free_failed" , stats->free_failed),
            make_FSStatPrimitive("index_export" , stats->index_export),
            make_FSStatPrimitive("iter_export" , stats->iter_export)
        };
        FlowStoreStat::PtrVector monitorVec = { std::make_shared<FlowStoreStatVector>("monitor", statVec) };
        return FlowStoreStatExpand(ptr, monitorVec);
    };

    void stats_reset() {
        StatsGuard stats(monitorStats);
        *(&stats) = {};
        this->m_flowstore.stats_reset();
    }
};

}
#endif /* IPXP_FLOW_STORE_MONITOR_HPP */
