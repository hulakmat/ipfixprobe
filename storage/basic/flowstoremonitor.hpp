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

#include "flowstore.hpp"

namespace ipxp {


template <typename F>
class FlowStoreMonitor :  public FlowStore<typename F::packet_info, typename F::accessor, typename F::iterator>
{
    typedef typename F::packet_info PacketInfo;
    typedef typename F::accessor Access;
    typedef typename F::iterator Iter;
public:
    OptionsParser *get_parser() const { return m_flowstore.get_parser(); }
    void init(const char *params) { m_flowstore.init(params); }
    Iter begin() { return m_flowstore.begin(); }
    Iter end() { return m_flowstore.end(); }
    PacketInfo prepare(Packet &pkt, bool inverse = false) {return m_flowstore.prepare(pkt, inverse); }
    Access lookup(const PacketInfo &pkt) { return m_flowstore.lookup(pkt); };
    Access lookup_empty(const PacketInfo &pkt) { return m_flowstore.lookup_empty(pkt); }
    Access lookup_end() { return m_flowstore.lookup_end(); }
    Access free(const PacketInfo &pkt) { return m_flowstore.free(pkt); }
    Access put(const Access &index) { return m_flowstore.put(index); }
    Access index_export(const Access &index, FlowRingBuffer &rb) { return m_flowstore.index_export(index, rb); }
    Access iter_export(const Iter &iter, FlowRingBuffer &rb) { return m_flowstore.iter_export(iter, rb); }

private:
    F m_flowstore;
};

}
#endif /* IPXP_FLOW_STORE_MONITOR_HPP */
