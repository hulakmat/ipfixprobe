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
#ifndef IPXP_FLOW_STORE_PROXY_HPP
#define IPXP_FLOW_STORE_PROXY_HPP

#include <string>
#include <fstream>

#include "flowstore.hpp"
#include <ipfixprobe/options.hpp>


namespace ipxp {

template <typename F, typename PacketInfo, typename Access, typename Iter, typename Parser>
class FlowStoreProxy : public FlowStore<PacketInfo, Access, Iter, Parser>
{
public:
    typedef PacketInfo packet_info;
    typedef Iter iterator; /* Iterator over accessors */
    typedef Access accessor;
    typedef Parser parser;

    void init(Parser &parser) { m_flowstore.init(parser); }
    Iter begin() { return m_flowstore.begin(); }
    Iter end() { return m_flowstore.end(); }
    PacketInfo prepare(Packet &pkt, bool inverse = false) {return m_flowstore.prepare(pkt, inverse); }
    Access lookup(PacketInfo &pkt) { return m_flowstore.lookup(pkt); };
    Access lookup_empty(PacketInfo &pkt) { return m_flowstore.lookup_empty(pkt); }
    Access lookup_end() { return m_flowstore.lookup_end(); }
    Access free(PacketInfo &pkt) { return m_flowstore.free(pkt); }
    Access put(const Access &index) { return m_flowstore.put(index); }
    Access index_export(const Access &index, FlowRingBuffer &rb) { return m_flowstore.index_export(index, rb); }
    Access iter_export(const Iter &iter, FlowRingBuffer &rb) { return m_flowstore.iter_export(iter, rb); }

    virtual FlowStoreStat::Ptr stats_export() { return m_flowstore.stats_export(); };
protected:
    F m_flowstore;
};

template <typename F>
class FlowStoreProxySimple : public FlowStoreProxy<F, typename F::packet_info, typename F::access, typename F::iterator, typename F::parser>
{
public:
    typedef typename F::packet_info packet_info;
    typedef typename F::iterator iterator; /* Iterator over accessors */
    typedef typename F::accessor accessor;
    typedef typename F::parser parser;
};

}
#endif /* IPXP_FLOW_STORE_PROXY_HPP */
