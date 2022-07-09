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
#ifndef IPXP_FLOW_STORE_PORT_FILTER_HPP
#define IPXP_FLOW_STORE_PORT_FILTER_HPP

#include <string>
#include <fstream>
#include <sstream>
#include <set>

#include "flowcache.hpp"
#include "flowstoreproxy.hpp"
#include <ipfixprobe/options.hpp>


namespace ipxp {

template <typename FsParser>
class FlowStorePortFilterParser : public FsParser {
public:
    std::set<uint16_t> m_filter_port_set;

    FlowStorePortFilterParser(const std::string &name = std::string("Filter Ports of ") + typeid(FsParser).name(), const std::string &desc = "") : FsParser(name, desc) {
        this->register_option("", "filter_ports", "Ports to accept", "Packet ports which will be accepted byt this cache. Ports separated by white space",
            [this](const char *arg){
                std::stringstream ss(arg);
                uint16_t port;
                while(ss) {
                    ss >> port;
                    m_filter_port_set.insert(port);
                }
                return true;
            },
            OptionsParser::OptionalArgument);
    }
};

template <typename F>
class FlowStorePortFilter: public FlowStoreProxy<F, typename F::packet_info, typename F::accessor, typename F::iterator, FlowStorePortFilterParser<typename F::parser>>
{
public:
    typedef typename F::packet_info PacketInfo;
    typedef typename F::accessor Access;
    typedef typename F::iterator Iter;
    typedef FlowStorePortFilterParser<typename F::parser> Parser;

//    static_assert(std::is_base_of<PacketInfo, FCPacketInfo>::value, "PacketInfo is not derived class of FCPacketInfo. Filter cannot proceed");

    void init(Parser &parser) { m_filter_port_set = parser.m_filter_port_set; this->m_flowstore.init(parser); }

    Access lookup(PacketInfo &pkt) {
        if(isPacketFiltered(pkt)) {
            return this->m_flowstore.lookup(pkt);
        }
        return this->m_flowstore.lookup_end();
    };
    Access lookup_empty(PacketInfo &pkt) {
        if(isPacketFiltered(pkt)) {
            return this->m_flowstore.lookup_empty(pkt);
        }
        return this->m_flowstore.lookup_end();
    }
    Access free(PacketInfo &pkt) {
        if(isPacketFiltered(pkt)) {
            return this->m_flowstore.free(pkt);
        }
        return this->m_flowstore.lookup_end();
    }
private:
    bool isPacketFiltered(PacketInfo &pkt) {
        if(m_filter_port_set.find(pkt.getPacket()->src_port) != m_filter_port_set.end())
            return true;
        if(m_filter_port_set.find(pkt.getPacket()->dst_port) != m_filter_port_set.end())
            return true;
        return false;
    }

    std::set<uint16_t> m_filter_port_set;
};

}
#endif /* IPXP_FLOW_STORE_PORT_FILTER_HPP */
