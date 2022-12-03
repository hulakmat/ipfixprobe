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
#ifndef IPXP_FLOW_STORE_STATS_WRITER_HPP
#define IPXP_FLOW_STORE_STATS_WRITER_HPP

#include <string>
#include <fstream>

#include "flowstoreproxy.hpp"
#include <ipfixprobe/options.hpp>
#include <thread>


namespace ipxp {

template <typename FsParser>
class FlowStoreStatsWriterParser : public FsParser {
public:
    std::string m_stats_file;

    FlowStoreStatsWriterParser(const std::string &name = std::string("Stats of ") + typeid(FsParser).name(), const std::string &desc = "") : FsParser(name, desc) {
        this->register_option("", "stats", "Stats file Path", "File where statistics will be saved",
            [this](const char *arg){
                m_stats_file = std::string(arg);
                return true;
            },
            OptionsParser::RequiredArgument);
    }
};

class FlowStoreStatsWriterStatic
{
protected:
    uint32_t m_instanceId;
    static uint32_t m_instanceIdGlobal;

    void initM_instanceId() {
        m_instanceId = m_instanceIdGlobal;
        m_instanceIdGlobal++;
    }
};

template <typename F>
class FlowStoreStatsWriter: public FlowStoreProxy<F, typename F::packet_info, typename F::accessor, typename F::iterator, FlowStoreStatsWriterParser<typename F::parser>>, private FlowStoreStatsWriterStatic
{
    typedef FlowStoreProxy<F, typename F::packet_info, typename F::accessor, typename F::iterator, FlowStoreStatsWriterParser<typename F::parser>> Base;
public:

    typedef typename F::packet_info PacketInfo;
    typedef typename F::accessor Access;
    typedef typename F::iterator Iter;
    typedef FlowStoreStatsWriterParser<typename F::parser> Parser;

    void init(Parser &parser) { m_stats_file = parser.m_stats_file; this->m_flowstore.init(parser); }
    FlowStoreStatsWriter() : Base() {
        initM_instanceId();
    }
    ~FlowStoreStatsWriter() {
        auto ptr = this->m_flowstore.stats_export();
        WriteStats(ptr);
    }

    FlowStoreStat::Ptr stats_export() {
        auto ptr = this->m_flowstore.stats_export();
        WriteStats(ptr);
        return ptr;
    };
private:
    std::string m_stats_file;

    void WriteStats(FlowStoreStat::Ptr ptr) {
        std::ofstream outFile;
        std::string outFileName(m_stats_file);
        if(outFileName.find("%t") != std::string::npos) {
            outFileName = outFileName.replace(outFileName.find("%t"), std::string("%t").size(), std::to_string(m_instanceId));
        }
        outFile.open(outFileName);
        if(outFile) {
            FlowStoreStatJSON(outFile, ptr);
        }
        outFile.close();
    }
};

}
#endif /* IPXP_FLOW_STORE_MONITOR_HPP */
