/**
 * \file cache.cpp
 * \brief "NewHashTable" flow cache
 * \author Martin Zadnik <zadnik@cesnet.cz>
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2014
 * \date 2015
 * \date 2016
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

#include <cstdlib>
#include <cstring>
#include <sys/time.h>

#include "ipfixprobe.hpp"
#include "pluginmgr.hpp"
#include "hashtablestore.hpp"
#include "flowstoremonitor.hpp"
#include "flowcacheoutput.hpp"
#include "xxhash.h"

namespace ipxp {

__attribute__((constructor)) static void register_this_plugin()
{
//    static PluginRecord rec = PluginRecord("cache_output", []() {
//       return new FlowCacheOutput<
//                      FlowStoreMonitor<
//                         HTFlowStore
//                      >
//                   >();
//    });
//    register_plugin(&rec);
}

template <class F>
FlowCacheOutput<F>::FlowCacheOutput() :
    m_output_plugin(nullptr)
{
}
#include <iostream>

template <class F>
FlowCacheOutput<F>::~FlowCacheOutput()
{
    delete m_output_plugin;
}

template <class F>
void FlowCacheOutput<F>::init(const char *params) {
    CacheLogOptParser parser;
    try {
        parser.parse(params);
    } catch (ParserError &e) {
        throw PluginError(e.what());
    }
    PluginManager pluginMgr;
    OutputPlugin::Plugins process_plugins;
    std::string output_name = "text";
    std::string output_params = "";

    if (parser.m_output.size()) {
        OptionsParser::process_plugin_argline(parser.m_output[0], output_name, output_params, ',');
    }
    std::replace( output_params.begin(), output_params.end(), ',', ';');

    m_output_plugin = nullptr;
    try {
        m_output_plugin = dynamic_cast<OutputPlugin *>(pluginMgr.get(output_name));
        if (m_output_plugin == nullptr) {
            throw IPXPError("invalid output plugin " + output_name);
        }
        m_output_plugin->init(output_params.c_str(), process_plugins);
    } catch (PluginError &e) {
        delete m_output_plugin;
        throw IPXPError(output_name + std::string(": ") + e.what());
    } catch (PluginExit &e) {
        delete m_output_plugin;
        throw IPXPError(output_name + std::string(": ") + e.what());
    } catch (PluginManagerError &e) {
        throw IPXPError(output_name + std::string(": ") + e.what());
    }

    std::string params_str(params);
    // Search for the substring in string
    size_t pos = params_str.find(parser.m_output[0]);
    if (pos != std::string::npos)
    {
        // If found then erase it from string
        params_str.erase(pos, parser.m_output[0].length());
    }
    Base::init(static_cast<typename Base::parser&>(parser));
}

template <class F>
void FlowCacheOutput<F>::flow_updated(FInfo &pkt_info, FAccess &flowAcc)
{
    m_output_plugin->export_flow((*flowAcc)->m_flow);
}
}