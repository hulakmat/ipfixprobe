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
#ifndef IPXP_FLOW_STORE_HPP
#define IPXP_FLOW_STORE_HPP

#include <string>

#include <ipfixprobe/storage.hpp>
#include <ipfixprobe/options.hpp>
#include "record.hpp"
#include <memory>
#include <sstream>
#include <functional>
#include "flowstorestats.hpp"

namespace ipxp {

class FlowRingBuffer;
template <typename PacketInfo, typename Access, typename Iter, typename Parser>
class FlowStore
{
public:
    /* Extract information from packet for other operations */
    typedef PacketInfo packet_info;
    /* Iterator over accessors */
    typedef Iter iterator;
    /* Accessor gives access to a FCRecord* record by dereferencing */
    typedef Access accessor;
    /* Argument parser */
    typedef Parser parser;

    /* Virtual destructor for overriding */
    virtual ~FlowStore() {};

    /* Parser options API */
    void init(parser &parser) {};

    /* Iteration API */
    virtual Iter begin() = 0;
    virtual Iter end() = 0;

    /* Prepare packet for processing. Calculates shared items for lookup/free operations */

    /* Note that the packet info can have invalidated Paket pointer for other operations.
     * This is due some late operation as flow moving such as CachedFlowStore implementation.
     * Operations such as lookup and etc. should not use the pkt pointer or should count for this move operation by checking its validity
     */
    virtual PacketInfo prepare(Packet &pkt, bool inverse) = 0;
    /* Looksup records for given hash. */
    virtual Access lookup(PacketInfo &pkt ) = 0;
    virtual Access lookup_empty(PacketInfo &pkt) = 0;

    /* Lookup operation invalid accessor signaling NotFound */
    virtual Access lookup_end() = 0;

    /* Return iterator to item to be freed from cache for given hash */
    virtual Access free(PacketInfo &pkt) = 0;

    /* Signals to Store end of operation with record. Export does the same. */
    virtual Access put(const Access &index) = 0;

    /* Exports given index and returns field for flow with same hash */
    virtual Access index_export(const Access &index, FlowRingBuffer &rb) = 0;

    /* Exports given iterator and returns field for flow with same hash */
    virtual Access iter_export(const Iter &iter, FlowRingBuffer &rb) = 0;

    /* Interface for getting statistic/performance information from the FlowStore */
    virtual FlowStoreStat::Ptr stats_export() { return nullptr; };

    typedef std::function<Access(const Access&)> ForcedFlowExportCallback;
    void setForcedFlowExportCallback(ForcedFlowExportCallback cb) {
        this->m_forced_callback = cb;
    };
protected:
    ForcedFlowExportCallback m_forced_callback;
};

}
#endif /* IPXP_FLOW_STORE_HPP */
