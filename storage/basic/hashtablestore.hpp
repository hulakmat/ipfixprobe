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
#ifndef IPXP_HASH_TABLE_STORE_HPP
#define IPXP_HASH_TABLE_STORE_HPP

#include "flowstore.hpp"
#include "record.hpp"

namespace ipxp {
#define FLOW_CACHE_STATS

typedef uint32_t flow_ip_v4_t;
typedef std::array<uint8_t, 16> flow_ip_v6_t;

struct __attribute__((packed)) flow_key_t
{
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t ip_version;
    union {
        struct {
            flow_ip_v4_t src_ip;
            flow_ip_v4_t dst_ip;
        } v4;
        struct {
            flow_ip_v6_t src_ip;
            flow_ip_v6_t dst_ip;
        } v6;
    } ip;
};

const size_t flow_key_info_len = sizeof(flow_key_t) - 2*sizeof(flow_ip_v6_t);
const size_t flow_key_v6_len = sizeof(flow_key_t);
const size_t flow_key_v4_len = flow_key_info_len + 2*sizeof(flow_ip_v4_t);


class HTFlowStore;
class HTFlowsStorePacketInfo : public FCPacketInfo {
    enum KeyType : uint8_t {
        None = 0,
        v4 = IP::v4,
        v6 = IP::v6
    };

    flow_key_t m_key;
    KeyType m_type;

    size_t getLength() const { return this->m_type == KeyType::v4 ? flow_key_v4_len : flow_key_v6_len; }
    void calcHash() { this->m_hash = XXH64(reinterpret_cast<uint8_t*>(&this->m_key), this->getLength(), 0);};
public:
    HTFlowsStorePacketInfo(HTFlowsStorePacketInfo &&info) : FCPacketInfo(std::move(info)), m_key(info.m_key), m_type(info.m_type)
        { }
    HTFlowsStorePacketInfo(Packet &pkt, flow_key_t key) : FCPacketInfo(pkt), m_key(key), m_type(static_cast<KeyType>(key.ip_version))
        { this->calcHash(); }
    static HTFlowsStorePacketInfo from_packet(Packet &pkt, bool inverse = false);
    bool isValid() const { return this->m_type != KeyType::None; };


    HTFlowsStorePacketInfo& operator=(HTFlowsStorePacketInfo&& other)
    {
        FCPacketInfo::operator=(std::move(other));
        m_key = other.m_key;
        m_type = other.m_type;
        return *this;
    }

    friend class HTFlowStore;
};

class HTFlowStore : public FlowStore<HTFlowsStorePacketInfo, FCRPtrVector::iterator, FCRPtrVector::iterator>
{
public:
    /* Parser options API */
    OptionsParser *get_parser() const;
    void init(const char *params);

    /* Iteration API */
    iterator begin() { return m_flow_table.begin(); }
    iterator end() { return m_flow_table.end(); } 
    packet_info prepare(Packet &pkt, bool inverse);

    accessor lookup(const packet_info &pkt);
    accessor lookup_empty(const packet_info &pkt);
    accessor lookup_end() { return end(); }
    accessor free(const packet_info &pkt);

    accessor put(const accessor &index);
    accessor index_export(const accessor &index, FlowRingBuffer &rb);
    accessor iter_export(const iterator &iter, FlowRingBuffer &rb);

private:
    typedef struct
    {
        bool valid;
        uint32_t line_index;
        uint32_t flow_index;
    } FlowIndex;

    int foo = 0;
    const FlowIndex fromAccessor(const accessor &access) {
        return {
            true,
            (uint32_t)(access - begin()) & this->m_line_mask,
            (uint32_t)(access - begin())
        };
    }

    const FlowIndex makeRowIndex(const FCHash hash)
    {
        return {
            true,
            ((uint32_t)hash) & this->m_line_mask,
            0};
    };

    const void moveToFront(const FlowIndex &flowIndex)
    {
#ifdef FLOW_CACHE_STATS
        const size_t lookup_len = (flowIndex.flow_index - flowIndex.line_index + 1);
        m_lookups += lookup_len;
        m_lookups2 += lookup_len * lookup_len;
#endif
        /* Moving pointers operate with FCRecord** otherwise would be operating with Values */
        std::rotate(m_flow_table.begin() + flowIndex.line_index,    //Index of the first element
                    m_flow_table.begin() + flowIndex.flow_index,    //Index of the element that should be first
                    m_flow_table.begin() + flowIndex.flow_index + 1 //Index of last element in array
        );
    }

    const FlowIndex searchEmptyLine(const FlowIndex &lIndex)
    {
        FlowIndex rIndex = lIndex;
        const uint32_t next_line = rIndex.line_index + this->m_line_size;
        /* Find existing flow record in flow cache. */
        for (rIndex.flow_index = rIndex.line_index; rIndex.flow_index < next_line; rIndex.flow_index++)
        {
            if (m_flow_table[rIndex.flow_index]->isEmpty())
            {
                rIndex.valid = true;
                return rIndex;
            }
        }
        rIndex.valid = false;
        return rIndex;
    }
    const FlowIndex searchLine(const FlowIndex lIndex, const FCHash hash)
    {
        FlowIndex rIndex = lIndex;
        const uint32_t next_line = rIndex.line_index + this->m_line_size;
        /* Find existing flow record in flow cache. */
        for (rIndex.flow_index = rIndex.line_index; rIndex.flow_index < next_line; rIndex.flow_index++)
        {
            if (m_flow_table[rIndex.flow_index]->getHash() == hash)
            {
                rIndex.valid = true;
#ifdef FLOW_CACHE_STATS
                m_hits++;
#endif
                return rIndex;
            }
        }
        rIndex.valid = false;
        return rIndex;
    }

    uint32_t m_cache_size;
    uint32_t m_line_size;
    uint32_t m_line_mask;
    uint32_t m_line_new_idx;

    FCRPtrVector m_flow_table;
    FCRVector m_flow_records;

#ifdef FLOW_CACHE_STATS
   uint64_t m_empty;
   uint64_t m_not_empty;
   uint64_t m_hits;
   uint64_t m_expired;
   uint64_t m_flushed;
   uint64_t m_lookups;
   uint64_t m_lookups2;
#endif /* FLOW_CACHE_STATS */
};

}
#endif /* IPXP_HASH_TABLE_STORE_HPP */