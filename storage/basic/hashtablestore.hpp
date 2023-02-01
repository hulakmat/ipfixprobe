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

#include <array>

namespace ipxp {
#define FLOW_CACHE_STATS


#ifdef IPXP_FLOW_CACHE_SIZE
static const uint32_t DEFAULT_FLOW_CACHE_SIZE = IPXP_FLOW_CACHE_SIZE;
#else
static const uint32_t DEFAULT_FLOW_CACHE_SIZE = 17; // 131072 records total
#endif /* IPXP_FLOW_CACHE_SIZE */

#ifdef IPXP_FLOW_LINE_SIZE
static const uint32_t DEFAULT_FLOW_LINE_SIZE = IPXP_FLOW_LINE_SIZE;
#else
static const uint32_t DEFAULT_FLOW_LINE_SIZE = 4; // 16 records per line
#endif /* IPXP_FLOW_LINE_SIZE */

static_assert(std::is_unsigned<decltype(DEFAULT_FLOW_CACHE_SIZE)>(), "Static checks of default cache sizes won't properly work without unsigned type.");
static_assert(bitcount<decltype(DEFAULT_FLOW_CACHE_SIZE)>(-1) > DEFAULT_FLOW_CACHE_SIZE, "Flow cache size is too big to fit in variable!");
static_assert(bitcount<decltype(DEFAULT_FLOW_LINE_SIZE)>(-1) > DEFAULT_FLOW_LINE_SIZE, "Flow cache line size is too big to fit in variable!");

static_assert(DEFAULT_FLOW_LINE_SIZE >= 1, "Flow cache line size must be at least 1!");
static_assert(DEFAULT_FLOW_CACHE_SIZE >= DEFAULT_FLOW_LINE_SIZE, "Flow cache size must be at least cache line size!");

class HashTableStoreParser : public OptionsParser
{
public:
   uint32_t m_cache_size;
   uint32_t m_line_size;
   uint32_t m_active;
   uint32_t m_inactive;

   HashTableStoreParser(const std::string &name = "hash", const std::string &desc = "Desc") : OptionsParser(name, desc),
      m_cache_size(1 << DEFAULT_FLOW_CACHE_SIZE), m_line_size(1 << DEFAULT_FLOW_LINE_SIZE)
   {
      register_option("s", "size", "EXPONENT", "Cache size exponent to the power of two",
         [this](const char *arg){try {unsigned exp = str2num<decltype(exp)>(arg);
               if (exp < 2 || exp > 30) {
                  throw PluginError("Flow cache size must be between 2 and 30");
               }
               m_cache_size = static_cast<uint32_t>(1) << exp;
            } catch(std::invalid_argument &e) {return false;} return true;},
         OptionFlags::RequiredArgument);
      register_option("l", "line", "EXPONENT", "Cache line size exponent to the power of two",
         [this](const char *arg){try {m_line_size = static_cast<uint32_t>(1) << str2num<decltype(m_line_size)>(arg);
               if (m_line_size < 1) {
                  throw PluginError("Flow cache line size must be at least 1");
               }
            } catch(std::invalid_argument &e) {return false;} return true;},
         OptionFlags::RequiredArgument);
   }
};

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
    HTFlowsStorePacketInfo(Packet &pkt, bool inverse, flow_key_t key) : FCPacketInfo(pkt, inverse), m_key(key), m_type(static_cast<KeyType>(key.ip_version))
        { this->calcHash(); }
    static HTFlowsStorePacketInfo from_packet(Packet &pkt, bool inverse = false);
    bool isValid() const { return this->m_type != KeyType::None; };
    friend class HTFlowStore;
};

class HTFlowStore : public FlowStore<HTFlowsStorePacketInfo, FCRPtrVector::iterator, FCRPtrVector::iterator, HashTableStoreParser>
{
public:
    typedef HTFlowsStorePacketInfo packet_info;
    typedef FCRPtrVector::iterator iterator;
    typedef FCRPtrVector::iterator access;
    typedef HashTableStoreParser parser;

    /* Parser options API */
    OptionsParser *get_parser() const;
    void init(HashTableStoreParser& parser);

    /* Iteration API */
    iterator begin() { return m_flow_table.begin(); }
    iterator end() { return m_flow_table.end(); } 
    packet_info prepare(Packet &pkt, bool inverse);

    accessor lookup(packet_info &pkt);
    accessor lookup_empty(packet_info &pkt);
    accessor lookup_end() { return end(); }
    accessor free(packet_info &pkt);

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
#ifdef DBG
        std::cout << "A Ind: " << (uint32_t)(access - begin()) << " Line Ind: " << ((uint32_t)(access - begin()) & this->m_line_mask) << " Fl Index: " << (uint32_t)(access - begin()) << " LineMask: " << std::hex << this->m_line_mask << std::endl;
#endif
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

    void moveToFront(const FlowIndex &flowIndex)
    {
#ifdef FLOW_CACHE_STATS
        const size_t lookup_len = (flowIndex.flow_index - flowIndex.line_index + 1);
        stats.m_lookups += lookup_len;
        stats.m_lookups2 += lookup_len * lookup_len;
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
#ifdef FLOW_CACHE_STATS
                const size_t search_len = (rIndex.flow_index - rIndex.line_index + 1);
                stats.m_searches += search_len;
                stats.m_searches2 += search_len * search_len;
#endif
                rIndex.valid = true;
                return rIndex;
            }
        }

#ifdef FLOW_CACHE_STATS
        const size_t search_len = this->m_line_size;
        stats.m_searches += search_len;
        stats.m_searches2 += search_len * search_len;
#endif
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
#ifdef FLOW_CACHE_STATS
                const size_t search_len = (rIndex.flow_index - rIndex.line_index + 1);
                stats.m_searches += search_len;
                stats.m_searches2 += search_len * search_len;
#endif
                rIndex.valid = true;
                return rIndex;
            }
        }

#ifdef FLOW_CACHE_STATS
        const size_t search_len = this->m_line_size;
        stats.m_searches += search_len;
        stats.m_searches2 += search_len * search_len;
#endif
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
    struct {
        uint64_t m_searches = 0;
        uint64_t m_searches2;

        uint64_t m_lookups = 0;
        uint64_t m_lookups2 = 0;
        uint32_t m_cacheline_max_index = 0;
    } stats = {};

public:
    void stats_reset() {
        memset(&stats, 0, sizeof(stats));
    }
#endif /* FLOW_CACHE_STATS */

public:
    FlowStoreStat::Ptr stats_export() {
        FlowStoreStat::PtrVector statVec = {
            make_FSStatPrimitive("lookups" , stats.m_lookups),
            make_FSStatPrimitive("lookups2" , stats.m_lookups2),
            make_FSStatPrimitive("searches" , stats.m_searches),
            make_FSStatPrimitive("searches2" , stats.m_searches2),
            make_FSStatPrimitive("cacheline_max_index" , stats.m_cacheline_max_index),
        };
        return std::make_shared<FlowStoreStatVector>("", statVec);
    };
};
}
#endif /* IPXP_HASH_TABLE_STORE_HPP */
