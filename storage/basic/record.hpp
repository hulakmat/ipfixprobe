/**
 * \file record.hpp
 * \brief "NewHashTable" flow cache record
 * \author Martin Zadnik <zadnik@cesnet.cz>
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \author Tomas Benes <benes@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2014-2021 CESNET
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
#ifndef IPXP_BASIC_CACHE_RECORD_HPP
#define IPXP_BASIC_CACHE_RECORD_HPP

#include <string>

#include <ipfixprobe/storage.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/utils.hpp>
#include "xxhash.h"

namespace ipxp {

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

typedef uint64_t FCHash;

enum FCKeyType {
   None = 0,
   V4 = 4,
   V6 = 6,
};

class FCKey {
    flow_key_t m_key;
    FCKeyType m_type;
    FCHash m_hash;

    void calcHash() { this->m_hash = XXH64(reinterpret_cast<uint8_t*>(&this->m_key), this->getLength(), 0);};
public:
    FCKey() : m_type(FCKeyType::None) {}
    FCKey(flow_key_t key) : m_key(key), m_type(static_cast<FCKeyType>(key.ip_version)) 
        { this->calcHash(); }
    static FCKey from_packet(const Packet &pkt, bool inverse = false);

    bool isValid() const { return this->m_type != FCKeyType::None; };
    size_t getLength() const { return this->m_type == FCKeyType::V4 ? flow_key_v4_len : flow_key_v6_len; }
    FCHash getHash() const { return m_hash; }

    inline __attribute__((always_inline)) bool operator==(const FCHash& other) const
    {
        return this->m_hash == other;
    }

    inline __attribute__((always_inline)) bool operator==(const FCKey& other) const
    {
        return this->m_hash == other.m_hash;
    }
};

class FCRecord
{
   FCHash m_hash;
public:
    Flow m_flow;

    FCRecord();
    ~FCRecord();

    void erase();
    void reuse();

    inline __attribute__((always_inline)) bool isEmpty() const { return m_hash == 0; }

    void create(const Packet &pkt, uint64_t pkt_hash);
    void update(const Packet &pkt, bool src);

    inline __attribute__((always_inline)) FCHash getHash() const { return m_hash; }
};

}
#endif /* IPXP_BASIC_CACHE_RECORD_HPP */
