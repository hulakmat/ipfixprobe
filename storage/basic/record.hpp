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

typedef uint64_t FCHash;

class FCPacketInfo {
    Packet *m_pkt;
    bool m_inverse;
protected:
    FCHash m_hash;
public:
    FCPacketInfo() : m_pkt(nullptr), m_hash(0) {}
    FCPacketInfo(Packet &pkt, bool inverse) : m_pkt(&pkt), m_inverse(inverse), m_hash(0) {}

    /* Check if packet is getPacket used in same context as the Packet which it depends on */
    bool isPacketValid() { return m_pkt != nullptr; }
    Packet *getPacket() { return m_pkt; }
    /* Should be called when structure leaves the same context as the Packet */
    void invalidatePacket() { m_pkt = nullptr; }
    /* Notates whether the FCPacket info identifies flows in single direction(true) or both(false) */
    virtual bool isInversable() const { return true; }
    virtual bool isInverse() const { return m_inverse; }
    virtual bool isValid() const = 0;
    virtual FCHash getHash() const { return m_hash; }
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

    void create(FCPacketInfo &pkt_info);
    void update(FCPacketInfo &pkt_info, bool src);

    inline __attribute__((always_inline)) FCHash getHash() const { return m_hash; }
};

typedef FCRecord* FCRecordPtr;
typedef std::vector<FCRecordPtr> FCRPtrVector;
typedef std::vector<FCRecord> FCRVector;

}
#endif /* IPXP_BASIC_CACHE_RECORD_HPP */
