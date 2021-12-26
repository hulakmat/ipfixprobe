/**
 * \file record.cpp
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

#include "record.hpp"

namespace ipxp {

FCKey FCKey::from_packet(const Packet &pkt, bool inverse) {
    flow_key_t key;
    key.proto = pkt.ip_proto;
    key.ip_version = pkt.ip_version;
    key.src_port = !inverse ? pkt.src_port : pkt.dst_port;
    key.dst_port = !inverse ? pkt.dst_port : pkt.src_port;
    if (pkt.ip_version == IP::v4) {
        key.ip.v4.src_ip = !inverse ? pkt.src_ip.v4 : pkt.dst_ip.v4;
        key.ip.v4.dst_ip = !inverse ? pkt.dst_ip.v4 : pkt.src_ip.v4;
    } else if (pkt.ip_version == IP::v6) {
        memcpy(key.ip.v6.src_ip.data(), !inverse ? pkt.src_ip.v6 : pkt.dst_ip.v6, sizeof(pkt.src_ip.v6));
        memcpy(key.ip.v6.dst_ip.data(), !inverse ? pkt.dst_ip.v6 : pkt.src_ip.v6, sizeof(pkt.dst_ip.v6));
    }
    return FCKey(key);
}

FCRecord::FCRecord()
{
   erase();
};

FCRecord::~FCRecord()
{
   erase();
};

void FCRecord::erase()
{
   m_flow.remove_extensions();
   m_hash = 0;

   memset(&m_flow.time_first, 0, sizeof(m_flow.time_first));
   memset(&m_flow.time_last, 0, sizeof(m_flow.time_last));
   m_flow.ip_version = 0;
   m_flow.ip_proto = 0;
   memset(&m_flow.src_ip, 0, sizeof(m_flow.src_ip));
   memset(&m_flow.dst_ip, 0, sizeof(m_flow.dst_ip));
   m_flow.src_port = 0;
   m_flow.dst_port = 0;
   m_flow.src_packets = 0;
   m_flow.dst_packets = 0;
   m_flow.src_bytes = 0;
   m_flow.dst_bytes = 0;
   m_flow.src_tcp_flags = 0;
   m_flow.dst_tcp_flags = 0;
}
void FCRecord::reuse()
{
   m_flow.remove_extensions();
   m_flow.time_first = m_flow.time_last;
   m_flow.src_packets = 0;
   m_flow.dst_packets = 0;
   m_flow.src_bytes = 0;
   m_flow.dst_bytes = 0;
   m_flow.src_tcp_flags = 0;
   m_flow.dst_tcp_flags = 0;
}

void FCRecord::create(const Packet &pkt, uint64_t hash)
{
   m_flow.src_packets = 1;

   m_hash = hash;

   m_flow.time_first = pkt.ts;
   m_flow.time_last = pkt.ts;

   memcpy(m_flow.src_mac, pkt.src_mac, 6);
   memcpy(m_flow.dst_mac, pkt.dst_mac, 6);

   if (pkt.ip_version == IP::v4) {
      m_flow.ip_version = pkt.ip_version;
      m_flow.ip_proto = pkt.ip_proto;
      m_flow.src_ip.v4 = pkt.src_ip.v4;
      m_flow.dst_ip.v4 = pkt.dst_ip.v4;
      m_flow.src_bytes = pkt.ip_len;
   } else if (pkt.ip_version == IP::v6) {
      m_flow.ip_version = pkt.ip_version;
      m_flow.ip_proto = pkt.ip_proto;
      memcpy(m_flow.src_ip.v6, pkt.src_ip.v6, 16);
      memcpy(m_flow.dst_ip.v6, pkt.dst_ip.v6, 16);
      m_flow.src_bytes = pkt.ip_len;
   }

   if (pkt.ip_proto == IPPROTO_TCP) {
      m_flow.src_port = pkt.src_port;
      m_flow.dst_port = pkt.dst_port;
      m_flow.src_tcp_flags = pkt.tcp_flags;
   } else if (pkt.ip_proto == IPPROTO_UDP) {
      m_flow.src_port = pkt.src_port;
      m_flow.dst_port = pkt.dst_port;
   } else if (pkt.ip_proto == IPPROTO_ICMP ||
      pkt.ip_proto == IPPROTO_ICMPV6) {
      m_flow.src_port = pkt.src_port;
      m_flow.dst_port = pkt.dst_port;
   }
}

void FCRecord::update(const Packet &pkt, bool src)
{
   m_flow.time_last = pkt.ts;
   if (src) {
      m_flow.src_packets++;
      m_flow.src_bytes += pkt.ip_len;

      if (pkt.ip_proto == IPPROTO_TCP) {
         m_flow.src_tcp_flags |= pkt.tcp_flags;
      }
   } else {
      m_flow.dst_packets++;
      m_flow.dst_bytes += pkt.ip_len;

      if (pkt.ip_proto == IPPROTO_TCP) {
         m_flow.dst_tcp_flags |= pkt.tcp_flags;
      }
   }
}

}
