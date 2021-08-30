/**
 * \file packet.hpp
 * \brief Structs/classes for communication between packet reader and flow cache
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

#ifndef IPXP_PACKET_HPP
#define IPXP_PACKET_HPP

#include <stdint.h>
#include <stdlib.h>

#include <ipfixprobe/ipaddr.hpp>
#include <ipfixprobe/flowifc.hpp>

namespace ipxp {

#define MAXPCKTSIZE 1600

#define PCKT_PAYLOAD 1
#define PCKT_TCP 2
#define PCKT_UDP 4
#define PCKT_ICMP 8

/**
 * \brief Structure for storing parsed packets up to transport layer.
 */
struct Packet : public Record {
   struct timeval timestamp;
   uint16_t   field_indicator;

   uint8_t     dst_mac[6];
   uint8_t     src_mac[6];
   uint16_t    ethertype;

   uint16_t    ip_length; /**< Length of IP header + its payload */
   uint16_t    ip_payload_length; /**< Length of IP payload */
   uint8_t     ip_version;
   uint8_t     ip_ttl;
   uint8_t     ip_proto;
   uint8_t     ip_tos;
   uint8_t     ip_flags;
   ipaddr_t    src_ip;
   ipaddr_t    dst_ip;

   uint16_t    src_port;
   uint16_t    dst_port;
   uint8_t     tcp_control_bits;
   uint16_t    tcp_window;
   uint64_t    tcp_options;
   uint32_t    tcp_mss;
   uint32_t    tcp_seq;
   uint32_t    tcp_ack;

   uint16_t    total_length; /**< Length of bytes in `packet` variable. */
   char        *packet; /**< Array containing whole packet. */
   uint16_t    payload_length; /**< Captured payload length. payload_length <= payload_length_orig */
   uint16_t    payload_length_orig; /**< Original payload length computed from headers. */
   char        *payload; /**< Pointer to packet payload section. */
   bool        source_pkt;
   uint16_t    wirelen; /**< Packet size on wire */

   /**
    * \brief Constructor.
    */
   Packet() : total_length(0), packet(nullptr), payload_length(0), payload(NULL)
   {
   }
};

struct PacketBlock {
   Packet *pkts;
   size_t cnt;
   size_t bytes;
   size_t size;
};

}
#endif /* IPXP_PACKET_HPP */