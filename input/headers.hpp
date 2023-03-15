/**
 * \file headers.hpp
 * \brief Packet parser headers.
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
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

#ifndef IPXP_INPUT_HEADERS_HPP
#define IPXP_INPUT_HEADERS_HPP

#include <endian.h>
#include <netinet/in.h>

#define ETH_P_8021AD 0x88A8
#define ETH_P_8021AH 0x88E7
#define ETH_P_8021Q 0x8100
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_MPLS_UC 0x8847
#define ETH_P_MPLS_MC 0x8848
#define ETH_P_PPP_SES 0x8864

#define ETH_ALEN 6
#define ARPHRD_ETHER 1

namespace Ipxp {

// Copied protocol headers from netinet/* files, which may not be present on other platforms

struct Ethhdr {
	unsigned char hDest[ETH_ALEN]; /* destination eth addr */
	unsigned char hSource[ETH_ALEN]; /* source ether addr */
	uint16_t hProto; /* packet type ID field */
} __attribute__((packed));

struct Iphdr {
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ihl : 4;
	unsigned int version : 4;
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
	unsigned int version : 4;
	unsigned int ihl : 4;
#else
#error "Please fix <endian.h>"
#endif
	uint8_t tos;
	uint16_t totLen;
	uint16_t id;
	uint16_t fragOff;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
	/*The options start here. */
};

struct Ip6Hdr {
	union {
		struct Ip6Hdrctl {
			uint32_t ip6Un1Flow; /* 4 bits version, 8 bits TC,
									  20 bits flow-ID */
			uint16_t ip6Un1Plen; /* payload length */
			uint8_t ip6Un1Nxt; /* next header */
			uint8_t ip6Un1Hlim; /* hop limit */
		} ip6Un1;
		uint8_t ip6Un2Vfc; /* 4 bits version, top 4 bits tclass */
	} ip6Ctlun;
	struct in6_addr ip6Src; /* source address */
	struct in6_addr ip6Dst; /* destination address */
};

struct Ip6Ext {
	uint8_t ip6eNxt; /* next header.  */
	uint8_t ip6eLen; /* length in units of 8 octets.  */
};

struct Ip6Rthdr {
	uint8_t ip6rNxt; /* next header */
	uint8_t ip6rLen; /* length in units of 8 octets */
	uint8_t ip6rType; /* routing type */
	uint8_t ip6rSegleft; /* segments left */
	/* followed by routing type specific data */
};

struct Tcphdr {
	__extension__ union {
		struct {
			uint16_t thSport; /* source port */
			uint16_t thDport; /* destination port */
			uint32_t thSeq; /* sequence number */
			uint32_t thAck; /* acknowledgement number */
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t thX2 : 4; /* (unused) */
			uint8_t thOff : 4; /* data offset */
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
			uint8_t th_off : 4; /* data offset */
			uint8_t th_x2 : 4; /* (unused) */
#else
#error "Please fix <endian.h>"
#endif
			uint8_t thFlags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
			uint16_t thWin; /* window */
			uint16_t thSum; /* checksum */
			uint16_t thUrp; /* urgent pointer */
		};
		struct {
			uint16_t source;
			uint16_t dest;
			uint32_t seq;
			uint32_t ackSeq;
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
			uint16_t res1 : 4;
			uint16_t doff : 4;
			uint16_t fin : 1;
			uint16_t syn : 1;
			uint16_t rst : 1;
			uint16_t psh : 1;
			uint16_t ack : 1;
			uint16_t urg : 1;
			uint16_t res2 : 2;
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
			uint16_t doff : 4;
			uint16_t res1 : 4;
			uint16_t res2 : 2;
			uint16_t urg : 1;
			uint16_t ack : 1;
			uint16_t psh : 1;
			uint16_t rst : 1;
			uint16_t syn : 1;
			uint16_t fin : 1;
#else
#error "Please fix <endian.h>"
#endif
			uint16_t window;
			uint16_t check;
			uint16_t urgPtr;
		};
	};
};

struct Udphdr {
	__extension__ union {
		struct {
			uint16_t uhSport; /* source port */
			uint16_t uhDport; /* destination port */
			uint16_t uhUlen; /* udp length */
			uint16_t uhSum; /* udp checksum */
		};
		struct {
			uint16_t source;
			uint16_t dest;
			uint16_t len;
			uint16_t check;
		};
	};
};

struct Icmphdr {
	uint8_t type; /* message type */
	uint8_t code; /* type sub-code */
	uint16_t checksum;
	union {
		struct {
			uint16_t id;
			uint16_t sequence;
		} echo; /* echo datagram */
		uint32_t gateway; /* gateway address */
		struct {
			uint16_t glibcReserved;
			uint16_t mtu;
		} frag; /* path mtu discovery */
	} un;
};

struct Icmp6Hdr {
	uint8_t icmp6Type; /* type field */
	uint8_t icmp6Code; /* code field */
	uint16_t icmp6Cksum; /* checksum field */
	union {
		uint32_t icmp6UnData32[1]; /* type-specific field */
		uint16_t icmp6UnData16[2]; /* type-specific field */
		uint8_t icmp6UnData8[4]; /* type-specific field */
	} icmp6Dataun;
};

struct __attribute__((packed)) TrillHdr {
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t opLen1 : 3;
	uint8_t m : 1;
	uint8_t res : 2;
	uint8_t version : 2;
	uint8_t hopCnt : 6;
	uint8_t opLen2 : 2;
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
	uint8_t version : 2;
	uint8_t res : 2;
	uint8_t m : 1;
	uint8_t op_len1 : 3;
	uint8_t op_len2 : 2;
	uint8_t hop_cnt : 6;
#else
#error "Please fix <endian.h>"
#endif
	uint16_t egressNick;
	uint16_t ingressNick;
};

struct __attribute__((packed)) PppoeHdr {
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t type : 4;
	uint8_t version : 4;
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
	uint8_t version : 4;
	uint8_t type : 4;
#else
#error "Please fix <endian.h>"
#endif
	uint8_t code;
	uint16_t sid;
	uint16_t length;
};

} // namespace ipxp
#endif /* IPXP_INPUT_HEADERS_HPP */
