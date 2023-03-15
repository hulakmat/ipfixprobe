/**
 * \file parser.cpp
 * \brief Packet parser functions
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

#include <config.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sys/types.h>

#include "headers.hpp"
#include "parser.hpp"
#include <ipfixprobe/packet.hpp>

namespace Ipxp {

//#define DEBUG_PARSER

#ifdef DEBUG_PARSER
// Print debug message if debugging is allowed.
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
// Process code if debugging is allowed.
#define DEBUG_CODE(code) code
static uint32_t s_total_pkts = 0;
#else
#define DEBUG_MSG(format, ...)
#define DEBUG_CODE(code)
#endif

/**
 * \brief Parse specific fields from ETHERNET frame header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parseEthHdr(const u_char* dataPtr, uint16_t dataLen, Packet* pkt)
{
	struct Ethhdr* eth = (struct Ethhdr*) dataPtr;
	if (sizeof(struct Ethhdr) > dataLen) {
		throw "Parser detected malformed packet";
	}
	uint16_t hdrLen = sizeof(struct Ethhdr);
	uint16_t ethertype = ntohs(eth->hProto);

	DEBUG_MSG("Ethernet header:\n");
#ifndef __CYGWIN__
	DEBUG_MSG("\tDest mac:\t%s\n", ether_ntoa((struct ether_addr*) eth->h_dest));
	DEBUG_MSG("\tSrc mac:\t%s\n", ether_ntoa((struct ether_addr*) eth->h_source));
#else
	DEBUG_CODE(char src_mac[18]; // ether_ntoa missing on some platforms
			   char dst_mac[18];
			   uint8_t* p = (uint8_t*) eth->h_source;
			   snprintf(
				   src_mac,
				   sizeof(src_mac),
				   "%02x:%02x:%02x:%02x:%02x:%02x",
				   p[0],
				   p[1],
				   p[2],
				   p[3],
				   p[4],
				   p[5]);
			   p = (uint8_t*) eth->h_dest;
			   snprintf(
				   dst_mac,
				   sizeof(dst_mac),
				   "%02x:%02x:%02x:%02x:%02x:%02x",
				   p[0],
				   p[1],
				   p[2],
				   p[3],
				   p[4],
				   p[5]););
	DEBUG_MSG("\tDest mac:\t%s\n", dst_mac);
	DEBUG_MSG("\tSrc mac:\t%s\n", src_mac);
#endif
	DEBUG_MSG("\tEthertype:\t%#06x\n", ethertype);

	memcpy(pkt->dstMac, eth->hDest, 6);
	memcpy(pkt->srcMac, eth->hSource, 6);

	if (ethertype == ETH_P_8021AD) {
		if (4 > dataLen - hdrLen) {
			throw "Parser detected malformed packet";
		}
		DEBUG_CODE(uint16_t vlan = ntohs(*(uint16_t*) (data_ptr + hdr_len)));
		DEBUG_MSG("\t802.1ad field:\n");
		DEBUG_MSG("\t\tPriority:\t%u\n", ((vlan & 0xE000) >> 12));
		DEBUG_MSG("\t\tCFI:\t\t%u\n", ((vlan & 0x1000) >> 11));
		DEBUG_MSG("\t\tVLAN:\t\t%u\n", (vlan & 0x0FFF));

		hdrLen += 4;
		ethertype = ntohs(*(uint16_t*) (dataPtr + hdrLen - 2));
		DEBUG_MSG("\t\tEthertype:\t%#06x\n", ethertype);
	}
	while (ethertype == ETH_P_8021Q) {
		if (4 > dataLen - hdrLen) {
			throw "Parser detected malformed packet";
		}
		DEBUG_CODE(uint16_t vlan = ntohs(*(uint16_t*) (data_ptr + hdr_len)));
		DEBUG_MSG("\t802.1q field:\n");
		DEBUG_MSG("\t\tPriority:\t%u\n", ((vlan & 0xE000) >> 12));
		DEBUG_MSG("\t\tCFI:\t\t%u\n", ((vlan & 0x1000) >> 11));
		DEBUG_MSG("\t\tVLAN:\t\t%u\n", (vlan & 0x0FFF));

		hdrLen += 4;
		ethertype = ntohs(*(uint16_t*) (dataPtr + hdrLen - 2));
		DEBUG_MSG("\t\tEthertype:\t%#06x\n", ethertype);
	}

	pkt->ethertype = ethertype;

	return hdrLen;
}

#ifdef WITH_PCAP
/**
 * \brief Parse specific fields from SLL frame header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parseSll(const u_char* dataPtr, uint16_t dataLen, Packet* pkt)
{
	struct sll_header* sll = (struct sll_header*) dataPtr;
	if (sizeof(struct sll_header) > dataLen) {
		throw "Parser detected malformed packet";
	}

	DEBUG_MSG("SLL header:\n");
	DEBUG_MSG("\tPacket type:\t%u\n", ntohs(sll->sll_pkttype));
	DEBUG_MSG("\tHA type:\t%u\n", ntohs(sll->sll_hatype));
	DEBUG_MSG("\tHA len:\t\t%u\n", ntohs(sll->sll_halen));
	DEBUG_CODE(DEBUG_MSG("\tAddress:\t"); for (int i = 0; i < SLL_ADDRLEN; i++) {
		DEBUG_MSG("%02x ", sll->sll_addr[i]);
	} DEBUG_MSG("\n"););
	DEBUG_MSG("\tProtocol:\t%u\n", ntohs(sll->sll_protocol));

	if (ntohs(sll->sll_hatype) == ARPHRD_ETHER) {
		memcpy(pkt->srcMac, sll->sll_addr, 6);
	} else {
		memset(pkt->srcMac, 0, sizeof(pkt->srcMac));
	}
	memset(pkt->dstMac, 0, sizeof(pkt->dstMac));
	pkt->ethertype = ntohs(sll->sll_protocol);
	return sizeof(struct sll_header);
}

#ifdef DLT_LINUX_SLL2
inline uint16_t parseSll2(const u_char* dataPtr, uint16_t dataLen, Packet* pkt)
{
	struct sll2_header* sll = (struct sll2_header*) dataPtr;
	if (sizeof(struct sll2_header) > dataLen) {
		throw "Parser detected malformed packet";
	}

	DEBUG_MSG("SLL2 header:\n");
	DEBUG_MSG("\tPacket type:\t%u\n", ntohs(sll->sll2_pkttype));
	DEBUG_MSG("\tHA type:\t%u\n", ntohs(sll->sll2_hatype));
	DEBUG_MSG("\tHA len:\t\t%u\n", ntohs(sll->sll2_halen));
	DEBUG_MSG("\tinterface index:\t\t%u\n", ntohl(sll->sll2_if_index));
	DEBUG_CODE(DEBUG_MSG("\tAddress:\t"); for (int i = 0; i < SLL_ADDRLEN; i++) {
		DEBUG_MSG("%02x ", sll->sll2_addr[i]);
	} DEBUG_MSG("\n"););
	DEBUG_MSG("\tProtocol:\t%u\n", ntohs(sll->sll2_protocol));

	if (ntohs(sll->sll2_hatype) == ARPHRD_ETHER) {
		memcpy(pkt->srcMac, sll->sll2_addr, 6);
	} else {
		memset(pkt->srcMac, 0, sizeof(pkt->srcMac));
	}
	memset(pkt->dstMac, 0, sizeof(pkt->dstMac));
	pkt->ethertype = ntohs(sll->sll2_protocol);
	return sizeof(struct sll2_header);
}
#endif /* DLT_LINUX_SLL2 */
#endif /* WITH_PCAP */

/**
 * \brief Parse specific fields from TRILL.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parseTrill(const u_char* dataPtr, uint16_t dataLen, Packet* pkt)
{
	struct TrillHdr* trill = (struct TrillHdr*) dataPtr;
	if (sizeof(struct TrillHdr) > dataLen) {
		throw "Parser detected malformed packet";
	}
	uint8_t opLen = ((trill->opLen1 << 2) | trill->opLen2);
	uint8_t opLenBytes = opLen * 4;

	DEBUG_MSG("TRILL header:\n");
	DEBUG_MSG("\tHDR version:\t%u\n", trill->version);
	DEBUG_MSG("\tRES:\t\t%u\n", trill->res);
	DEBUG_MSG("\tM:\t\t%u\n", trill->m);
	DEBUG_MSG("\tOP length:\t%u (%u B)\n", op_len, op_len_bytes);
	DEBUG_MSG("\tHop cnt:\t%u\n", trill->hop_cnt);
	DEBUG_MSG("\tEgress nick:\t%u\n", ntohs(trill->egress_nick));
	DEBUG_MSG("\tIngress nick:\t%u\n", ntohs(trill->ingress_nick));

	return sizeof(TrillHdr) + opLenBytes;
}

/**
 * \brief Parse specific fields from IPv4 header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parseIpv4Hdr(const u_char* dataPtr, uint16_t dataLen, Packet* pkt)
{
	struct Iphdr* ip = (struct Iphdr*) dataPtr;
	if (sizeof(struct Iphdr) > dataLen) {
		throw "Parser detected malformed packet";
	}

	pkt->ipVersion = IP::V4;
	pkt->ipProto = ip->protocol;
	pkt->ipTos = ip->tos;
	pkt->ipLen = ntohs(ip->totLen);
	pkt->ipPayloadLen = pkt->ipLen - (ip->ihl << 2);
	pkt->ipTtl = ip->ttl;
	pkt->ipFlags = (ntohs(ip->fragOff) & 0xE000) >> 13;
	pkt->srcIp.v4 = ip->saddr;
	pkt->dstIp.v4 = ip->daddr;

	DEBUG_MSG("IPv4 header:\n");
	DEBUG_MSG("\tHDR version:\t%u\n", ip->version);
	DEBUG_MSG("\tHDR length:\t%u\n", ip->ihl);
	DEBUG_MSG("\tTOS:\t\t%u\n", ip->tos);
	DEBUG_MSG("\tTotal length:\t%u\n", ntohs(ip->tot_len));
	DEBUG_MSG("\tID:\t\t%#x\n", ntohs(ip->id));
	DEBUG_MSG("\tFlags:\t\t%#x\n", ((ntohs(ip->frag_off) & 0xE000) >> 13));
	DEBUG_MSG("\tFrag off:\t%#x\n", (ntohs(ip->frag_off) & 0x1FFF));
	DEBUG_MSG("\tTTL:\t\t%u\n", ip->ttl);
	DEBUG_MSG("\tProtocol:\t%u\n", ip->protocol);
	DEBUG_MSG("\tChecksum:\t%#06x\n", ntohs(ip->check));
	DEBUG_MSG("\tSrc addr:\t%s\n", inet_ntoa(*(struct in_addr*) (&ip->saddr)));
	DEBUG_MSG("\tDest addr:\t%s\n", inet_ntoa(*(struct in_addr*) (&ip->daddr)));

	return (ip->ihl << 2);
}

/**
 * \brief Skip IPv6 extension headers.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Length of headers in bytes.
 */
uint16_t skipIpv6ExtHdrs(const u_char* dataPtr, uint16_t dataLen, Packet* pkt)
{
	struct Ip6Ext* ext = (struct Ip6Ext*) dataPtr;
	uint8_t nextHdr = pkt->ipProto;
	uint16_t hdrsLen = 0;

	/* Skip extension headers... */
	while (1) {
		if ((int) sizeof(struct Ip6Ext) > dataLen - hdrsLen) {
			throw "Parser detected malformed packet";
		}
		if (nextHdr == IPPROTO_HOPOPTS || nextHdr == IPPROTO_DSTOPTS) {
			hdrsLen += (ext->ip6eLen << 3) + 8;
		} else if (nextHdr == IPPROTO_ROUTING) {
			struct Ip6Rthdr* rt = (struct Ip6Rthdr*) (dataPtr + hdrsLen);
			hdrsLen += (rt->ip6rLen << 3) + 8;
		} else if (nextHdr == IPPROTO_AH) {
			hdrsLen += (ext->ip6eLen << 2) - 2;
		} else if (nextHdr == IPPROTO_FRAGMENT) {
			hdrsLen += 8;
		} else {
			break;
		}
		DEBUG_MSG("\tIPv6 extension header:\t%u\n", next_hdr);
		DEBUG_MSG("\t\tLength:\t%u\n", ext->ip6e_len);

		nextHdr = ext->ip6eNxt;
		ext = (struct Ip6Ext*) (dataPtr + hdrsLen);
		pkt->ipProto = nextHdr;
	}

	pkt->ipPayloadLen -= hdrsLen;
	return hdrsLen;
}

/**
 * \brief Parse specific fields from IPv6 header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parseIpv6Hdr(const u_char* dataPtr, uint16_t dataLen, Packet* pkt)
{
	struct Ip6Hdr* ip6 = (struct Ip6Hdr*) dataPtr;
	uint16_t hdrLen = sizeof(struct Ip6Hdr);
	if (sizeof(struct Ip6Hdr) > dataLen) {
		throw "Parser detected malformed packet";
	}

	pkt->ipVersion = IP::V6;
	pkt->ipTos = (ntohl(ip6->ip6Ctlun.ip6Un1.ip6Un1Flow) & 0x0ff00000) >> 20;
	pkt->ipProto = ip6->ip6Ctlun.ip6Un1.ip6Un1Nxt;
	pkt->ipTtl = ip6->ip6Ctlun.ip6Un1.ip6Un1Hlim;
	pkt->ipFlags = 0;
	pkt->ipPayloadLen = ntohs(ip6->ip6Ctlun.ip6Un1.ip6Un1Plen);
	pkt->ipLen = pkt->ipPayloadLen + 40;
	memcpy(pkt->srcIp.v6, (const char*) &ip6->ip6Src, 16);
	memcpy(pkt->dstIp.v6, (const char*) &ip6->ip6Dst, 16);

	DEBUG_CODE(char buffer[INET6_ADDRSTRLEN]);
	DEBUG_MSG("IPv6 header:\n");
	DEBUG_MSG("\tVersion:\t%u\n", (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0xf0000000) >> 28);
	DEBUG_MSG("\tClass:\t\t%u\n", (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x0ff00000) >> 20);
	DEBUG_MSG("\tFlow:\t\t%#x\n", (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x000fffff));
	DEBUG_MSG("\tLength:\t\t%u\n", ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
	DEBUG_MSG("\tProtocol:\t%u\n", ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
	DEBUG_MSG("\tHop limit:\t%u\n", ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);

	DEBUG_CODE(inet_ntop(AF_INET6, (const void*) &ip6->ip6_src, buffer, INET6_ADDRSTRLEN));
	DEBUG_MSG("\tSrc addr:\t%s\n", buffer);
	DEBUG_CODE(inet_ntop(AF_INET6, (const void*) &ip6->ip6_dst, buffer, INET6_ADDRSTRLEN));
	DEBUG_MSG("\tDest addr:\t%s\n", buffer);

	if (pkt->ipProto != IPPROTO_TCP && pkt->ipProto != IPPROTO_UDP) {
		hdrLen += skipIpv6ExtHdrs(dataPtr + hdrLen, dataLen - hdrLen, pkt);
	}

	return hdrLen;
}

/**
 * \brief Parse specific fields from TCP header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parseTcpHdr(const u_char* dataPtr, uint16_t dataLen, Packet* pkt)
{
	struct Tcphdr* tcp = (struct Tcphdr*) dataPtr;
	if (sizeof(struct Tcphdr) > dataLen) {
		throw "Parser detected malformed packet";
	}

	pkt->srcPort = ntohs(tcp->source);
	pkt->dstPort = ntohs(tcp->dest);
	pkt->tcpSeq = ntohl(tcp->seq);
	pkt->tcpAck = ntohl(tcp->ackSeq);
	pkt->tcpFlags = (uint8_t) * (dataPtr + 13) & 0xFF;
	pkt->tcpWindow = ntohs(tcp->window);

	DEBUG_MSG("TCP header:\n");
	DEBUG_MSG("\tSrc port:\t%u\n", ntohs(tcp->source));
	DEBUG_MSG("\tDest port:\t%u\n", ntohs(tcp->dest));
	DEBUG_MSG("\tSEQ:\t\t%#x\n", ntohl(tcp->seq));
	DEBUG_MSG("\tACK SEQ:\t%#x\n", ntohl(tcp->ack_seq));
	DEBUG_MSG("\tData offset:\t%u\n", tcp->doff);
	DEBUG_MSG(
		"\tFlags:\t\t%s%s%s%s%s%s\n",
		(tcp->fin ? "FIN " : ""),
		(tcp->syn ? "SYN " : ""),
		(tcp->rst ? "RST " : ""),
		(tcp->psh ? "PSH " : ""),
		(tcp->ack ? "ACK " : ""),
		(tcp->urg ? "URG" : ""));
	DEBUG_MSG("\tWindow:\t\t%u\n", ntohs(tcp->window));
	DEBUG_MSG("\tChecksum:\t%#06x\n", ntohs(tcp->check));
	DEBUG_MSG("\tUrg ptr:\t%#x\n", ntohs(tcp->urg_ptr));
	DEBUG_MSG("\tReserved1:\t%#x\n", tcp->res1);
	DEBUG_MSG("\tReserved2:\t%#x\n", tcp->res2);

	int hdrLen = tcp->doff << 2;
	int hdrOptLen = hdrLen - sizeof(struct Tcphdr);
	int i = 0;
	DEBUG_MSG("\tTCP_OPTIONS (%uB):\n", hdr_opt_len);
	if (hdrLen > dataLen) {
		throw "Parser detected malformed packet";
	}
	while (i < hdrOptLen) {
		uint8_t* optPtr = (uint8_t*) dataPtr + sizeof(struct Tcphdr) + i;
		uint8_t optKind = *optPtr;
		if (i + 1 >= hdrOptLen) {
			if (optKind <= 1) {
				return hdrLen;
			}
			throw "Parser detected malformed packet";
		}
		uint8_t optLen = (optKind <= 1 ? 1 : *(optPtr + 1));
		DEBUG_MSG("\t\t%u: len=%u\n", opt_kind, opt_len);

		pkt->tcpOptions |= ((uint64_t) 1 << optKind);
		if (optKind == 0x00) {
			break;
		} else if (optKind == 0x02) {
			// Parse Maximum Segment Size (MSS)
			pkt->tcpMss = ntohl(*(uint32_t*) (optPtr + 2));
		}
		if (optLen == 0) {
			// Prevent infinity loop
			throw "Parser detected malformed packet";
		}
		i += optLen;
	}

	return hdrLen;
}

/**
 * \brief Parse specific fields from UDP header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parseUdpHdr(const u_char* dataPtr, uint16_t dataLen, Packet* pkt)
{
	struct Udphdr* udp = (struct Udphdr*) dataPtr;
	if (sizeof(struct Udphdr) > dataLen) {
		throw "Parser detected malformed packet";
	}

	pkt->srcPort = ntohs(udp->source);
	pkt->dstPort = ntohs(udp->dest);

	DEBUG_MSG("UDP header:\n");
	DEBUG_MSG("\tSrc port:\t%u\n", ntohs(udp->source));
	DEBUG_MSG("\tDest port:\t%u\n", ntohs(udp->dest));
	DEBUG_MSG("\tLength:\t\t%u\n", ntohs(udp->len));
	DEBUG_MSG("\tChecksum:\t%#06x\n", ntohs(udp->check));

	return 8;
}

/**
 * \brief Parse specific fields from ICMP header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parseIcmpHdr(const u_char* dataPtr, uint16_t dataLen, Packet* pkt)
{
	struct Icmphdr* icmp = (struct Icmphdr*) dataPtr;
	if (sizeof(struct Icmphdr) > dataLen) {
		throw "Parser detected malformed packet";
	}
	pkt->dstPort = icmp->type * 256 + icmp->code;

	DEBUG_MSG("ICMP header:\n");
	DEBUG_MSG("\tType:\t\t%u\n", icmp->type);
	DEBUG_MSG("\tCode:\t\t%u\n", icmp->code);
	DEBUG_MSG("\tChecksum:\t%#06x\n", ntohs(icmp->checksum));
	DEBUG_MSG("\tRest:\t\t%#06x\n", ntohl(*(uint32_t*) &icmp->un));

	return 0;
}

/**
 * \brief Parse specific fields from ICMPv6 header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parseIcmpv6Hdr(const u_char* dataPtr, uint16_t dataLen, Packet* pkt)
{
	struct Icmp6Hdr* icmp6 = (struct Icmp6Hdr*) dataPtr;
	if (sizeof(struct Icmp6Hdr) > dataLen) {
		throw "Parser detected malformed packet";
	}
	pkt->dstPort = icmp6->icmp6Type * 256 + icmp6->icmp6Code;

	DEBUG_MSG("ICMPv6 header:\n");
	DEBUG_MSG("\tType:\t\t%u\n", icmp6->icmp6_type);
	DEBUG_MSG("\tCode:\t\t%u\n", icmp6->icmp6_code);
	DEBUG_MSG("\tChecksum:\t%#x\n", ntohs(icmp6->icmp6_cksum));
	DEBUG_MSG("\tBody:\t\t%#x\n", ntohs(*(uint32_t*) &icmp6->icmp6_dataun));

	return 0;
}

/**
 * \brief Skip MPLS stack.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \return Size of headers in bytes.
 */
uint16_t processMplsStack(const u_char* dataPtr, uint16_t dataLen)
{
	uint32_t* mpls;
	uint16_t length = 0;

	do {
		mpls = (uint32_t*) (dataPtr + length);
		length += sizeof(uint32_t);
		if (0 > dataLen - length) {
			throw "Parser detected malformed packet";
		}

		DEBUG_MSG("MPLS:\n");
		DEBUG_MSG("\tLabel:\t%u\n", ntohl(*mpls) >> 12);
		DEBUG_MSG("\tTC:\t%u\n", (ntohl(*mpls) & 0xE00) >> 9);
		DEBUG_MSG("\tBOS:\t%u\n", (ntohl(*mpls) & 0x100) >> 8);
		DEBUG_MSG("\tTTL:\t%u\n", ntohl(*mpls) & 0xFF);

	} while (!(ntohl(*mpls) & 0x100));

	return length;
}

/**
 * \brief Skip MPLS stack and parse the following header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of parsed data in bytes.
 */
uint16_t processMpls(const u_char* dataPtr, uint16_t dataLen, Packet* pkt)
{
	Packet tmp;
	uint16_t length = processMplsStack(dataPtr, dataLen);
	uint8_t nextHdr = (*(dataPtr + length) & 0xF0) >> 4;

	if (nextHdr == IP::V4) {
		length += parseIpv4Hdr(dataPtr + length, dataLen - length, pkt);
	} else if (nextHdr == IP::V6) {
		length += parseIpv6Hdr(dataPtr + length, dataLen - length, pkt);
	} else if (nextHdr == 0) {
		/* Process EoMPLS */
		length += 4; /* Skip Pseudo Wire Ethernet control word. */
		length = parseEthHdr(dataPtr + length, dataLen - length, &tmp);
		if (tmp.ethertype == ETH_P_IP) {
			length += parseIpv4Hdr(dataPtr + length, dataLen - length, pkt);
		} else if (tmp.ethertype == ETH_P_IPV6) {
			length += parseIpv6Hdr(dataPtr + length, dataLen - length, pkt);
		}
	}

	return length;
}

/**
 * \brief Parse PPPOE header and the following IP header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of parsed data in bytes.
 */
inline uint16_t processPppoe(const u_char* dataPtr, uint16_t dataLen, Packet* pkt)
{
	struct PppoeHdr* pppoe = (struct PppoeHdr*) dataPtr;
	if (sizeof(struct PppoeHdr) + 2 > dataLen) {
		throw "Parser detected malformed packet";
	}
	uint16_t nextHdr = ntohs(*(uint16_t*) (dataPtr + sizeof(struct PppoeHdr)));
	uint16_t length = sizeof(struct PppoeHdr) + 2;

	DEBUG_MSG("PPPoE header:\n");
	DEBUG_MSG("\tVer:\t%u\n", pppoe->version);
	DEBUG_MSG("\tType:\t%u\n", pppoe->type);
	DEBUG_MSG("\tCode:\t%u\n", pppoe->code);
	DEBUG_MSG("\tSID:\t%u\n", ntohs(pppoe->sid));
	DEBUG_MSG("\tLength:\t%u\n", ntohs(pppoe->length));
	DEBUG_MSG("PPP header:\n");
	DEBUG_MSG("\tProtocol:\t%#04x\n", next_hdr);
	if (pppoe->code != 0) {
		return length;
	}

	if (nextHdr == 0x0021) {
		length += parseIpv4Hdr(dataPtr + length, dataLen - length, pkt);
	} else if (nextHdr == 0x0057) {
		length += parseIpv6Hdr(dataPtr + length, dataLen - length, pkt);
	}

	return length;
}

void parsePacket(
	parser_opt_t* opt,
	struct timeval ts,
	const uint8_t* data,
	uint16_t len,
	uint16_t caplen)
{
	if (opt->pblock->cnt >= opt->pblock->size) {
		return;
	}
	Packet* pkt = &opt->pblock->pkts[opt->pblock->cnt];
	uint16_t dataOffset = 0;

	DEBUG_MSG("---------- packet parser  #%u -------------\n", ++s_total_pkts);
	DEBUG_CODE(char timestamp[32]; time_t time = ts.tv_sec;
			   strftime(timestamp, sizeof(timestamp), "%FT%T", localtime(&time)););
	DEBUG_MSG("Time:\t\t\t%s.%06lu\n", timestamp, ts.tv_usec);
	DEBUG_MSG("Packet length:\t\tcaplen=%uB len=%uB\n\n", caplen, len);

	pkt->packetLenWire = len;
	pkt->ts = ts;
	pkt->srcPort = 0;
	pkt->dstPort = 0;
	pkt->ipProto = 0;
	pkt->ipTtl = 0;
	pkt->ipFlags = 0;
	pkt->ipVersion = 0;
	pkt->ipPayloadLen = 0;
	pkt->tcpFlags = 0;
	pkt->tcpWindow = 0;
	pkt->tcpOptions = 0;
	pkt->tcpMss = 0;

	uint32_t l3HdrOffset = 0;
	uint32_t l4HdrOffset = 0;
	try {
#ifdef WITH_PCAP
		if (opt->datalink == DLT_EN10MB) {
			dataOffset = parseEthHdr(data, caplen, pkt);
		} else if (opt->datalink == DLT_LINUX_SLL) {
			dataOffset = parseSll(data, caplen, pkt);
#ifdef DLT_LINUX_SLL2
		} else if (opt->datalink == DLT_LINUX_SLL2) {
			dataOffset = parseSll2(data, caplen, pkt);
#endif /* DLT_LINUX_SLL2 */
		} else if (opt->datalink == DLT_RAW) {
			if ((data[0] & 0xF0) == 0x40) {
				pkt->ethertype = ETH_P_IP;
			} else if ((data[0] & 0xF0) == 0x60) {
				pkt->ethertype = ETH_P_IPV6;
			}
		}
#else
		data_offset = parse_eth_hdr(data, caplen, pkt);
#endif /* WITH_PCAP */

		if (pkt->ethertype == ETH_P_TRILL) {
			dataOffset += parseTrill(data + dataOffset, caplen - dataOffset, pkt);
			dataOffset += parseEthHdr(data + dataOffset, caplen - dataOffset, pkt);
		}
		l3HdrOffset = dataOffset;
		if (pkt->ethertype == ETH_P_IP) {
			dataOffset += parseIpv4Hdr(data + dataOffset, caplen - dataOffset, pkt);
		} else if (pkt->ethertype == ETH_P_IPV6) {
			dataOffset += parseIpv6Hdr(data + dataOffset, caplen - dataOffset, pkt);
		} else if (pkt->ethertype == ETH_P_MPLS_UC || pkt->ethertype == ETH_P_MPLS_MC) {
			dataOffset += processMpls(data + dataOffset, caplen - dataOffset, pkt);
		} else if (pkt->ethertype == ETH_P_PPP_SES) {
			dataOffset += processPppoe(data + dataOffset, caplen - dataOffset, pkt);
		} else if (!opt->parseAll) {
			DEBUG_MSG("Unknown ethertype %x\n", pkt->ethertype);
			return;
		}

		l4HdrOffset = dataOffset;
		if (pkt->ipProto == IPPROTO_TCP) {
			dataOffset += parseTcpHdr(data + dataOffset, caplen - dataOffset, pkt);
		} else if (pkt->ipProto == IPPROTO_UDP) {
			dataOffset += parseUdpHdr(data + dataOffset, caplen - dataOffset, pkt);
		} else if (pkt->ipProto == IPPROTO_ICMP) {
			dataOffset += parseIcmpHdr(data + dataOffset, caplen - dataOffset, pkt);
		} else if (pkt->ipProto == IPPROTO_ICMPV6) {
			dataOffset += parseIcmpv6Hdr(data + dataOffset, caplen - dataOffset, pkt);
		}
	} catch (const char* err) {
		DEBUG_MSG("%s\n", err);
		return;
	}

	uint16_t pktLen = caplen;
	pkt->packet = data;
	pkt->packetLen = caplen;

	if (l4HdrOffset != l3HdrOffset) {
		if (l4HdrOffset + pkt->ipPayloadLen < 64) {
			// Packet contains 0x00 padding bytes, do not include them in payload
			pktLen = l4HdrOffset + pkt->ipPayloadLen;
		}
		pkt->payloadLenWire = pkt->ipPayloadLen - (dataOffset - l4HdrOffset);
	} else {
		pkt->payloadLenWire = pktLen - dataOffset;
	}

	pkt->payloadLen = pkt->payloadLenWire;
	if (pkt->payloadLen + dataOffset > pktLen) {
		// Set correct size when payload length is bigger than captured payload length
		pkt->payloadLen = pktLen - dataOffset;
	}
	pkt->payload = pkt->packet + dataOffset;

	DEBUG_MSG("Payload length:\t%u\n", pkt->payload_len);
	DEBUG_MSG("Packet parser exits: packet parsed\n");
	opt->packetValid = true;
	opt->pblock->cnt++;
	opt->pblock->bytes += len;
}

} // namespace ipxp
