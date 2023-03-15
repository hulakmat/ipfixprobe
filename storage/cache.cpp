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
#include <iostream>
#include <sys/time.h>

#include "cache.hpp"
#include "xxhash.h"
#include <ipfixprobe/ring.h>

namespace Ipxp {

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("cache", []() { return new NHTFlowCache(); });
	registerPlugin(&rec);
}

FlowRecord::FlowRecord()
{
	erase();
};

FlowRecord::~FlowRecord()
{
	erase();
};

void FlowRecord::erase()
{
	mFlow.removeExtensions();
	m_hash = 0;

	memset(&mFlow.timeFirst, 0, sizeof(mFlow.timeFirst));
	memset(&mFlow.timeLast, 0, sizeof(mFlow.timeLast));
	mFlow.ipVersion = 0;
	mFlow.ipProto = 0;
	memset(&mFlow.srcIp, 0, sizeof(mFlow.srcIp));
	memset(&mFlow.dstIp, 0, sizeof(mFlow.dstIp));
	mFlow.srcPort = 0;
	mFlow.dstPort = 0;
	mFlow.srcPackets = 0;
	mFlow.dstPackets = 0;
	mFlow.srcBytes = 0;
	mFlow.dstBytes = 0;
	mFlow.srcTcpFlags = 0;
	mFlow.dstTcpFlags = 0;
}
void FlowRecord::reuse()
{
	mFlow.removeExtensions();
	mFlow.timeFirst = mFlow.timeLast;
	mFlow.srcPackets = 0;
	mFlow.dstPackets = 0;
	mFlow.srcBytes = 0;
	mFlow.dstBytes = 0;
	mFlow.srcTcpFlags = 0;
	mFlow.dstTcpFlags = 0;
}

inline __attribute__((always_inline)) bool FlowRecord::isEmpty() const
{
	return m_hash == 0;
}

inline __attribute__((always_inline)) bool FlowRecord::belongs(uint64_t hash) const
{
	return hash == m_hash;
}

void FlowRecord::create(const Packet& pkt, uint64_t hash)
{
	mFlow.srcPackets = 1;

	m_hash = hash;

	mFlow.timeFirst = pkt.ts;
	mFlow.timeLast = pkt.ts;

	memcpy(mFlow.srcMac, pkt.srcMac, 6);
	memcpy(mFlow.dstMac, pkt.dstMac, 6);

	if (pkt.ipVersion == IP::V4) {
		mFlow.ipVersion = pkt.ipVersion;
		mFlow.ipProto = pkt.ipProto;
		mFlow.srcIp.v4 = pkt.srcIp.v4;
		mFlow.dstIp.v4 = pkt.dstIp.v4;
		mFlow.srcBytes = pkt.ipLen;
	} else if (pkt.ipVersion == IP::V6) {
		mFlow.ipVersion = pkt.ipVersion;
		mFlow.ipProto = pkt.ipProto;
		memcpy(mFlow.srcIp.v6, pkt.srcIp.v6, 16);
		memcpy(mFlow.dstIp.v6, pkt.dstIp.v6, 16);
		mFlow.srcBytes = pkt.ipLen;
	}

	if (pkt.ipProto == IPPROTO_TCP) {
		mFlow.srcPort = pkt.srcPort;
		mFlow.dstPort = pkt.dstPort;
		mFlow.srcTcpFlags = pkt.tcpFlags;
	} else if (pkt.ipProto == IPPROTO_UDP) {
		mFlow.srcPort = pkt.srcPort;
		mFlow.dstPort = pkt.dstPort;
	} else if (pkt.ipProto == IPPROTO_ICMP || pkt.ipProto == IPPROTO_ICMPV6) {
		mFlow.srcPort = pkt.srcPort;
		mFlow.dstPort = pkt.dstPort;
	}
}

void FlowRecord::update(const Packet& pkt, bool src)
{
	mFlow.timeLast = pkt.ts;
	if (src) {
		mFlow.srcPackets++;
		mFlow.srcBytes += pkt.ipLen;

		if (pkt.ipProto == IPPROTO_TCP) {
			mFlow.srcTcpFlags |= pkt.tcpFlags;
		}
	} else {
		mFlow.dstPackets++;
		mFlow.dstBytes += pkt.ipLen;

		if (pkt.ipProto == IPPROTO_TCP) {
			mFlow.dstTcpFlags |= pkt.tcpFlags;
		}
	}
}

NHTFlowCache::NHTFlowCache()
	: m_cache_size(0)
	, m_line_size(0)
	, m_line_mask(0)
	, m_line_new_idx(0)
	, m_qsize(0)
	, m_qidx(0)
	, m_timeout_idx(0)
	, m_active(0)
	, m_inactive(0)
	, m_split_biflow(false)
	, m_keylen(0)
	, m_key()
	, m_key_inv()
	, m_flow_table(nullptr)
	, m_flow_records(nullptr)
{
}

NHTFlowCache::~NHTFlowCache()
{
	close();
}

void NHTFlowCache::init(const char* params)
{
	CacheOptParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	m_cache_size = parser.mCacheSize;
	m_line_size = parser.mLineSize;
	m_active = parser.mActive;
	m_inactive = parser.mInactive;
	m_qidx = 0;
	m_timeout_idx = 0;
	m_line_mask = (m_cache_size - 1) & ~(m_line_size - 1);
	m_line_new_idx = m_line_size / 2;

	if (mExportQueue == nullptr) {
		throw PluginError("output queue must be set before init");
	}

	if (m_line_size > m_cache_size) {
		throw PluginError("flow cache line size must be greater or equal to cache size");
	}
	if (m_cache_size == 0) {
		throw PluginError("flow cache won't properly work with 0 records");
	}

	try {
		m_flow_table = new FlowRecord*[m_cache_size + m_qsize];
		m_flow_records = new FlowRecord[m_cache_size + m_qsize];
		for (decltype(m_cache_size + m_qsize) i = 0; i < m_cache_size + m_qsize; i++) {
			m_flow_table[i] = m_flow_records + i;
		}
	} catch (std::bad_alloc& e) {
		throw PluginError("not enough memory for flow cache allocation");
	}

	m_split_biflow = parser.mSplitBiflow;

#ifdef FLOW_CACHE_STATS
	m_empty = 0;
	m_not_empty = 0;
	m_hits = 0;
	m_expired = 0;
	m_flushed = 0;
	m_lookups = 0;
	m_lookups2 = 0;
#endif /* FLOW_CACHE_STATS */
}

void NHTFlowCache::close()
{
	if (m_flow_records != nullptr) {
		delete[] m_flow_records;
		m_flow_records = nullptr;
	}
	if (m_flow_table != nullptr) {
		delete[] m_flow_table;
		m_flow_table = nullptr;
	}
}

void NHTFlowCache::setQueue(ipx_ring_t* queue)
{
	mExportQueue = queue;
	m_qsize = ipxRingSize(queue);
}

void NHTFlowCache::exportFlow(size_t index)
{
	ipxRingPush(mExportQueue, &m_flow_table[index]->mFlow);
	std::swap(m_flow_table[index], m_flow_table[m_cache_size + m_qidx]);
	m_flow_table[index]->erase();
	m_qidx = (m_qidx + 1) % m_qsize;
}

void NHTFlowCache::finish()
{
	for (decltype(m_cache_size) i = 0; i < m_cache_size; i++) {
		if (!m_flow_table[i]->isEmpty()) {
			pluginsPreExport(m_flow_table[i]->mFlow);
			m_flow_table[i]->mFlow.endReason = FLOW_END_FORCED;
			exportFlow(i);
#ifdef FLOW_CACHE_STATS
			m_expired++;
#endif /* FLOW_CACHE_STATS */
		}
	}
}

void NHTFlowCache::flush(Packet& pkt, size_t flowIndex, int ret, bool sourceFlow)
{
#ifdef FLOW_CACHE_STATS
	m_flushed++;
#endif /* FLOW_CACHE_STATS */

	if (ret == FLOW_FLUSH_WITH_REINSERT) {
		FlowRecord* flow = m_flow_table[flowIndex];
		flow->mFlow.endReason = FLOW_END_FORCED;
		ipxRingPush(mExportQueue, &flow->mFlow);

		std::swap(m_flow_table[flowIndex], m_flow_table[m_cache_size + m_qidx]);

		flow = m_flow_table[flowIndex];
		flow->mFlow.removeExtensions();
		*flow = *m_flow_table[m_cache_size + m_qidx];
		m_qidx = (m_qidx + 1) % m_qsize;

		flow->mFlow.mExts = nullptr;
		flow->reuse(); // Clean counters, set time first to last
		flow->update(pkt, sourceFlow); // Set new counters from packet

		ret = pluginsPostCreate(flow->mFlow, pkt);
		if (ret & FLOW_FLUSH) {
			flush(pkt, flowIndex, ret, sourceFlow);
		}
	} else {
		m_flow_table[flowIndex]->mFlow.endReason = FLOW_END_FORCED;
		exportFlow(flowIndex);
	}
}

int NHTFlowCache::putPkt(Packet& pkt)
{
	int ret = pluginsPreCreate(pkt);

	if (!createHashKey(pkt)) { // saves key value and key length into attributes NHTFlowCache::key
							   // and NHTFlowCache::m_keylen
		return 0;
	}

	uint64_t hashval
		= XXH64(m_key, m_keylen, 0); /* Calculates hash value from key created before. */

	FlowRecord* flow; /* Pointer to flow we will be working with. */
	bool found = false;
	bool sourceFlow = true;
	uint32_t lineIndex = hashval & m_line_mask; /* Get index of flow line. */
	uint32_t flowIndex = 0;
	uint32_t nextLine = lineIndex + m_line_size;

	/* Find existing flow record in flow cache. */
	for (flowIndex = lineIndex; flowIndex < nextLine; flowIndex++) {
		if (m_flow_table[flowIndex]->belongs(hashval)) {
			found = true;
			break;
		}
	}

	/* Find inversed flow. */
	if (!found && !m_split_biflow) {
		uint64_t hashvalInv = XXH64(m_key_inv, m_keylen, 0);
		uint64_t lineIndexInv = hashvalInv & m_line_mask;
		uint64_t nextLineInv = lineIndexInv + m_line_size;
		for (flowIndex = lineIndexInv; flowIndex < nextLineInv; flowIndex++) {
			if (m_flow_table[flowIndex]->belongs(hashvalInv)) {
				found = true;
				sourceFlow = false;
				hashval = hashvalInv;
				lineIndex = lineIndexInv;
				break;
			}
		}
	}

	if (found) {
		/* Existing flow record was found, put flow record at the first index of flow line. */
#ifdef FLOW_CACHE_STATS
		m_lookups += (flow_index - line_index + 1);
		m_lookups2 += (flow_index - line_index + 1) * (flow_index - line_index + 1);
#endif /* FLOW_CACHE_STATS */

		flow = m_flow_table[flowIndex];
		for (decltype(flowIndex) j = flowIndex; j > lineIndex; j--) {
			m_flow_table[j] = m_flow_table[j - 1];
		}

		m_flow_table[lineIndex] = flow;
		flowIndex = lineIndex;
#ifdef FLOW_CACHE_STATS
		m_hits++;
#endif /* FLOW_CACHE_STATS */
	} else {
		/* Existing flow record was not found. Find free place in flow line. */
		for (flowIndex = lineIndex; flowIndex < nextLine; flowIndex++) {
			if (m_flow_table[flowIndex]->isEmpty()) {
				found = true;
				break;
			}
		}
		if (!found) {
			/* If free place was not found (flow line is full), find
			 * record which will be replaced by new record. */
			flowIndex = nextLine - 1;

			// Export flow
			pluginsPreExport(m_flow_table[flowIndex]->mFlow);
			m_flow_table[flowIndex]->mFlow.endReason = FLOW_END_NO_RES;
			exportFlow(flowIndex);

#ifdef FLOW_CACHE_STATS
			m_expired++;
#endif /* FLOW_CACHE_STATS */
			uint32_t flowNewIndex = lineIndex + m_line_new_idx;
			flow = m_flow_table[flowIndex];
			for (decltype(flowIndex) j = flowIndex; j > flowNewIndex; j--) {
				m_flow_table[j] = m_flow_table[j - 1];
			}
			flowIndex = flowNewIndex;
			m_flow_table[flowNewIndex] = flow;
#ifdef FLOW_CACHE_STATS
			m_not_empty++;
		} else {
			m_empty++;
#endif /* FLOW_CACHE_STATS */
		}
	}

	pkt.sourcePkt = sourceFlow;
	flow = m_flow_table[flowIndex];

	uint8_t flwFlags = sourceFlow ? flow->mFlow.srcTcpFlags : flow->mFlow.dstTcpFlags;
	if ((pkt.tcpFlags & 0x02) && (flwFlags & (0x01 | 0x04))) {
		// Flows with FIN or RST TCP flags are exported when new SYN packet arrives
		m_flow_table[flowIndex]->mFlow.endReason = FLOW_END_EOF;
		exportFlow(flowIndex);
		putPkt(pkt);
		return 0;
	}

	if (flow->isEmpty()) {
		flow->create(pkt, hashval);
		ret = pluginsPostCreate(flow->mFlow, pkt);

		if (ret & FLOW_FLUSH) {
			exportFlow(flowIndex);
#ifdef FLOW_CACHE_STATS
			m_flushed++;
#endif /* FLOW_CACHE_STATS */
		}
	} else {
		/* Check if flow record is expired (inactive timeout). */
		if (pkt.ts.tv_sec - flow->mFlow.timeLast.tv_sec >= m_inactive) {
			m_flow_table[flowIndex]->mFlow.endReason = getExportReason(flow->mFlow);
			pluginsPreExport(flow->mFlow);
			exportFlow(flowIndex);
#ifdef FLOW_CACHE_STATS
			m_expired++;
#endif /* FLOW_CACHE_STATS */
			return putPkt(pkt);
		}

		/* Check if flow record is expired (active timeout). */
		if (pkt.ts.tv_sec - flow->mFlow.timeFirst.tv_sec >= m_active) {
			m_flow_table[flowIndex]->mFlow.endReason = FLOW_END_ACTIVE;
			pluginsPreExport(flow->mFlow);
			exportFlow(flowIndex);
#ifdef FLOW_CACHE_STATS
			m_expired++;
#endif /* FLOW_CACHE_STATS */
			return putPkt(pkt);
		}

		ret = pluginsPreUpdate(flow->mFlow, pkt);
		if (ret & FLOW_FLUSH) {
			flush(pkt, flowIndex, ret, sourceFlow);
			return 0;
		} else {
			flow->update(pkt, sourceFlow);
			ret = pluginsPostUpdate(flow->mFlow, pkt);

			if (ret & FLOW_FLUSH) {
				flush(pkt, flowIndex, ret, sourceFlow);
				return 0;
			}
		}
	}

	exportExpired(pkt.ts.tv_sec);
	return 0;
}

uint8_t NHTFlowCache::getExportReason(Flow& flow)
{
	if ((flow.srcTcpFlags | flow.dstTcpFlags) & (0x01 | 0x04)) {
		// When FIN or RST is set, TCP connection ended naturally
		return FLOW_END_EOF;
	} else {
		return FLOW_END_INACTIVE;
	}
}

void NHTFlowCache::exportExpired(time_t ts)
{
	for (decltype(m_timeout_idx) i = m_timeout_idx; i < m_timeout_idx + m_line_new_idx; i++) {
		if (!m_flow_table[i]->isEmpty()
			&& ts - m_flow_table[i]->mFlow.timeLast.tv_sec >= m_inactive) {
			m_flow_table[i]->mFlow.endReason = getExportReason(m_flow_table[i]->mFlow);
			pluginsPreExport(m_flow_table[i]->mFlow);
			exportFlow(i);
#ifdef FLOW_CACHE_STATS
			m_expired++;
#endif /* FLOW_CACHE_STATS */
		}
	}

	m_timeout_idx = (m_timeout_idx + m_line_new_idx) & (m_cache_size - 1);
}

bool NHTFlowCache::createHashKey(Packet& pkt)
{
	if (pkt.ipVersion == IP::V4) {
		struct flow_key_v4_t* keyV4 = reinterpret_cast<struct flow_key_v4_t*>(m_key);
		struct flow_key_v4_t* keyV4Inv = reinterpret_cast<struct flow_key_v4_t*>(m_key_inv);

		keyV4->proto = pkt.ipProto;
		keyV4->ipVersion = IP::V4;
		keyV4->srcPort = pkt.srcPort;
		keyV4->dstPort = pkt.dstPort;
		keyV4->srcIp = pkt.srcIp.v4;
		keyV4->dstIp = pkt.dstIp.v4;

		keyV4Inv->proto = pkt.ipProto;
		keyV4Inv->ipVersion = IP::V4;
		keyV4Inv->srcPort = pkt.dstPort;
		keyV4Inv->dstPort = pkt.srcPort;
		keyV4Inv->srcIp = pkt.dstIp.v4;
		keyV4Inv->dstIp = pkt.srcIp.v4;

		m_keylen = sizeof(flow_key_v4_t);
		return true;
	} else if (pkt.ipVersion == IP::V6) {
		struct flow_key_v6_t* keyV6 = reinterpret_cast<struct flow_key_v6_t*>(m_key);
		struct flow_key_v6_t* keyV6Inv = reinterpret_cast<struct flow_key_v6_t*>(m_key_inv);

		keyV6->proto = pkt.ipProto;
		keyV6->ipVersion = IP::V6;
		keyV6->srcPort = pkt.srcPort;
		keyV6->dstPort = pkt.dstPort;
		memcpy(keyV6->srcIp, pkt.srcIp.v6, sizeof(pkt.srcIp.v6));
		memcpy(keyV6->dstIp, pkt.dstIp.v6, sizeof(pkt.dstIp.v6));

		keyV6Inv->proto = pkt.ipProto;
		keyV6Inv->ipVersion = IP::V6;
		keyV6Inv->srcPort = pkt.dstPort;
		keyV6Inv->dstPort = pkt.srcPort;
		memcpy(keyV6Inv->srcIp, pkt.dstIp.v6, sizeof(pkt.dstIp.v6));
		memcpy(keyV6Inv->dstIp, pkt.srcIp.v6, sizeof(pkt.srcIp.v6));

		m_keylen = sizeof(flow_key_v6_t);
		return true;
	}

	return false;
}

#ifdef FLOW_CACHE_STATS
void NHTFlowCache::print_report()
{
	float tmp = float(m_lookups) / m_hits;

	cout << "Hits: " << m_hits << endl;
	cout << "Empty: " << m_empty << endl;
	cout << "Not empty: " << m_not_empty << endl;
	cout << "Expired: " << m_expired << endl;
	cout << "Flushed: " << m_flushed << endl;
	cout << "Average Lookup:  " << tmp << endl;
	cout << "Variance Lookup: " << float(m_lookups2) / m_hits - tmp * tmp << endl;
}
#endif /* FLOW_CACHE_STATS */

} // namespace Ipxp
