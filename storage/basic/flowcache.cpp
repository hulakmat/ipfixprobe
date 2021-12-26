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
#include <sys/time.h>

#include "flowcache.hpp"
#include "xxhash.h"

namespace ipxp {

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("cache", [](){return new NHTFlowCache();});
   register_plugin(&rec);
}

NHTFlowCache::NHTFlowCache() :
   m_cache_size(0), m_line_size(0), m_line_mask(0), m_line_new_idx(0),
   m_timeout_idx(0), m_active(0), m_inactive(0),
   m_split_biflow(false), m_keylen(0), m_flow_table(nullptr), m_flow_records(nullptr)
{
}

NHTFlowCache::~NHTFlowCache()
{
   close();
}

void NHTFlowCache::init(const char *params)
{
   CacheOptParser parser;
   try {
      parser.parse(params);
   } catch (ParserError &e) {
      throw PluginError(e.what());
   }

   m_cache_size = parser.m_cache_size;
   m_line_size = parser.m_line_size;
   m_active = parser.m_active;
   m_inactive = parser.m_inactive;
   m_timeout_idx = 0;
   m_line_mask = (m_cache_size - 1) & ~(m_line_size - 1);
   m_line_new_idx = m_line_size / 2;

   if (m_export_queue == nullptr) {
      throw PluginError("output queue must be set before init");
   }

   if (m_line_size > m_cache_size) {
      throw PluginError("flow cache line size must be greater or equal to cache size");
   }
   if (m_cache_size == 0) {
      throw PluginError("flow cache won't properly work with 0 records");
   }

   try {
      m_flow_table = new FCRecord*[m_cache_size];
      m_flow_records = new FCRecord[m_cache_size];
      for (decltype(m_cache_size) i = 0; i < m_cache_size; i++) {
         m_flow_table[i] = m_flow_records + i;
      }
   } catch (std::bad_alloc &e) {
      throw PluginError("not enough memory for flow cache allocation");
   }

   m_split_biflow = parser.m_split_biflow;

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
      delete [] m_flow_records;
      m_flow_records = nullptr;
   }
   if (m_flow_table != nullptr) {
      delete [] m_flow_table;
      m_flow_table = nullptr;
   }
}

void NHTFlowCache::set_queue(ipx_ring_t *queue)
{
   m_out_queue.set_queue(queue);
   StoragePlugin::set_queue(queue);
}

FCRecord* NHTFlowCache::export_flow(size_t index, uint8_t reason, bool pre_export_hook)
{
   m_flow_table[index]->m_flow.end_reason = reason;
   if(pre_export_hook) {
      plugins_pre_export(m_flow_table[index]->m_flow);
   }
   FCRecord *sw_rec = m_out_queue.put(m_flow_table[index]);
   m_flow_table[index] = sw_rec;
   sw_rec->erase();
   return sw_rec;
}

void NHTFlowCache::finish()
{
   for (decltype(m_cache_size) i = 0; i < m_cache_size; i++) {
      if (!m_flow_table[i]->isEmpty()) {
         export_flow(i, FLOW_END_FORCED);
#ifdef FLOW_CACHE_STATS
         m_expired++;
#endif /* FLOW_CACHE_STATS */
      }
   }
}

void NHTFlowCache::flush(Packet &pkt, size_t flow_index, int ret, bool source_flow)
{
#ifdef FLOW_CACHE_STATS
   m_flushed++;
#endif /* FLOW_CACHE_STATS */

   if (ret == FLOW_FLUSH_WITH_REINSERT) {
      FCRecord *exp_flow = m_flow_table[flow_index];
      FCRecord *flow = export_flow(flow_index, FLOW_END_FORCED, false);

      flow->m_flow.remove_extensions();
      /* Copy fields into new space */
      *flow = *exp_flow;

      flow->m_flow.m_exts = nullptr;
      flow->reuse(); // Clean counters, set time first to last
      flow->update(pkt, source_flow); // Set new counters from packet

      ret = plugins_post_create(flow->m_flow, pkt);
      if (ret & FLOW_FLUSH) {
         flush(pkt, flow_index, ret, source_flow);
      }
   } else {
      export_flow(flow_index, FLOW_END_FORCED, false);
   }
}


int NHTFlowCache::put_pkt(Packet &pkt)
{
   int ret = plugins_pre_create(pkt);

   FCKey pkt_key = FCKey::from_packet(pkt);
   if (!pkt_key.isValid()) {
      return 0;
   }


   FCRecord *flow; /* Pointer to flow we will be working with. */
   bool source_flow = true;
   FlowIndex flowRow_index = makeRowIndex(pkt_key.getHash());
   FlowIndex flowIndex = searchLine(flowRow_index, pkt_key.getHash());

   /* Find inversed flow. */
   if (!flowIndex.valid && !m_split_biflow) {
      FCKey pkt_inv_key = FCKey::from_packet(pkt, true);
      FlowIndex flowRow_inv_index = makeRowIndex(pkt_inv_key.getHash());
      FlowIndex flowIndex_inv = searchLine(flowRow_inv_index, pkt_inv_key.getHash());
      if(flowIndex_inv.valid) {
         /* When inverse flow found declare it as operatinal field */
         flowRow_index = flowRow_inv_index;
         flowIndex = flowIndex_inv;
         pkt_key = pkt_inv_key;

         source_flow = false;
      }
   }

   if (flowIndex.valid) {
      moveToFront(flowIndex);
   } else {
      /* Existing flow record was not found. Find free place in flow line. */
      flowIndex = searchEmptyLine(flowIndex);
      if (!flowIndex.valid) {
         /* If free place was not found (flow line is full), find
          * record which will be replaced by new record. */

         /* Last flow will be used */
         flowIndex.flow_index = flowIndex.line_index + m_line_size - 1;
         moveToFront(flowIndex);

         // Export flow
         export_flow(flowIndex.flow_index, FLOW_END_NO_RES);

         /* Flow index has been freed for the incoming flow */
      }
   }

   pkt.source_pkt = source_flow;
   flow = m_flow_table[flowIndex.flow_index];

   /* Processing new flow insertion into the flow cache */
   if (flow->isEmpty()) {
      flow->create(pkt, pkt_key.getHash());
      ret = plugins_post_create(flow->m_flow, pkt);

      if (ret & FLOW_FLUSH) {
         export_flow(flowIndex.flow_index, FLOW_END_FORCED, false); //TODO: Why does not have export reason? EOF when plugin requests flush ?
#ifdef FLOW_CACHE_STATS
         m_flushed++;
#endif /* FLOW_CACHE_STATS */
      }
      return 0;
   }

   /* Processing existing flow inside the flow cache */
   uint8_t flw_flags = source_flow ? flow->m_flow.src_tcp_flags : flow->m_flow.dst_tcp_flags;
   if ((pkt.tcp_flags & 0x02) && (flw_flags & (0x01 | 0x04)))
   {
      // Flows with FIN or RST TCP flags are exported when new SYN packet arrives
      export_flow(flowIndex.flow_index, FLOW_END_EOF, false);
      put_pkt(pkt);
      return 0;
   }

   /* Check inactive timeout for given flow */
   if (pkt.ts.tv_sec - flow->m_flow.time_last.tv_sec >= m_inactive)
   {
      export_flow(flowIndex.flow_index, FLOW_END_INACTIVE, false);
#ifdef FLOW_CACHE_STATS
      m_expired++;
#endif /* FLOW_CACHE_STATS */
      return put_pkt(pkt);
   }

   ret = plugins_pre_update(flow->m_flow, pkt);
   if (ret & FLOW_FLUSH)
   {
      flush(pkt, flowIndex.flow_index, ret, source_flow);
      return 0;
   }
   else
   {
      flow->update(pkt, source_flow);
      ret = plugins_post_update(flow->m_flow, pkt);

      if (ret & FLOW_FLUSH)
      {
         flush(pkt, flowIndex.flow_index, ret, source_flow);
         return 0;
      }
   }

   /* Check if flow record is expired. */
   if (pkt.ts.tv_sec - flow->m_flow.time_first.tv_sec >= m_active)
   {
      export_flow(flowIndex.flow_index, FLOW_END_ACTIVE);
#ifdef FLOW_CACHE_STATS
      m_expired++;
#endif /* FLOW_CACHE_STATS */
   }

   //TODO: Move to the front.
   /* Export expired flows before processing the incoming packet */
   export_expired(pkt.ts.tv_sec);
   return 0;
}

void NHTFlowCache::export_expired(time_t ts)
{
   for (decltype(m_timeout_idx) i = m_timeout_idx; i < m_timeout_idx + m_line_new_idx; i++) {
      if (!m_flow_table[i]->isEmpty() && ts - m_flow_table[i]->m_flow.time_last.tv_sec >= m_inactive) {
         export_flow(i, FLOW_END_INACTIVE);
#ifdef FLOW_CACHE_STATS
         m_expired++;
#endif /* FLOW_CACHE_STATS */
      }
   }

   m_timeout_idx = (m_timeout_idx + m_line_new_idx) & (m_cache_size - 1);
}

#ifdef FLOW_CACHE_STATS
#include <iostream>
using namespace std;
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

}
