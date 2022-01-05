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

#include "hashtablestore.hpp"
#include "flowstoremonitor.hpp"
#include "hiearchyflowstore.hpp"
#include "flowcache.hpp"
#include "xxhash.h"

namespace ipxp {

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("cache", []() {
      // return new FlowCache<
      //                FlowStoreMonitor<
      //                   HTFlowStore
      //                >
      //             >();
         return new FlowCache<
                  FlowStoreHiearchy<
                     FlowStoreMonitor<
                        HTFlowStore
                     >
                  >
               >();
   });
   register_plugin(&rec);
}

template <class F>
FlowCache<F>::FlowCache() :
   m_active(0), m_inactive(0),
   m_split_biflow(false)
{
}

template <class F>
void FlowCache<F>::init(const char *params)
{
   CacheOptParser parser;
   try {
      parser.parse(params);
   } catch (ParserError &e) {
      throw PluginError(e.what());
   }
   init(parser);
}


template <class F>
void FlowCache<F>::init(CacheOptParser &parser)
{
   m_active = parser.m_active;
   m_inactive = parser.m_inactive;
   m_timeout_step = parser.m_timeout_step;

   if (m_export_queue == nullptr) {
      throw PluginError("output queue must be set before init");
   }

   m_flow_store.init(static_cast<BaseParser&>(parser));
   m_timeout_iter = m_flow_store.begin();
   m_split_biflow = parser.m_split_biflow;

#ifdef FLOW_CACHE_STATS
   m_empty = 0;
   m_not_empty = 0;
   m_hits = 0;
   m_expired = 0;
   m_flushed = 0;
#endif /* FLOW_CACHE_STATS */
}

template <class F>
void FlowCache<F>::set_queue(ipx_ring_t *queue)
{
   m_out_queue.set_queue(queue);
   StoragePlugin::set_queue(queue);
}


template <class F>
void FlowCache<F>::export_prepare(FCRecord *flow, uint8_t reason, bool pre_export_hook)
{
   flow->m_flow.end_reason = reason;
   if(pre_export_hook) {
      plugins_pre_export(flow->m_flow);
   }
}

template <class F>
typename FlowCache<F>::FAccess FlowCache<F>::export_acc(const FAccess &flowAcc, uint8_t reason, bool pre_export_hook)
{
   export_prepare(*flowAcc, reason, pre_export_hook);
   return m_flow_store.index_export(flowAcc, m_out_queue);
}

template <class F>
typename FlowCache<F>::FAccess FlowCache<F>::export_iter(const FIter &flowIt, uint8_t reason, bool pre_export_hook)
{
   export_prepare(*flowIt, reason, pre_export_hook);
   return m_flow_store.iter_export(flowIt, m_out_queue);
}

template <class F>
void FlowCache<F>::finish()
{
   for(auto it = m_flow_store.begin(); it != m_flow_store.end(); ++it) {
      if (!(*it)->isEmpty()) {
         export_iter(it, FLOW_END_FORCED);
#ifdef FLOW_CACHE_STATS
         m_expired++;
#endif /* FLOW_CACHE_STATS */
      }
   }
}

template <class F>
void FlowCache<F>::flush(FInfo &pkt_info, FAccess flowIt, int ret, bool source_flow)
{
#ifdef FLOW_CACHE_STATS
   m_flushed++;
#endif /* FLOW_CACHE_STATS */

   if (ret == FLOW_FLUSH_WITH_REINSERT) {
      FCRecord *expFlow = (*flowIt);
      flowIt = export_acc(flowIt, FLOW_END_FORCED, false);
      FCRecord *flow = (*flowIt);

      flow->m_flow.remove_extensions();
      /* Copy fields into new space */
      *flow = *expFlow;

      flow->m_flow.m_exts = nullptr;
      flow->reuse(); // Clean counters, set time first to last
      flow->update(pkt_info, source_flow); // Set new counters from packet

      /* Mark flow as updated apply cache policy */
      flowIt = m_flow_store.put(flowIt);

      ret = plugins_post_create(flow->m_flow, *pkt_info.getPacket());
      if (ret & FLOW_FLUSH) {
         flush(pkt_info, flowIt, ret, source_flow);
      }
   } else {
      export_acc(flowIt, FLOW_END_FORCED, false);
   }
}

template <class F>
int FlowCache<F>::put_pkt(Packet &pkt)
{
   plugins_pre_create(pkt);
   auto pkt_info = m_flow_store.prepare(pkt);
   if (!pkt_info.isValid()) {
      return 0;
   }

   auto flowIt = m_flow_store.lookup(pkt_info);
   /* Find inversed flow. */
   if (flowIt == m_flow_store.lookup_end() && !m_split_biflow) {
      auto pkt_inv_info = m_flow_store.prepare(pkt, true);
      auto flowInvIt = m_flow_store.lookup(pkt_inv_info);
      if(flowInvIt != m_flow_store.lookup_end()) {
         /* When inverse flow found declare it as operatinal field */
         flowIt = flowInvIt;
         pkt_info = std::move(pkt_inv_info);
      }
   }

   if (flowIt == m_flow_store.lookup_end()) {
      /* Existing flow record was not found. Find free place in flow line. */
      flowIt = m_flow_store.lookup_empty(pkt_info);
      if (flowIt == m_flow_store.lookup_end()) {
         /* If free place was not found (flow line is full), find
          * record which will be replaced by new record. */
         auto freeIt = m_flow_store.free(pkt_info);
         if(freeIt == m_flow_store.lookup_end()) {
            //Throw unable to store flow. or return ?
            return 0;
         }
         flowIt = export_acc(freeIt, FLOW_END_NO_RES);
         /* Flow index has been freed for the incoming flow */
#ifdef FLOW_CACHE_STATS
         m_not_empty++;
      } else {
         m_empty++;
#endif /* FLOW_CACHE_STATS */
      }
   } else {
#ifdef FLOW_CACHE_STATS
      m_hits++;
#endif /* FLOW_CACHE_STATS */
   }
   return process_flow(pkt, pkt_info, flowIt);
}

template <class F>
int FlowCache<F>::process_flow(Packet &pkt, FInfo &pkt_info, FAccess &flowIt)
{
   int ret;
   pkt.source_pkt = !pkt_info.isInverse();
   FCRecord *flow = (*flowIt);

   /* Processing new flow insertion into the flow cache */
   if (flow->isEmpty()) {
      flow->create(static_cast<FCPacketInfo &>(pkt_info));
      ret = plugins_post_create(flow->m_flow, pkt);

      /* Used by derivate classes to track flow and packet info */
      flow_updated(pkt_info, flowIt);

      /* Mark flow as updated apply cache policy */
      flowIt = m_flow_store.put(flowIt);
      if (ret & FLOW_FLUSH) {
         flush(pkt_info, flowIt, ret, pkt.source_pkt);
      }
      return 0;
   }

   /* Processing existing flow inside the flow cache */
   uint8_t flw_flags = pkt.source_pkt ? flow->m_flow.src_tcp_flags : flow->m_flow.dst_tcp_flags;
   if ((pkt.tcp_flags & 0x02) && (flw_flags & (0x01 | 0x04))) //TODO: Make some enum/flags constants
   {
      // Flows with FIN or RST TCP flags are exported when new SYN packet arrives TODO: Why ? only complicates flow
      export_acc(flowIt, FLOW_END_EOF, false);
      put_pkt(pkt);
      return 0;
   }

   /* Check inactive timeout for given flow */
   if (pkt.ts.tv_sec - flow->m_flow.time_last.tv_sec >= m_inactive)
   {
      export_acc(flowIt, FLOW_END_INACTIVE, false);
#ifdef FLOW_CACHE_STATS
      m_expired++;
#endif /* FLOW_CACHE_STATS */
      return put_pkt(pkt);
   }

   ret = plugins_pre_update(flow->m_flow, pkt);
   if (ret & FLOW_FLUSH)
   {
      /* Used by derivate classes to track flow and packet info */
      flow_updated(pkt_info, flowIt);

      flush(pkt_info, flowIt, ret, pkt.source_pkt);
      return 0;
   }
   else
   {
      flow->update(static_cast<FCPacketInfo &>(pkt_info), pkt.source_pkt);
      ret = plugins_post_update(flow->m_flow, pkt);

      /* Used by derivate classes to track flow and packet info */
      flow_updated(pkt_info, flowIt);
      
      /* Mark flow as updated apply cache policy */
      flowIt = m_flow_store.put(flowIt);

      if (ret & FLOW_FLUSH)
      {
         flush(pkt_info, flowIt, ret, pkt.source_pkt);
         return 0;
      }
   }

   /* Check if flow record is expired. */
   if (pkt.ts.tv_sec - flow->m_flow.time_first.tv_sec >= m_active)
   {
      export_acc(flowIt, FLOW_END_ACTIVE);
#ifdef FLOW_CACHE_STATS
      m_expired++;
#endif /* FLOW_CACHE_STATS */
   }

   //TODO: Move to the front.
   /* Export expired flows before processing the incoming packet */
   export_expired(pkt.ts.tv_sec);
   return 0;
}

template <class F>
void FlowCache<F>::export_expired(time_t ts)
{
   for(uint32_t i = 0; i < m_timeout_step && m_timeout_iter != m_flow_store.end(); ++i) {
      if (!(*m_timeout_iter)->isEmpty() && ts - (*m_timeout_iter)->m_flow.time_last.tv_sec >= m_inactive) {
         export_iter(m_timeout_iter, FLOW_END_INACTIVE);
#ifdef FLOW_CACHE_STATS
         m_expired++;
#endif /* FLOW_CACHE_STATS */
      }
      ++m_timeout_iter;
   }
   if(m_timeout_iter == m_flow_store.end()) {
      m_timeout_iter = m_flow_store.begin();
   }
}

#ifdef FLOW_CACHE_STATS
#include <iostream>
using namespace std;
template <class F>
void FlowCache<F>::print_report()
{
   cout << "Hits: " << m_hits << endl;
   cout << "Empty: " << m_empty << endl;
   cout << "Not empty: " << m_not_empty << endl;
   cout << "Expired: " << m_expired << endl;
   cout << "Flushed: " << m_flushed << endl;
}
#endif /* FLOW_CACHE_STATS */

}
