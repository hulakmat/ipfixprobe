/**
 * \file cache.hpp
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
#ifndef IPXP_STORAGE_CACHE_HPP
#define IPXP_STORAGE_CACHE_HPP

#include <string>

#include <ipfixprobe/storage.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/utils.hpp>
#include "record.hpp"
#include "flowringbuffer.hpp"

#define FLOW_CACHE_STATS

namespace ipxp {

static const uint32_t DEFAULT_INACTIVE_TIMEOUT = 30;
static const uint32_t DEFAULT_ACTIVE_TIMEOUT = 300;
static const uint32_t DEFAULT_TIMEOUT_STEP = 8;

template <typename F>
class FlowCache : public StoragePlugin
{
   typedef typename F::parser BaseParser;
   class CacheOptParser : public BaseParser
   {
   public:
      uint32_t m_timeout_step;
      uint32_t m_active;
      uint32_t m_inactive;
      bool m_split_biflow;

      CacheOptParser(const std::string &name = "cache", const std::string &desc = "Desciption") : BaseParser(name, desc),
         m_timeout_step(DEFAULT_TIMEOUT_STEP), m_active(DEFAULT_ACTIVE_TIMEOUT), m_inactive(DEFAULT_INACTIVE_TIMEOUT), m_split_biflow(false)
      {
         this->register_option("a", "active", "TIME", "Active timeout in seconds",
            [this](const char *arg){try {m_active = str2num<decltype(m_active)>(arg);} catch(std::invalid_argument &e) {return false;} return true;},
            OptionsParser::OptionFlags::RequiredArgument);
         this->register_option("i", "inactive", "TIME", "Inactive timeout in seconds",
            [this](const char *arg){try {m_inactive = str2num<decltype(m_inactive)>(arg);} catch(std::invalid_argument &e) {return false;} return true;},
            OptionsParser::OptionFlags::RequiredArgument);
         this->register_option("t", "timeoutstep", "", "Number of records check each timeout check",
            [this](const char *arg){try {m_timeout_step = str2num<decltype(m_timeout_step)>(arg);} catch(std::invalid_argument &e) {return false;} return true;},
            OptionsParser::OptionFlags::RequiredArgument);
         this->register_option("S", "split", "", "Split biflows into uniflows",
            [this](const char *arg){ m_split_biflow = true; return true;}, 
            OptionsParser::OptionFlags::NoArgument);
      }
   };

public:
   typedef CacheOptParser parser;
   typedef typename F::iterator FIter;
   typedef typename F::accessor FAccess;
   typedef typename F::packet_info FInfo;

   FlowCache();
   void init(const char *params);
   void init(CacheOptParser &parser);
   void set_queue(ipx_ring_t *queue);
   OptionsParser *get_parser() const { return new CacheOptParser(); }
   std::string get_name() const { return "cache"; }

   int put_pkt(Packet &pkt);
   int process_flow(Packet &pkt, FInfo &pkt_info, FAccess &flowIt);
   void export_expired(time_t ts);

private:
   FlowRingBuffer m_out_queue;
   F m_flow_store;
   
   uint32_t m_timeout_step;
   FIter m_timeout_iter;
#ifdef FLOW_CACHE_STATS
   uint64_t m_empty;
   uint64_t m_not_empty;
   uint64_t m_hits;
   uint64_t m_expired;
   uint64_t m_flushed;
#endif /* FLOW_CACHE_STATS */
   uint32_t m_active;
   uint32_t m_inactive;
   bool m_split_biflow;

   virtual void flow_updated(FInfo &pkt_info, FAccess &flowIt) {};
   void flush(FInfo &pkt_info, FAccess flowIt, int ret, bool source_flow);
   void export_prepare(FCRecord *flow, uint8_t reason = FLOW_END_NO_RES, bool pre_export_hook = true);
   FAccess export_acc(const FAccess &flowAcc, uint8_t reason = FLOW_END_NO_RES, bool pre_export_hook = true);
   FAccess export_iter(const FIter &flowIt, uint8_t reason = FLOW_END_NO_RES, bool pre_export_hook = true);
   void finish();

#ifdef FLOW_CACHE_STATS
   void print_report();
#endif /* FLOW_CACHE_STATS */
};

}
#endif /* IPXP_STORAGE_CACHE_HPP */
