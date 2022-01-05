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
#ifndef IPXP_STORAGE_CACHE_OUTPUT_HPP
#define IPXP_STORAGE_CACHE_OUTPUT_HPP

#include <string>

#include <ipfixprobe/storage.hpp>
#include <ipfixprobe/output.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/utils.hpp>
#include "record.hpp"
#include "flowringbuffer.hpp"
#include "flowcache.hpp"

namespace ipxp {

template <typename F>
class FlowCacheOutput : public FlowCache<F>
{
   typedef FlowCache<F> Base;
   class CacheLogOptParser : public Base::parser
   {
   public:
      std::vector<std::string> m_output;
      CacheLogOptParser() : Base::parser("cache_output", "Description")
      {
         this->register_option("o", "output", "ARGS", "Activate output plugin (-h output for help)",
                           [this](const char *arg) {
                              m_output.push_back(arg);
                              return true;
                           }, OptionsParser::OptionFlags::RequiredArgument);
      }
   };
   
public:
   typedef typename Base::FIter FIter;
   typedef typename Base::FAccess FAccess;
   typedef typename Base::FInfo FInfo;

   FlowCacheOutput();
   ~FlowCacheOutput();
   void init(const char *params);
   OptionsParser *get_parser() const { return new CacheLogOptParser(); }
   std::string get_name() const { return "cache_output"; }
   void flow_updated(FInfo &pkt_info, FAccess& flowAcc) override;

private:
   OutputPlugin *m_output_plugin; 
};
}
#endif /* IPXP_STORAGE_CACHE_HPP */
