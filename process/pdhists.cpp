/**
 * \file pdhists.cpp
 * \brief Plugin for parsing pdhists traffic.
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
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
 *
 *
 */

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <limits>
#include <math.h>

#include "pdhists.hpp"

namespace ipxp {

int RecordExtPDHISTS::REGISTERED_ID = -1;
const uint32_t RecordExtPDHISTS::dist_hist_empty_val = 0;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("pdhists", [](){return new PDHISTSPlugin();});
   register_plugin(&rec);
   RecordExtPDHISTS::REGISTERED_ID = register_extension();
}

#define PDHISTS_INCLUDE_ZEROS_OPT "includezeros"



const uint32_t PDHISTSPlugin::log2_lookup32[32] = { 0,  9,  1,  10, 13, 21, 2,  29,
                                                   11, 14, 16, 18, 22, 25, 3,  30,
                                                   8,  12, 20, 28, 15, 17, 24, 7,
                                                   19, 27, 23, 6,  26, 5,  4,  31 };

PDHISTSPlugin::PDHISTSPlugin() : use_zeros(false)
{
}

PDHISTSPlugin::~PDHISTSPlugin()
{
   close();
}

void PDHISTSPlugin::init(const char *params)
{
   PDHISTSOptParser parser;
   try {
      parser.parse(params);
   } catch (ParserError &e) {
      throw PluginError(e.what());
   }

   use_zeros = parser.m_include_zeroes;
}

void PDHISTSPlugin::close()
{
}

ProcessPlugin *PDHISTSPlugin::copy()
{
   return new PDHISTSPlugin(*this);
}

void PDHISTSPlugin::update_hist(uint32_t value, uint32_t *histogram)
{
   PDHISTS_DEBUG("Update Hist");
   if (value <  (2 << (2+HISTOGRAM_OFFSET))) {
      histogram[0] = no_overflow_increment(histogram[0]);
   } else if (value > (2 << (HISTOGRAM_SIZE+HISTOGRAM_OFFSET))) {
      histogram[HISTOGRAM_SIZE - 1] = no_overflow_increment(histogram[HISTOGRAM_SIZE - 1]);
   } else {
      size_t index = fastlog2_32(value) - HISTOGRAM_OFFSET - 1;
      if(index >= HISTOGRAM_SIZE) {
          std::cerr << "Weee wooo wee woo" << std::endl;
      }
      histogram[index] = no_overflow_increment(histogram[index]);
   }
   PDHISTS_DEBUG("Update Hist End");
   return;
}

uint64_t PDHISTSPlugin::calculate_packet_dst(uint64_t ind, uint64_t *last_val)
{
   if (*last_val == RecordExtPDHISTS::dist_hist_empty_val) {
      *last_val = ind;
      return std::numeric_limits<uint64_t>::max();
   }
   uint64_t diff = ind - *last_val;
   if(*last_val > ind) {
      /* Unwrapp */
      diff = std::numeric_limits<uint64_t>::max() - (ind - *last_val);
   }
   *last_val = ind;
   return diff;
}

void PDHISTSPlugin::update_record(RecordExtPDHISTS *pdhists_data, const Packet &pkt)
{
   if (pkt.payload_len_wire == 0 && use_zeros == false){
      return;
   }
   uint64_t inv_dst = std::numeric_limits<uint64_t>::max();
   uint8_t direction = pkt.source_pkt ? 0 : 1;
   uint64_t pkt_dir_chan_dst = calculate_packet_dst(pkt.channel_index, pdhists_data->last_pkt_index_channel + direction);
   uint64_t pkt_dir_link_dst = calculate_packet_dst(pkt.link_index, pdhists_data->last_pkt_index_intf + direction);
   uint64_t pkt_chan_dst     = calculate_packet_dst(pkt.channel_index, pdhists_data->last_pkt_index_channel + 2);
   uint64_t pkt_link_dst     = calculate_packet_dst(pkt.link_index, pdhists_data->last_pkt_index_intf + 2);
   
   PDHISTS_DEBUG("pkt_dir_chan_dst: " << pkt_dir_chan_dst <<
                 " pkt_dir_link_dst: " << pkt_dir_link_dst<<
                 " pkt_chan_dst: " << pkt_chan_dst<<
                 " pkt_link_dst: " << pkt_link_dst);
   if (pkt_dir_chan_dst != inv_dst) {
      update_hist((uint32_t) pkt_dir_chan_dst, pdhists_data->dist_hist_chan[direction]);
   }
   if (pkt_dir_link_dst != inv_dst) {
      update_hist((uint32_t) pkt_dir_link_dst, pdhists_data->dist_hist_intf[direction]);
   }
   if (pkt_chan_dst != inv_dst) {
      update_hist((uint32_t) pkt_chan_dst, pdhists_data->dist_hist_chan[2]);
   }
   if (pkt_link_dst != inv_dst) {
      update_hist((uint32_t) pkt_link_dst, pdhists_data->dist_hist_intf[2]);
   }
}



void PDHISTSPlugin::pre_export(Flow &rec)
{
   PDHISTS_DEBUG("Pre Export");
   //do not export pdhists for single packets flows, usually port scans
   uint32_t packets = rec.src_packets + rec.dst_packets;
   uint8_t flags = rec.src_tcp_flags | rec.dst_tcp_flags;

   if (packets <= PDHISTS_MINLEN && (flags & 0x02)) { //tcp SYN set
      rec.remove_extension(RecordExtPDHISTS::REGISTERED_ID);
   }
   
   PDHISTS_DEBUG("Pre Export Done");
}

int PDHISTSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   PDHISTS_DEBUG("Post create");
   RecordExtPDHISTS *pdhists_data = new RecordExtPDHISTS();

   rec.add_extension(pdhists_data);

   update_record(pdhists_data, pkt);
   PDHISTS_DEBUG("Post Create Done");
   return 0;
}

int PDHISTSPlugin::post_update(Flow &rec, const Packet &pkt)
{
   PDHISTS_DEBUG("Post Update");
   RecordExtPDHISTS *pdhists_data = (RecordExtPDHISTS *) rec.get_extension(RecordExtPDHISTS::REGISTERED_ID);

   update_record(pdhists_data, pkt);
   PDHISTS_DEBUG("Post Done");
   return 0;
}

}
