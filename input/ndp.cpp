/**
 * \file ndp.cpp
 * \brief Packet reader using NDP library for high speed capture.
 * \author Tomas Benes <benesto@fit.cvut.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2020-2021 CESNET
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

#include <cstdio>
#include <cstring>
#include <iostream>

#include "ndp.hpp"
#include "parser.hpp"

namespace ipxp {

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("ndp", [](){return new NdpPacketReader();});
   register_plugin(&rec);
}

uint64_t le48toh(const uint8_t *data) {
   uint64_t result = ((uint64_t)data[5] << 40) |
                     ((uint64_t)data[4] << 32) |
                     ((uint64_t)data[3] << 24) |
                     ((uint64_t)data[2] << 16) |
                     ((uint64_t)data[1] << 8)  |
                     ((uint64_t)data[0] << 0);
   return result;
}

void packet_ndp_handler(parser_opt_t *opt, const struct ndp_packet *ndp_packet, const struct ndp_header *ndp_header)
{
   struct timeval ts;
#ifdef NDK_APP_NIC_HEADER
   if(ndp_header->timestamp == 0xffffffffffffffffL) {
	std::cerr << "Recieved invalid timestamp from FW tsu not working ?" << std::endl;
   }
#endif
   ts.tv_sec = le32toh(ndp_header->timestamp_sec);
   ts.tv_usec = le32toh(ndp_header->timestamp_nsec) / 1000;
   
   Packet *pkt = parse_packet(opt, ts, ndp_packet->data, ndp_packet->data_length, ndp_packet->data_length);
   if(pkt) {
       pkt->acc_ts.tv_ns = le32toh(ndp_header->timestamp_nsec) % 1000;
   }
}

NdpPacketReader::NdpPacketReader() : m_input_index(0)
{
}

NdpPacketReader::~NdpPacketReader()
{
   close();
}

void NdpPacketReader::init(const char *params)
{
   NdpOptParser parser;
   try {
      parser.parse(params);
   } catch (ParserError &e) {
      throw PluginError(e.what());
   }

   if (parser.m_dev.empty()) {
      throw PluginError("specify device path");
   }
   init_ifc(parser.m_dev);
   m_index_reserved = parser.m_index_reserved;
}

void NdpPacketReader::close()
{
   ndpReader.close();
}

void NdpPacketReader::init_ifc(const std::string &dev)
{
   if (ndpReader.init_interface(dev) != 0) {
      throw PluginError(ndpReader.error_msg);
   }
}

InputPlugin::Result NdpPacketReader::get(PacketBlock &packets)
{
   parser_opt_t opt = {&packets, false, false, 0, &m_input_index, 0};
   struct ndp_packet *ndp_packet;
   struct ndp_header *ndp_header;
   size_t read_pkts = 0;
   int ret = -1;

   packets.cnt = 0;
   for (unsigned i = 0; i < packets.size; i++) {
      ret = ndpReader.get_pkt(&ndp_packet, &ndp_header);
      if (ret == 0) {
         if (opt.pblock->cnt) {
            break;
         }
         return Result::TIMEOUT;
      } else if (ret < 0) {
         // Error occured.
         throw PluginError(ndpReader.error_msg);
      }
      read_pkts++;
      
      /* Counter for input channel */
      opt.link_index = 0;
      if(m_index_reserved) {
          opt.link_index = le48toh(ndp_header->reserved);
      }
      packet_ndp_handler(&opt, ndp_packet, ndp_header);
   }

   m_seen += read_pkts;
   m_parsed += opt.pblock->cnt;
   return opt.pblock->cnt ? Result::PARSED : Result::NOT_PARSED;
}

}
