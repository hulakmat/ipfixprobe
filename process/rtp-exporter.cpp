/**
 * \file rtp-exporter.cpp
 * \brief Plugin for parsing rtp-exporter traffic.
 * \author Stepan Simek simekst2@fit.cvut.cz
 * \date 2022
 */
/*
 * Copyright (C) 2022 CESNET
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
 * This software is provided as is'', and any express or implied
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

#include <iostream>
#include <iomanip>
#include <sstream>
#include <thread>

#include "rtp-exporter.hpp"
#include "rtp.hpp"
#include "ipfixprobe.hpp"

namespace ipxp {
int RecordExtRTP_EXPORTER::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("rtp-exporter", [](){
         return new RTP_EXPORTERPlugin();
      });

   register_plugin(&rec);
   RecordExtRTP_EXPORTER::REGISTERED_ID = register_extension();
}

RTP_EXPORTERPlugin::RTP_EXPORTERPlugin() : isInValidState(true)
{
   std::ostringstream ss_filename;

   ss_filename << "/tmp/rtp-exporter-";
   ss_filename << std::this_thread::get_id();

   ofs = std::make_shared<std::ofstream>();
   ofs->open(ss_filename.str(), std::ios::out | std::ios::trunc);
   if (ofs->is_open()) {
      *ofs << std::setprecision(RTP_EXPORTER_DECIMAL_PRECISION_EXPORT);
   }
   else{
      isInValidState = false;
      error("Invalid export location for rtp-exporter");
   }
}

RTP_EXPORTERPlugin::~RTP_EXPORTERPlugin()
{ }

void RTP_EXPORTERPlugin::init(const char *params)
{ }

void RTP_EXPORTERPlugin::close()
{ }

ProcessPlugin *RTP_EXPORTERPlugin::copy()
{
   return new RTP_EXPORTERPlugin(*this);
}

int RTP_EXPORTERPlugin::post_create(Flow &rec, const Packet &pkt)
{
   if (!isInValidState)
      return 0;

   RecordExtRTP_EXPORTER *rtp_export_record = new RecordExtRTP_EXPORTER();

   rec.add_extension(rtp_export_record);

   manage_packet(rec, pkt);

   return 0;
}

int RTP_EXPORTERPlugin::post_update(Flow &rec, const Packet &pkt)
{
   if (!isInValidState)
      return 0;

   manage_packet(rec, pkt);
   return 0;
}

void RTP_EXPORTERPlugin::manage_packet(const Flow &rec, const Packet &pkt)
{
   if (rec.ip_version != 0x04 || rec.ip_proto != IPPROTO_UDP)
      return;

   if (pkt.dst_port == 53 || pkt.src_port == 53)
      return;

   RecordExtRTP_EXPORTER *rtp_exporter_record =
     static_cast<RecordExtRTP_EXPORTER *>(rec.get_extension(RecordExtRTP_EXPORTER::REGISTERED_ID));

   uint32_t totalPackets = rec.dst_packets + rec.src_packets;

   if (rtp_exporter_record->counter == RTP_EXPORTER_EXPORT_PACKETS_TOTAL) {
      return;
   } else if (rtp_exporter_record->counter < RTP_EXPORTER_EXPORT_PACKETS_TOTAL 
      && totalPackets > RTP_EXPORTER_EXPORT_PACKETS_START) {

      rtp_exporter_record->add_packet(pkt);
      if (rtp_exporter_record->counter == RTP_EXPORTER_EXPORT_PACKETS_TOTAL) {
         export_flow(rec);
      }
      
   }
}

void RTP_EXPORTERPlugin::export_flow(const Flow &rec)
{
   RecordExtRTP *rtp_record = static_cast<RecordExtRTP *>(rec.get_extension(RecordExtRTP::REGISTERED_ID));

   if (!rtp_record) {
      isInValidState = false;
      error("Requirement for RTP_EXPORTER is not satisfied - RTP plugin is not turned on!");
   }

   RecordExtRTP_EXPORTER *rtp_exporter_record =
     static_cast<RecordExtRTP_EXPORTER *>(rec.get_extension(RecordExtRTP_EXPORTER::REGISTERED_ID));

   uint32_t totalRtp = rtp_record->rtp_counter.rtp_src
     + rtp_record->rtp_counter.rtp_dst;
   uint32_t totalProcessed = rec.src_packets
     + rec.dst_packets;

   double ratioRtp = totalProcessed > 0 ?
     ((double) totalRtp / totalProcessed ) : 0;

   for (size_t i = 0; i < rtp_exporter_record->counter; i++) {
      const Packet & pkt = rtp_exporter_record->packets[i];
      *ofs <<
         pkt.ts.tv_sec << FIELD_SEPARATOR <<
         pkt.ts.tv_usec << FIELD_SEPARATOR <<
         pkt.src_ip.v4 << FIELD_SEPARATOR <<
         pkt.dst_ip.v4 << FIELD_SEPARATOR <<
         pkt.src_port << FIELD_SEPARATOR <<
         pkt.dst_port << FIELD_SEPARATOR <<
         pkt.payload_len << FIELD_SEPARATOR <<
         (uint32_t) pkt.ip_proto << FIELD_SEPARATOR <<
         (uint32_t) pkt.ip_flags << FIELD_SEPARATOR <<
         (uint32_t) pkt.ip_tos << FIELD_SEPARATOR <<
         ratioRtp << NEW_LINE;
   }
} // RTP_EXPORTERPlugin::export_flow
}
