/**
 * \file rtp-exporter.hpp
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

#ifndef IPXP_PROCESS_RTP_EXPORTER_HPP
#define IPXP_PROCESS_RTP_EXPORTER_HPP

#include <cstring>

#ifdef WITH_NEMEA
# include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>


#include <cstring>
#include <fstream>
#include <memory>

namespace ipxp {
#define RTP_EXPORTER_UNIREC_TEMPLATE "" /* TODO: unirec template */

UR_FIELDS(
   /* TODO: unirec fields definition */
)

#define RTP_EXPORTER_EXPORT_PACKETS_TOTAL 200
#define RTP_EXPORTER_EXPORT_PACKETS_START 0
#define RTP_EXPORTER_DETECTION_THRESHOLD  0.3f
#define RTP_EXPORTER_DECIMAL_PRECISION_EXPORT 2 //decimal places

/**
 * \brief Flow record extension header for storing parsed RTP_EXPORTER data.
 */
struct RecordExtRTP_EXPORTER : public RecordExt {
   static int    REGISTERED_ID;

   struct Packet packets[RTP_EXPORTER_EXPORT_PACKETS_TOTAL];
   uint32_t      counter;

   RecordExtRTP_EXPORTER() : RecordExt(REGISTERED_ID), counter(0)
   { }

   #ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   { }

   const char *get_unirec_tmplt() const
   {
      return RTP_EXPORTER_UNIREC_TEMPLATE;
   }

   #endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      return 0;
   }

   const char **get_ipfix_tmplt() const
   {
      return 0;
   }

   void add_packet(const Packet &pkt)
   {
      if (counter < RTP_EXPORTER_EXPORT_PACKETS_TOTAL)
         packets[counter++] = pkt;
   }
};

/**
 * \brief Flow cache plugin for parsing RTP_EXPORTER packets.
 */
class RTP_EXPORTERPlugin : public ProcessPlugin
{
public:
   RTP_EXPORTERPlugin();
   ~RTP_EXPORTERPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser("rtp-exporter", "Parse RTP_EXPORTER traffic"); }

   std::string get_name() const { return "rtp-exporter"; }

   RecordExt *get_ext() const { return new RecordExtRTP_EXPORTER(); }

   ProcessPlugin *copy();

   int post_create(Flow &rec, const Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);

   void manage_packet(const Flow &rec, const Packet &pkt);
   void export_flow(const Flow &rec);


private:
   bool isInValidState;
   std::shared_ptr<std::ofstream> ofs;
   const char NEW_LINE        = '\n';
   const char FIELD_SEPARATOR = ',';
};
}
#endif /* IPXP_PROCESS_RTP_EXPORTER_HPP */
