/**
 * \file rtp.hpp
 * \brief Plugin for parsing rtp traffic.
 * \author STEPAN SIMEK simekst2@fit.cvut.cz
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

#pragma once

#ifndef IPXP_PROCESS_RTP_HPP
# define IPXP_PROCESS_RTP_HPP

# include <cstring>

# ifdef WITH_NEMEA
#  include "fields.h"
# endif

# include <ipfixprobe/process.hpp>
# include <ipfixprobe/flowifc.hpp>
# include <ipfixprobe/packet.hpp>
# include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp {
# define RTP_HEADER_MINIMUM_SIZE            12

# define RTP_HEADER_SRC_EMPTY               1
# define RTP_HEADER_SRC_MATCHING            2
# define RTP_HEADER_SRC_INITIALIZED         4

# define RTP_HEADER_DST_EMPTY               8
# define RTP_HEADER_DST_MATCHING            16
# define RTP_HEADER_DST_INITIALIZED         32

# define FLOW_PACKET_DIRECTION_SAME         0
# define FLOW_PACKET_DIRECTION_DIFFERENT    1

# define RTP_SEQUENCE_NUMBER_MAX_DIFFERENCE 5
# define RTP_TIMESTAMP_MAX_DIFFERENCE       ( 10 * 1024 )

# define RTP_UNIREC_TEMPLATE                "" /* TODO: unirec template */

UR_FIELDS(
   /* TODO: unirec fields definition */
)

struct __attribute__((packed)) rtp_header {
   union {
      struct {
         # if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
         uint16_t csrc_count : 4;
         uint16_t extension : 1;
         uint16_t padding : 1;
         uint16_t version : 2;
         // next byte
         uint16_t payload_type : 7;
         uint16_t marker : 1;
         # elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
         uint16_t version : 2;
         uint16_t padding : 1;
         uint16_t extension : 1;
         uint16_t csrc_count : 4;
         // next byte
         uint16_t marker : 1;
         uint16_t payload_type : 7;

         # else // if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
         #  error  "Please fix <endian.h>"
         # endif // if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
      };
      uint16_t flags;
   };
   uint16_t sequence_number;
   uint32_t timestamp;
   uint32_t ssrc;
};

struct rtp_counter {
   uint32_t total_src_after_recognition;
   uint32_t rtp_src;

   uint32_t total_dst_after_recognition;
   uint32_t rtp_dst;
};

/**
 * \brief Flow record extension header for storing parsed RTP data.
 */
struct RecordExtRTP : public RecordExt {
   static int         REGISTERED_ID;

   struct rtp_header  rtp_header_src;
   struct rtp_header  rtp_header_dst;

   struct rtp_counter rtp_counter;

   uint8_t            rtp_header_filled;

   RecordExtRTP() : RecordExt(REGISTERED_ID), rtp_counter{0}
   {
      rtp_header_filled = RTP_HEADER_SRC_EMPTY | RTP_HEADER_DST_EMPTY;
   }

   # ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   { }

   const char *get_unirec_tmplt() const
   {
      return RTP_UNIREC_TEMPLATE;
   }

   # endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      return 0;
   }

   const char **get_ipfix_tmplt() const
   {
      return 0;
   }
};

/**
 * \brief Process plugin for parsing RTP packets.
 */
class RTPPlugin : public ProcessPlugin
{
public:
   RTPPlugin();
   ~RTPPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser("rtp", "Parse RTP traffic"); }

   std::string get_name() const { return "rtp"; }

   RecordExt *get_ext() const { return new RecordExtRTP(); }

   ProcessPlugin *copy();

   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   void pre_export(Flow &rec);

private:

   void fill_rtp_record(const Packet &pkt, struct rtp_header &rtp_header);
   void update_rtp_record(const Packet &pkt, struct rtp_header &rtp_header);
   void convert_rtp_record(struct rtp_header &rtp_header);

   void manage_packet(const Flow & rec, const Packet &pkt);
   bool validate_rtp(const Packet &pkt);
   bool verify_rtp(const Packet &pkt, const struct rtp_header &rtp_header_flow);
};
}
#endif /* IPXP_PROCESS_RTP_HPP */
