/**
 * \file tlsstats.hpp
 * \brief Plugin for parsing tlsstats traffic.
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
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

#ifndef IPXP_PROCESS_TLSSTATS_HPP
#define IPXP_PROCESS_TLSSTATS_HPP

#include <endian.h>
#include <algorithm>
#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp
{

#ifndef MAX_TLS_LENGTHS
#define MAX_TLS_LENGTHS 20
#endif

#ifndef MAX_SEQ_NUM_TO_STORE
#define MAX_SEQ_NUM_TO_STORE 5
#endif



   typedef struct __attribute__((packed)) tls_header
   {
      uint8_t content_type;
      uint16_t version;
      uint16_t length;
   } tls_header;

#define TLSSTATS_UNIREC_TEMPLATE "PPI_PKT_LENGTHS,PPI_PKT_TIMES,PPI_PKT_FLAGS,PPI_PKT_DIRECTIONS" /* TODO: unirec template */

   UR_FIELDS(
       /* TODO: unirec fields definition */
   )

   /**
    * \brief Flow record extension header for storing parsed TLSSTATS data.
    */
   struct RecordExtTLSSTATS : public RecordExt
   {
      static int REGISTERED_ID;

      uint16_t tls_sizes[MAX_TLS_LENGTHS] = {0};

      RecordExtTLSSTATS() : RecordExt(REGISTERED_ID)
      {
      }

#ifdef WITH_NEMEA
      virtual void fill_unirec(ur_template_t *tmplt, void *record)
      {
      }

      const char *get_unirec_tmplt() const
      {
         return TLSSTATS_UNIREC_TEMPLATE;
      }
#endif

      virtual int fill_ipfix(uint8_t *buffer, int size)
      {
         return 0;
      }

      const char **get_ipfix_tmplt() const
      {
         static const char *ipfix_template[] = {
             IPFIX_TLSSTATS_TEMPLATE(IPFIX_FIELD_NAMES)
                 NULL};
         return ipfix_template;
      }
   };

   /**
    * \brief Process plugin for parsing TLSSTATS packets.
    */
   class TLSSTATSPlugin : public ProcessPlugin
   {
   public:
      enum content_type
      {
         change_cipher_spec = 0x14,
         alert = 0x15,
         handshake = 0x16,
         application_data = 0x17,
         heartbeat = 0x18,
         tls12_cid = 0x19,
         ack = 0x1A,
      };
      enum tls_ver
      {
         TLSV1 = 0x301,
         TLSV1DOT1 = 0x302,
         TLSV1DOT2 = 0x303,
         TLSV1DOT3 = 0x304
      };





      TLSSTATSPlugin();
      ~TLSSTATSPlugin();
      void init(const char *params);
      void close();
      OptionsParser *get_parser() const { return new OptionsParser("tlsstats", "Parse TLSSTATS traffic"); }
      std::string get_name() const { return "tlsstats"; }
      RecordExt *get_ext() const { return new RecordExtTLSSTATS(); }
      ProcessPlugin *copy();

      int pre_create(Packet &pkt);
      int post_create(Flow &rec, const Packet &pkt);
      int pre_update(Flow &rec, Packet &pkt);
      int post_update(Flow &rec, const Packet &pkt);
      void pre_export(Flow &rec);



}
#endif /* IPXP_PROCESS_TLSSTATS_HPP */

