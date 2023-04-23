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
#include <ipfixprobe/ipfix-basiclist.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp
{

#ifndef MAX_TLS_LENGTHS
#define MAX_TLS_LENGTHS 20
#endif

#ifndef MAX_SEQ_NUM_TO_STORE
#define MAX_SEQ_NUM_TO_STORE 5
#endif

   typedef struct __attribute__((packed)) tls_frames
   {
      // timeval ts --> z packet.hpp
      // smer --> z packet.hpp
      // typ z check_if_tls
      uint32_t num;
      uint16_t frame_len;
      timeval timestamp;
      int8_t direction;
      uint8_t type;
   } tls_frames;

   typedef struct __attribute__((packed)) seq_num_data
   {
      uint32_t seq_num;
      uint16_t data_left;
   } seq_num_data;

   typedef struct __attribute__((packed)) tls_header
   {
      uint8_t content_type;
      uint16_t version;
      uint16_t length;
   } tls_header;

#define TLSSTATS_UNIREC_TEMPLATE "STATS_TLS_SIZES,STATS_TLS_TIMESTAMPS,STATS_TLS_DIRS,STATS_TLS_TYPES"

   UR_FIELDS(
       uint16 *STATS_TLS_SIZES,
       time *STATS_TLS_TIMESTAMPS,
       int8 *STATS_TLS_DIRS,
       uint8 *STATS_TLS_TYPES)

   /**
    * \brief Flow record extension header for storing parsed TLSSTATS data.
    */
   struct RecordExtTLSSTATS : public RecordExt
   {
      // update this based on what Tomas create
      typedef enum eHdrFieldID
      {
         SIZES = 804,
         TIMES = 805,
         DIRECTIONS = 806,
         TYPES = 807,
      } eHdrFieldID;
      static int REGISTERED_ID;

      uint16_t tls_sizes[MAX_TLS_LENGTHS] = {0};
      timeval tls_timestamps[MAX_TLS_LENGTHS] = {0};
      int8_t tls_directions[MAX_TLS_LENGTHS] = {-1};
      uint8_t tls_types[MAX_TLS_LENGTHS] = {0};
      uint8_t records_parsed = MAX_TLS_LENGTHS;

      RecordExtTLSSTATS() : RecordExt(REGISTERED_ID)
      {
      }

#ifdef WITH_NEMEA
      virtual void fill_unirec(ur_template_t *tmplt, void *record)
      {
         for (int i = 0; i < records_parsed; i++)
         {
            // "Automatically resizes array when index is out of array bounds"
            ur_array_set(tmplt, record, F_STATS_TLS_SIZES, i, tls_sizes[i]);
            ur_array_set(tmplt, record, F_STATS_TLS_TIMESTAMPS, i, tls_timestamps[i].tv_usec);
            ur_array_set(tmplt, record, F_STATS_TLS_DIRS, i, tls_directions[i]);
            ur_array_set(tmplt, record, F_STATS_TLS_TYPES, i, tls_types[i]);
         }
      }

      const char *get_unirec_tmplt() const
      {
         return TLSSTATS_UNIREC_TEMPLATE;
      }
#endif

      virtual int fill_ipfix(uint8_t *buffer, int size)
      {
         int32_t bufferPtr;
         IpfixBasicList basiclist;

         basiclist.hdrEnterpriseNum = IpfixBasicList::CesnetPEM;

         int req_size = 4 * basiclist.HeaderSize() +
                        sizeof(uint16_t) * records_parsed + // sizes
                        sizeof(uint64_t) * records_parsed + // timestamps
                        sizeof(int8_t) * records_parsed +   // directions
                        sizeof(uint8_t) * records_parsed;   // types

         if (req_size > size)
         {
            return -1;
         }
         bufferPtr = basiclist.FillBuffer(buffer, tls_sizes, records_parsed, (uint16_t)SIZES);
         bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, tls_timestamps, records_parsed, (uint16_t)TIMES);
         bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, tls_directions, records_parsed, (uint16_t)DIRECTIONS);
         bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, tls_types, records_parsed, (uint16_t)TYPES);

         return bufferPtr;
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

         CHANGE_CIPHER_SPEC = 0x14,
         ALERT = 0x15,
         HANDSHAKE = 0x16,
         APPLICATION_DATA = 0x17,
         HEARTHBEAT = 0x18,
         TLS12_CID = 0x19,
         ACK = 0x1A,
      };
      enum tls_ver
      {
         TLSV1 = 0x301,
         TLSV1DOT1 = 0x302,
         TLSV1DOT2 = 0x303,
         TLSV1DOT3 = 0x304
      };

      // first in pair je vzdy nasledujuce in order ocakavane seq number
      // second in pair je pocet dat ktore potrebujem este prijat v pripade ze je tls
      // napriec viacerymi paketmi

      tls_frames tls_frames_arr[MAX_TLS_LENGTHS];
      uint8_t last_free = 0;

      seq_num_data global_offsets_side1[MAX_SEQ_NUM_TO_STORE];
      seq_num_data global_offsets_side2[MAX_SEQ_NUM_TO_STORE];

      seq_num_data *current = nullptr;

      // std::map<uint16_t, std::vector<std::pair<uint32_t,uint16_t>>> global_offsets;

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

      void get_data(const Packet &);
      void fill_data(RecordExtTLSSTATS *);

      bool check_if_tls(tls_header *);
      void check_overlap(const uint8_t *, const uint8_t *, tls_header *, uint16_t, int8_t, const Packet &);

      void process_paket(const Packet &);
      bool find_seq(const Packet &, uint16_t &, int8_t &);
   };

}
#endif /* IPXP_PROCESS_TLSSTATS_HPP */
