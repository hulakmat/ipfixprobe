/**
 * \file tlsstats.cpp
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

#include "tlsstats.hpp"

#ifdef DEBUG_TLS
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

namespace ipxp
{

   int RecordExtTLSSTATS::REGISTERED_ID = -1;

   __attribute__((constructor)) static void register_this_plugin()
   {
      static PluginRecord rec = PluginRecord("tlsstats", []()
                                             { return new TLSSTATSPlugin(); });
      register_plugin(&rec);
      RecordExtTLSSTATS::REGISTERED_ID = register_extension();
   }

   TLSSTATSPlugin::TLSSTATSPlugin()
   {
      // initialze buffers for both sides
      for (uint8_t x = 0; x < MAX_SEQ_NUM_TO_STORE; x++)
      {
         global_offsets_side1[x].seq_num = 0;
         global_offsets_side1[x].data_left = 0;
         global_offsets_side2[x].seq_num = 0;
         global_offsets_side2[x].data_left = 0;
      }
   }
   TLSSTATSPlugin::~TLSSTATSPlugin()
   {
   }

   void TLSSTATSPlugin::init(const char *params)
   {
   }

   void TLSSTATSPlugin::close()
   {
   }

   ProcessPlugin *TLSSTATSPlugin::copy()
   {
      return new TLSSTATSPlugin(*this);
   }

   int TLSSTATSPlugin::pre_create(Packet &pkt)
   {
      return 0;
   }

   int TLSSTATSPlugin::post_create(Flow &rec, const Packet &pkt)
   {
      get_data(pkt);
      return 0;
   }

   int TLSSTATSPlugin::pre_update(Flow &rec, Packet &pkt)
   {
      return 0;
   }

   int TLSSTATSPlugin::post_update(Flow &rec, const Packet &pkt)
   {
      get_data(pkt);
      return 0;
   }
   bool compare(const tls_frames &a, const tls_frames &b) { return a.num < b.num; }
   void TLSSTATSPlugin::fill_data(RecordExtTLSSTATS *tlsstats_data)
   {
      std::sort(tls_frames_arr, tls_frames_arr + last_free, &compare);
      for (uint8_t x = 0; x < last_free; x++)
      {
         tlsstats_data->tls_sizes[x] = tls_frames_arr[x].frame_len;
         tlsstats_data->tls_timestamps[x] = tls_frames_arr[x].timestamp;
         tlsstats_data->tls_directions[x] = tls_frames_arr[x].direction;
         tlsstats_data->tls_types[x] = tls_frames_arr[x].type;
         
         DEBUG_MSG("---\n");
         DEBUG_MSG("Size: %u \n", tlsstats_data->tls_sizes[x]);
         DEBUG_MSG("Timeval: %u \n", tlsstats_data->tls_timestamps[x]);
         DEBUG_MSG("Dir: %u \n", tlsstats_data->tls_directions[x]);
         DEBUG_MSG("Type: %u \n", tlsstats_data->tls_types[x]);
         DEBUG_MSG("---\n");
      }
      tlsstats_data->records_parsed = last_free;
      DEBUG_MSG("\n");
   }

   void TLSSTATSPlugin::pre_export(Flow &rec)
   {
      RecordExtTLSSTATS *tlsstats_data = new RecordExtTLSSTATS();
      rec.add_extension(tlsstats_data);
      fill_data(tlsstats_data);
   }

   bool TLSSTATSPlugin::check_if_tls(tls_header *tls_h)
   {
      if ((tls_h->content_type == CHANGE_CIPHER_SPEC ||
           tls_h->content_type == ALERT ||
           tls_h->content_type == HANDSHAKE ||
           tls_h->content_type == APPLICATION_DATA ||
           tls_h->content_type == HEARTHBEAT ||
           tls_h->content_type == TLS12_CID ||
           tls_h->content_type == ACK) &&
          ((be16toh(tls_h->version) == TLSV1) ||
           (be16toh(tls_h->version) == TLSV1DOT1) ||
           (be16toh(tls_h->version) == TLSV1DOT2) ||
           (be16toh(tls_h->version) == TLSV1DOT3)))
         return true;
      return false;
   }

   void TLSSTATSPlugin::check_overlap(const uint8_t *payload_start, const uint8_t *payload_end,
                                      tls_header *tls_h, uint16_t offset, int8_t vector_index, const Packet &pkt)
   {

      if ((payload_start + offset + be16toh(tls_h->length)) > payload_end)
      {
         // frame overlaps, so we need to update record in the buffer
         if (vector_index > -1 && vector_index < MAX_SEQ_NUM_TO_STORE)
         {
            // seq number for next packet and data left for number of tls data 
            // that needs to be obtained
            current[vector_index].seq_num =
                pkt.tcp_seq + pkt.payload_len;

            current[vector_index].data_left =
                be16toh(tls_h->length) - (payload_end - (payload_start + offset));
         }
         else
         {
            DEBUG_MSG("Vector index out of bounds\n");
         }
      }
      else if ((payload_start + offset + be16toh(tls_h->length)) == payload_end)
      {
         // frame does not overlap so reset record to zeros
         if (vector_index > -1 && vector_index < MAX_SEQ_NUM_TO_STORE)
         {
            current[vector_index].seq_num = 0;
            current[vector_index].data_left = 0;
         }
         else
         {
            DEBUG_MSG("Vector index out of bounds\n");
         }
      }
   }

   bool TLSSTATSPlugin::find_seq(const Packet &pkt, uint16_t &local_offset, int8_t &vector_index)
   {

      for (uint8_t i = 0; i < MAX_SEQ_NUM_TO_STORE; i++)
      {
         // We dont have to handle example belove, because if we get in order no overlaping
         // or we get from the futer either way we look at start, so 
         // we dont have to calculate offset.

         // 1.
         // PKT1        PKT2        PKT3
         // -------     -------     -------
         // |     |     |     |     |     |
         // -------     -------     -------
         //             ^
         //             |        

         // or
         
         // 2.
         // PKT1        PKT2        PKT3
         // -------     -------     -------
         // |     |     |     |     |     |
         // -------     -------     -------
         //             FULL OF     ^
         //             TLS HERE    |        

         // ------------------------------------------------------------------------

         // 1.
         // PKT1        THIS PKT    PKT3
         // -------     -------     -------
         // |     |     |     |     |     |
         // -------     -------     -------
         //     ^                       ^
         //     |                       |
         //    TLS Start,               TLS ends somewhere here,
         //    somewhere here           so we just skip
         
         
         // or

         // 2.
         // PKT1        PKT2        THIS PKT
         // -------     -------     -------
         // |     |     |     |     |     |
         // -------     -------     -------
         //     ^                       ^
         //     |                       |
         //    TLS Start               TLS ends somewhere here,
         //    somewhere here          so we need to calculate
         //                            where    
         if (
            pkt.tcp_seq >= current[i].seq_num && 
            pkt.tcp_seq <= current[i].seq_num + current[i].data_left)
         {
            // TLS ends here, 2. option
            if (current[i].seq_num + current[i].data_left -
                    pkt.tcp_seq <=
                pkt.payload_len)
            {
               // Calculate offset where TLS ends
               local_offset = current[i].seq_num + current[i].data_left -
                              pkt.tcp_seq;
               
               vector_index = i;

               //reset tls buffer
               current[i].seq_num = pkt.tcp_seq;
               current[i].data_left = 0;

               return true;
            }
            // TLS does not end here 1. option 
            else
            {
               // TLS does not end here 1. option
               local_offset = pkt.payload_len;
               vector_index = -1;
               return true;
            }
         }
      }
      return false;
   }

   void TLSSTATSPlugin::process_paket(const Packet &pkt)
   {
      uint16_t local_offset = 0;
      int8_t vector_index = -1;
      const uint8_t *payload_start = pkt.payload;
      const uint8_t *payload_end = pkt.payload + pkt.payload_len;
      tls_header *tls_h = nullptr;

      if (!find_seq(pkt, local_offset, vector_index))
      {
         // consider creating buffer record in the ckeck overlap
         // because we dont know yet If we will ned the record
         vector_index = MAX_SEQ_NUM_TO_STORE;
         for (uint8_t i = 0; i < MAX_SEQ_NUM_TO_STORE; i++)
         {
            if (current[i].seq_num == 0 && current[i].data_left == 0)
            {
               vector_index = i;
               break;
            }
         }
         if (vector_index < MAX_SEQ_NUM_TO_STORE)
         {
            current[vector_index].seq_num = pkt.tcp_seq;
            current[vector_index].data_left = 0;

         }
         else
         {
            DEBUG_MSG("Can`t process more out of order packets, returning\n");
            // consider not returing here.
            return;
         }
      }

      while ((payload_start + local_offset) < payload_end)
      {
         tls_h = (tls_header *)(payload_start + local_offset);
         if (check_if_tls(tls_h))
         {
            // skip tls header
            local_offset += sizeof(tls_header);
            // check if tls overlaps multiple packets, if so setup buffer
            // if not, we do not need record, so reset record
            check_overlap(payload_start, payload_end, tls_h, local_offset, vector_index, pkt);
            DEBUG_MSG("FRAME LENGTH %d\n", be16toh(tls_h->length));
            if (last_free < MAX_TLS_LENGTHS)
            {
               if (pkt.source_pkt)
               {
                  tls_frames_arr[last_free].num = pkt.tcp_seq;
               }
               else
               {
                  tls_frames_arr[last_free].num = pkt.tcp_ack;
               }
               tls_frames_arr[last_free].frame_len = be16toh(tls_h->length);
               int8_t direction = (int8_t) !pkt.source_pkt;
               tls_frames_arr[last_free].timestamp = pkt.ts;
               tls_frames_arr[last_free].direction = direction;
               tls_frames_arr[last_free++].type = tls_h->content_type;
            }
            else
            {
               // cant process more TLS records, so pointless to loop
               return;
            }

            local_offset += be16toh(tls_h->length);
         }
         else
         {
            DEBUG_MSG("THIS CAN HAPPEN IF YOU INCORRECTLY USE OFFSET OR WE DO NOT KNOW WHERE TO LOOK SO WE JUST LOOK AT START\n");
            
            // consider returning here
            // return;
            local_offset++;
         }
      }
   }

   void TLSSTATSPlugin::get_data(const Packet &pkt)
   {
      // MAX_TLS_LENGTHS is set to 20 that means we can 
      // process 20 TLS Frames, if the value is reached,
      // stop processing
      if (last_free >= MAX_TLS_LENGTHS)
         return;
      
      // setup pointers based on direction
      if (pkt.source_pkt)
      {
         current = global_offsets_side1;
      }
      else
      {
         current = global_offsets_side2;
      }
      process_paket(pkt);
   }

}
