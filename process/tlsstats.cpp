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
         DEBUG_MSG("%u ", tlsstats_data->tls_sizes[x]);
      }
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
      if ((tls_h->content_type == change_cipher_spec ||
           tls_h->content_type == alert ||
           tls_h->content_type == handshake ||
           tls_h->content_type == application_data ||
           tls_h->content_type == heartbeat ||
           tls_h->content_type == tls12_cid ||
           tls_h->content_type == ack) &&
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
         // frame presahuje takze bude niekde v nasledujucich paketoch koncit
         if (vector_index > -1 && vector_index < MAX_SEQ_NUM_TO_STORE)
         {
            // nastav seq number na dalsi paket
            current[vector_index].seq_num =
                current[vector_index].seq_num + pkt.payload_len;

            // nastav data left na pocet ktory je potrebne este PRIJAT
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
         // frame nepresahuje
         if (vector_index > -1 && vector_index < MAX_SEQ_NUM_TO_STORE)
         {
            // nastav seq number na nasledujuci paket
            current[vector_index].seq_num =
                current[vector_index].seq_num + pkt.payload_len;
            // nastav data left na 0
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

      for (uint8_t i = 0; i < *current_last_free; i++)
      {
         // zvacsi seq number pre prazdny paket ktory obsahuje SYN
         if (pkt.payload == 0 && pkt.tcp_flags & 2 && pkt.tcp_seq == current[i].seq_num)
         {
            current[i].seq_num += 1;
            return true;
         }
         // prisiel mi packet in order
         // dlzka sa pripocitava aby sme preskocili pakety pokial sa frame rozlieha
         else if (pkt.tcp_seq == current[i].seq_num +
                                     current[i].data_left)
         {
            // local offset pre tls parse
            local_offset = 0;
            // vektor index aby som vedel co aktualizovat pre overlap/no overlap
            vector_index = i;
            // pre istotu vynuluj tcp/data length
            current[i].seq_num = pkt.tcp_seq;
            current[i].data_left = 0;

            return true;
         }
         // prisiel mi paket ktory spada do okna, okno je niekolko paketov ktore by mali obsahovat
         // jeden tls ramec, v tomto pripade su dve moznosti

         // 1. tento paket je zo stredu a tls tu nekonci -- nerobim nic
         // 2. paket je hranicny a dany ramec tu konci -- zmenim seq cislo a nastavim pocet dat
         //                                              ktore este potrebujem prijat
         else if (pkt.tcp_seq >= current[i].seq_num &&
                  pkt.tcp_seq <= current[i].seq_num + current[i].data_left)
         {
            // hranicny paket, tls tu konci
            if (current[i].seq_num + current[i].data_left -
                    pkt.tcp_seq <=
                pkt.payload_len)
            {
               // dopocitaj lokalny offset
               local_offset = current[i].seq_num + current[i].data_left -
                              pkt.tcp_seq;
               // vektor index aby som vedel co aktualizovat pre overlap/no overlap
               vector_index = i;

               // pre istotu vynuluj tcp/data length
               current[i].seq_num = pkt.tcp_seq;
               current[i].data_left = 0;

               return true;
            }
            // paket zo stredu tls tu nekonci
            else
            {
               // nastav lokal offset, parsovat nieje potreba
               local_offset = pkt.payload_len;
               vector_index = -1;
               return true;
            }
         }
      }
      // return false ked sme uplne out of order, v takom pripade novy zaznam
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
         // treba vytvorit novy zaznam
         if (*current_last_free < MAX_SEQ_NUM_TO_STORE)
         {
            // vytvor par
            current[*current_last_free].seq_num = pkt.tcp_seq;
            current[*current_last_free].data_left = 0;

            // nastav vektor index na posledny prvok
            vector_index = *current_last_free;

            // increment free position
            *current_last_free += 1;
         }
         else
         {
            DEBUG_MSG("Can`t process more out of order packets, returning\n");
            // technicky tu asi nemusi byt return, akurat v check_overlap sa nic nesmie
            // aktualizovat
            return;
         }
      }

      while ((payload_start + local_offset) < payload_end)
      {
         tls_h = (tls_header *)(payload_start + local_offset);
         if (check_if_tls(tls_h))
         {
            // posun offset za header
            local_offset += sizeof(tls_header);
            // skontroluj ci tls frame "konci za koncom paketu"
            check_overlap(payload_start, payload_end, tls_h, local_offset, vector_index, pkt);
            DEBUG_MSG("FRAME LENGTH %d\n", be16toh(tls_h->length));
            if (last_free < MAX_TLS_LENGTHS)
            {
               if (pkt.source_pkt)
               {
                  tls_frames_arr[last_free].num = pkt.tcp_seq;
                  tls_frames_arr[last_free++].frame_len = be16toh(tls_h->length);
               }
               else
               {
                  tls_frames_arr[last_free].num = pkt.tcp_ack;
                  tls_frames_arr[last_free++].frame_len = be16toh(tls_h->length);
               }
            }
            else
            {
               return;
            }

            local_offset += be16toh(tls_h->length);
         }
         else
         {
            DEBUG_MSG("IF THIS HAPPENS PROBABLY INCORRECTLY USING OFFSET\n");
            local_offset++;
         }
      }
   }

   void TLSSTATSPlugin::get_data(const Packet &pkt)
   {
      if (last_free >= MAX_TLS_LENGTHS)
         return;
      if (pkt.source_pkt)
      {
         current = global_offsets_side1;
         current_last_free = &last_free1;
      }
      else
      {
         current = global_offsets_side2;
         current_last_free = &last_free2;
      }
      if (current[0].seq_num == 0 && current[0].data_left == 0)
      {
         current[0].seq_num = pkt.tcp_seq;
         current[0].data_left = 0;
         *current_last_free += 1;
      }
      process_paket(pkt);
   }

}
