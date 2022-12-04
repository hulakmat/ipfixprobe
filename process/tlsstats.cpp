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

#include <iostream>

#include "tlsstats.hpp"

namespace ipxp {

int RecordExtTLSSTATS::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("tlsstats", [](){return new TLSSTATSPlugin();});
   register_plugin(&rec);
   RecordExtTLSSTATS::REGISTERED_ID = register_extension();
}

TLSSTATSPlugin::TLSSTATSPlugin()
{
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
   RecordExtTLSSTATS *tlsstats_data = new RecordExtTLSSTATS();
   rec.add_extension(tlsstats_data);

   update_record(tlsstats_data, pkt);
   return 0;
}

int TLSSTATSPlugin::pre_update(Flow &rec, Packet &pkt)
{
   return 0;
}

int TLSSTATSPlugin::post_update(Flow &rec, const Packet &pkt)
{
   RecordExtTLSSTATS *tlsstats_data = (RecordExtTLSSTATS *) rec.get_extension(RecordExtTLSSTATS::REGISTERED_ID);
   update_record(tlsstats_data, pkt);
   
   return 0;
}

void TLSSTATSPlugin::pre_export(Flow &rec)
{
   // RecordExtTLSSTATS *tlsstats_data = (RecordExtTLSSTATS *) rec.get_extension(RecordExtTLSSTATS::REGISTERED_ID);
   // printf("index: %d\n",index);
   // for (int x = 0;x < index;x++ )
   // {
   //    printf("%d\n",be16toh(tlsstats_data->tls_headers[x].length));
   // }


   uint32_t packets = rec.src_packets + rec.dst_packets;
   if (packets <= TLSSTATS_MINLEN) { 
      rec.remove_extension(RecordExtTLSSTATS::REGISTERED_ID);
   }


}


void TLSSTATSPlugin::update_record(RecordExtTLSSTATS *tlsstats_data, const Packet &pkt)
{
   if(index >= TLSSTATS_MAXELEMCOUNT)
   {
      return;
   }
   uint64_t offset = 0;
   const uint8_t * payload_start = pkt.payload;
   const uint8_t * payload_end = pkt.payload + pkt.payload_len;

   tls_header *tls_h;
   while((payload_start + offset) < payload_end)
   {
      tls_h = (tls_header *) (payload_start + offset);
      if ((tls_h->content_type == change_cipher_spec ||
          tls_h->content_type == alert ||
          tls_h->content_type == handshake ||
          tls_h->content_type == application_data ||
          tls_h->content_type == heartbeat ||
          tls_h->content_type == tls12_cid ||
          tls_h->content_type == ack ) && ( 
          (be16toh(tls_h->version) == TLSV1) ||
          (be16toh(tls_h->version) == TLSV1DOT1) ||
          (be16toh(tls_h->version) == TLSV1DOT2) ||
          (be16toh(tls_h->version) == TLSV1DOT3)))
          {
            if(index < TLSSTATS_MAXELEMCOUNT)
            {
               tlsstats_data->tls_headers[index++] = *tls_h;
               offset += sizeof(tls_header);
               offset += be16toh(tls_h->length);
            }
            else
            {
               return;
            }
          }
          else
          {
            offset++;
          }
   }
   return;
}


}

