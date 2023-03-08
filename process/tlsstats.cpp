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


// #define DEBUG_TLS 

#ifdef  DEBUG_TLS
# define DEBUG_MSG(format, ...) fprintf(stderr, format, ## __VA_ARGS__)
#else
# define DEBUG_MSG(format, ...)
#endif


namespace ipxp {
void print_node(TLS_Lengths * node)
{
   if(node != nullptr)
   {
      print_node(node->left);
      DEBUG_MSG("---\n");
      DEBUG_MSG("SEQ: %u\n",node->seq);
      DEBUG_MSG("ACK: %u\n",node->ack);
      DEBUG_MSG("CLIENT: %d\n",node->source_pkt);
      DEBUG_MSG("TLS:");
      DEBUG_MSG("LENGTHS:"); 
      DEBUG_MSG(" %d ",node->tls_size);
      DEBUG_MSG("\n");
      print_node(node->right);
   }
   else
   {
      return;
   }
}

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
void clear_tree(TLS_Lengths * node)
{
   if (node->left != nullptr)
   {
      clear_tree(node->left);
   }
   if(node->right != nullptr)
   {
      clear_tree(node->right);
   }
   delete node;
   return; 
}
TLSSTATSPlugin::~TLSSTATSPlugin()
{
   total_tls_count = 0;
   harvested_index = 0;
   if(tls_tree != nullptr)
      clear_tree(tls_tree);
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
void TLSSTATSPlugin::fill_data(TLS_Lengths * node,RecordExtTLSSTATS *tlsstats_data)
{
   if(node != nullptr)
   {
      fill_data(node->left,tlsstats_data);
      tlsstats_data->tls_sizes[harvested_index++] = node->tls_size;
      fill_data(node->right,tlsstats_data);
   }
   else
   {
      return;
   }
}

void TLSSTATSPlugin::pre_export(Flow &rec)
{
   #ifdef  DEBUG_TLS
   DEBUG_MSG("PRINTING TLS LENGTHS TREE\n");
   print_node(tls_tree);
   DEBUG_MSG("PRINTING TLS LENGTHS TREE DONE\n");
   #endif
   
   
   
   RecordExtTLSSTATS *tlsstats_data = new RecordExtTLSSTATS();
   rec.add_extension(tlsstats_data);
   fill_data(tls_tree,tlsstats_data);


   #ifdef  DEBUG_TLS
   DEBUG_MSG("PRINTING TLS LENGTHS AS TLS_DATA\n");
   for(uint8_t x = 0 ;  x < MAX_TLS_LENGTHS ; x++)
   {
      DEBUG_MSG(" %d ",tlsstats_data->tls_sizes[x]);
   }
   DEBUG_MSG("\n");
   #endif
}

void TLSSTATSPlugin::add_node_stats(TLS_Lengths * where,const Packet &pkt, uint16_t tls_size)
{
   where->seq = pkt.tcp_seq;
   where->ack = pkt.tcp_ack;
   where->source_pkt = pkt.source_pkt;
   where->left = nullptr;
   where->right = nullptr;
   where->tls_size = tls_size;
   total_tls_count++;
}
bool TLSSTATSPlugin::check_global_offset(uint16_t & offset,const Packet &pkt)
{
   if(global_offsets[pkt.src_port] == 0){
      offset = 0;
      return true;
   }else{
      if (global_offsets[pkt.src_port] - pkt.payload_len >= 0){
         global_offsets[pkt.src_port] = global_offsets[pkt.src_port] - pkt.payload_len;
         return false;
      }else{
         offset = global_offsets[pkt.src_port];
         global_offsets[pkt.src_port] = 0;
         return true;
      }
   }
}

bool TLSSTATSPlugin::check_if_tls(tls_header * tls_h)
{
   if (( tls_h->content_type == change_cipher_spec ||
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
         return true;
   return false;
}

void TLSSTATSPlugin::check_overlap(const uint8_t * payload_start,const uint8_t * payload_end,
                  tls_header * tls_h, uint16_t offset,const Packet &pkt)
{
   if ((payload_start + be16toh(tls_h->length)) > payload_end)
   {
      // frame presahuje takze bude niekde v nasledujucich paketoch koncit
      global_offsets[pkt.src_port] = be16toh(tls_h->length) - (payload_end - (payload_start + offset));
   }
   else if ((payload_start + be16toh(tls_h->length)) == payload_end)
   {
      // frame nepresahuje
      global_offsets[pkt.src_port] = 0;
   }
}

bool go_left(const Packet &pkt,TLS_Lengths * tmp)
{
   if((pkt.source_pkt && tmp->source_pkt && pkt.tcp_seq < tmp->seq) ||
      (pkt.source_pkt && !tmp->source_pkt && pkt.tcp_seq < tmp->ack) ||
      (!pkt.source_pkt && tmp->source_pkt && pkt.tcp_ack < tmp->seq) ||
      (!pkt.source_pkt && !tmp->source_pkt && pkt.tcp_ack < tmp->ack) )
      return true;
   return false;
}

void TLSSTATSPlugin::add_tree_node(const Packet &pkt)
{
   const uint8_t * payload_start = pkt.payload;
   const uint8_t * payload_end = pkt.payload + pkt.payload_len;
   uint16_t offset = 0;

   tls_header *tls_h = nullptr;
   TLS_Lengths *where = nullptr;



   if(tls_tree == nullptr)
   {
      if(!check_global_offset(offset,pkt))
      {
         return;
      }
      while((payload_start + offset) < payload_end)
      {
         tls_h = (tls_header *) (payload_start + offset);
         if (check_if_tls(tls_h))
         {
            if(total_tls_count < MAX_TLS_LENGTHS)
            {
               if(!tls_tree){
                  tls_tree = new TLS_Lengths;
                  add_node_stats(tls_tree,pkt,be16toh(tls_h->length));
                  where = tls_tree;
               }else{
                  where->right = new TLS_Lengths;
                  where = where->right;
                  add_node_stats(where,pkt,be16toh(tls_h->length));
               }
                  
               offset += sizeof(tls_header);
               check_overlap(payload_start,payload_end,tls_h,offset,pkt);
               offset += be16toh(tls_h->length);
            }
            else
            {
               return;
            }
         }
         else
         {
            DEBUG_MSG("IF THIS HAPPENS PROBABLY INCORRECTLY USING OFFSET\n");
            offset++;
         }
      }
      return;
   }
   else
   {
      TLS_Lengths * tmp = tls_tree;
      while(1)
      {
         if (go_left(pkt,tmp))
         {
            if (tmp->left != nullptr)
            {
               tmp = tmp->left;
               continue;
            }
            else
            {
               if(!check_global_offset(offset,pkt))
                  return;
               while((payload_start + offset) < payload_end)
               {
                  tls_h = (tls_header *) (payload_start + offset);
                  if (check_if_tls(tls_h))
                     {
                        if(total_tls_count < MAX_TLS_LENGTHS)
                        {
                           if (!tmp->left)
                           {
                              tmp->left = new TLS_Lengths;
                              add_node_stats(tmp->left,pkt,be16toh(tls_h->length));
                              where = tmp->left;
                           }else{
                              where->right = new TLS_Lengths;
                              where = where->right;
                              add_node_stats(where,pkt,be16toh(tls_h->length));
                           }
                           offset += sizeof(tls_header);
                           check_overlap(payload_start,payload_end,tls_h,offset,pkt);
                           offset += be16toh(tls_h->length);

                        }
                        else
                        {
                           return;
                        }
                     }
                     else
                     {
                        DEBUG_MSG("IF THIS HAPPENS PROBABLY INCORRECTLY USING OFFSET\n");
                        offset++;
                     }
               }
               return;
            }
         }
         else
         {
            if (tmp->right != nullptr)
            {
               tmp = tmp->right;
               continue;
            }
            else
            {
               if(!check_global_offset(offset,pkt))
               {
                  return;
               }
               while((payload_start + offset) < payload_end)
               {
                  tls_h = (tls_header *) (payload_start + offset);
                  if (check_if_tls(tls_h))
                  {
                     if(total_tls_count < MAX_TLS_LENGTHS)
                     {
                        if (!tmp->right)
                        {
                           tmp->right = new TLS_Lengths;
                           add_node_stats(tmp->right,pkt,be16toh(tls_h->length));
                           where = tmp->right;
                        }else{
                           where->right = new TLS_Lengths;
                           where = where->right;
                           add_node_stats(where,pkt,be16toh(tls_h->length));
                        }
                        offset += sizeof(tls_header);
                        check_overlap(payload_start,payload_end,tls_h,offset,pkt);
                        offset += be16toh(tls_h->length);
                     }
                     else
                     {
                        return;
                     }
                  }
                  else
                  {
                     DEBUG_MSG("IF THIS HAPPENS PROBABLY INCORRECTLY USING OFFSET\n");
                     offset++;
                  }
               }
               return;
            }
         }
      }
   }
}
void TLSSTATSPlugin::get_data(const Packet &pkt)
{
   if(global_offsets.find(pkt.src_port) == global_offsets.end())
      global_offsets[pkt.src_port] = 0;
   if(total_tls_count < MAX_TLS_LENGTHS)
      add_tree_node(pkt);

}


}

