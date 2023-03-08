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


//#define DEBUG_TLS 

#ifdef  DEBUG_TLS
# define DEBUG_MSG(format, ...) fprintf(stderr, format, ## __VA_ARGS__)
#else
# define DEBUG_MSG(format, ...)
#endif


namespace ipxp {

void clear_tree(TCP_Tree * node)
{
   if (node->left != nullptr)
   {
      clear_tree(node->left);
   }
   if(node->right != nullptr)
   {
      clear_tree(node->right);
   }
   free(node);
   return; 
}
void print_node(TCP_Tree * node)
{
   if(node != nullptr)
   {
      print_node(node->left);
      DEBUG_MSG("---\n");
      DEBUG_MSG("SEQ: %d\n",node->seq);
      DEBUG_MSG("ACK: %d\n",node->ack);
      DEBUG_MSG("CLIENT: %d\n",node->source_pkt);
      DEBUG_MSG("TLS:");
      DEBUG_MSG("LENGTHS:"); 
      for (uint8_t x = 0; x < node->contains_tls ; x++)
      {
         DEBUG_MSG(" %d ",be16toh(node->tls_headers[x].length));
      }
      DEBUG_MSG("\nVERSIONS:"); 
      for (uint8_t x = 0; x < node->contains_tls ; x++)
      {
         DEBUG_MSG(" %02x ",node->tls_headers[x].version);
      }
      DEBUG_MSG("\nTYPES:"); 
      for (uint8_t x = 0; x < node->contains_tls ; x++)
      {
         DEBUG_MSG(" %02x ",node->tls_headers[x].content_type);
      }
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
   side_1 = nullptr;
   side_2 = nullptr;
}

TLSSTATSPlugin::~TLSSTATSPlugin()
{
   tree_size = 0;
   harvested_index = 0;
   if(tcp_tree != nullptr)
      clear_tree(tcp_tree);
   // delete side_1;
   // delete side_2;
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
void TLSSTATSPlugin::harvest_tls(TCP_Tree * node)
{
   if(node != nullptr)
   {
      harvest_tls(node->left);
      for(uint8_t x = 0 ; x < node->contains_tls ;x++)
      {
         if(harvested_index >= TLSSTATS_MAXELEMCOUNT)
         {
            return;
         }
         harvested[harvested_index++] = node->tls_headers[x];
      }
      harvest_tls(node->right);
   }
   else
   {
      return;
   }
}
void TLSSTATSPlugin::fill_data(RecordExtTLSSTATS *tlsstats_data)
{
   for(uint8_t x = 0 ; x < harvested_index ;x++)
   {
      tlsstats_data->tls_sizes[x] = be16toh(harvested[x].length);
      tlsstats_data->tls_types[x] = harvested[x].content_type;
      tlsstats_data->tls_versions[x] = harvested[x].version;
   }
}


void TLSSTATSPlugin::pre_export(Flow &rec)
{
   #ifdef  DEBUG_TLS
   DEBUG_MSG("PRINTING TCP TREE\n");
   print_node(tcp_tree);
   DEBUG_MSG("PRINTING TCP TREE DONE\n");
   #endif
   RecordExtTLSSTATS *tlsstats_data = new RecordExtTLSSTATS();
   rec.add_extension(tlsstats_data);
   harvest_tls(tcp_tree);
   fill_data(tlsstats_data);
   #ifdef  DEBUG_TLS
   DEBUG_MSG("PRINTING TLS LENGTHS\n");
   for(uint8_t x = 0 ;  x < TLSSTATS_MAXELEMCOUNT ; x++)
   {
      DEBUG_MSG(" %d ",be16toh(harvested[x].length));
   }
   DEBUG_MSG("\n");
   #endif
}

void TLSSTATSPlugin::add_node_stats(TCP_Tree * where,const Packet &pkt)
{
   where->seq = pkt.tcp_seq;
   where->ack = pkt.tcp_ack;
   where->source_pkt = pkt.source_pkt;
   where->contains_tls = 0;
   where->left = nullptr;
   where->right = nullptr;
}
void TLSSTATSPlugin::add_tls_node_stats(TCP_Tree * where,const Packet &pkt)
{
   uint64_t offset;
   if(global_offsets[pkt.src_port] == 0){
      offset = 0;
   }else{
      if (global_offsets[pkt.src_port] - pkt.payload_len >= 0){
         global_offsets[pkt.src_port] = global_offsets[pkt.src_port] - pkt.payload_len;
         return;
      }else{
         offset = global_offsets[pkt.src_port];
         global_offsets[pkt.src_port] = 0;
      }
   }
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
            if(where->contains_tls < TLS_FRAMES_PER_PKT)
            {
               where->tls_headers[where->contains_tls++] = *tls_h;
               offset += sizeof(tls_header);
               if ((payload_start + be16toh(tls_h->length)) > payload_end)
               {
                  // frame presahuje takze bude niekde v nasledujucich paketoch
                  global_offsets[pkt.src_port] = be16toh(tls_h->length) - (payload_end - (payload_start + offset));
               }
               else if ((payload_start + be16toh(tls_h->length)) == payload_end)
               {
                  // frame nepresahuje
                  global_offsets[pkt.src_port] = 0;
               }
               offset += be16toh(tls_h->length);

            }
            else
            {
               return;
            }
          }
          else
          {
            // idealne by tato moznost nastat nemala, ale musime incrementovat
            // aby cyklus skoncil v pripade ze nastane
            offset++;
          }
   }
   return;
}

void TLSSTATSPlugin::add_tree_node(const Packet &pkt)
{
   if(tcp_tree == nullptr)
   {
      tcp_tree = (TCP_Tree*)malloc(sizeof(TCP_Tree));
      add_node_stats(tcp_tree,pkt);
      add_tls_node_stats(tcp_tree,pkt);
   }
   else
   {
      TCP_Tree * tmp = tcp_tree;
      while(1)
      {
         //porovnava sa pkt seq a node seq
         //porovnava sa pkt seq a node ack
         //porovnava sa pkt ack a node seq
         //porovnava sa pkt ack a node ack
         if ((pkt.source_pkt && tmp->source_pkt && pkt.tcp_seq < tmp->seq) ||
             (pkt.source_pkt && !tmp->source_pkt && pkt.tcp_seq < tmp->ack) ||
             (!pkt.source_pkt && tmp->source_pkt && pkt.tcp_ack < tmp->seq) ||
             (!pkt.source_pkt && !tmp->source_pkt && pkt.tcp_ack < tmp->ack) )
         {
            if (tmp->left != nullptr)
               tmp = tmp->left;
            else
            {
               tmp->left = (TCP_Tree*)malloc(sizeof(TCP_Tree));
               add_node_stats(tmp->left,pkt);
               add_tls_node_stats(tmp->left,pkt);
               break;
            }
         }
         // else if ((pkt.source_pkt && tmp->source_pkt && pkt.tcp_seq >= tmp->seq) || 
         //          (pkt.source_pkt && !tmp->source_pkt && pkt.tcp_seq >= tmp->ack) ||
         //          (!pkt.source_pkt && tmp->source_pkt && pkt.tcp_ack >= tmp->seq) ||
         //          (!pkt.source_pkt && !tmp->source_pkt && pkt.tcp_ack >= tmp->ack) )
         else
         {
            if (tmp->right != nullptr)
               tmp = tmp->right;
            else
            {
               tmp->right = (TCP_Tree*)malloc(sizeof(TCP_Tree));
               add_node_stats(tmp->right,pkt);
               add_tls_node_stats(tmp->right,pkt);
               break;
            }
         }
      }
   }
}
void TLSSTATSPlugin::get_data(const Packet &pkt)
{
   if(global_offsets.find(pkt.src_port) == global_offsets.end())
      global_offsets[pkt.src_port] = 0;
   if(tree_size < TCP_MAX_TREE_SIZE)
      add_tree_node(pkt);
   
   // if(!side_1){
   //    side_1 = new side;
   //    side_1->port = pkt.src_port;
   //    side_1->last_ack = pkt.tcp_ack;
   //    side_1->last_seq = pkt.tcp_seq;
   // }else if (side_1->port == pkt.src_port){
   //    printf("ack diff ---> %u\n",pkt.tcp_ack-side_1->last_ack);
   //    //printf("seq diff ---> %u\n",pkt.tcp_seq-side_1->last_seq);
      
   //    side_1->last_ack = pkt.tcp_ack;
   //    side_1->last_seq = pkt.tcp_seq;
   // }
   // else if (!side_2){
   //    side_2 = new side;
   //    side_2->port = pkt.src_port;
   //    side_2->last_ack = pkt.tcp_ack;
   //    side_2->last_seq = pkt.tcp_seq;
   // }else if (side_2->port == pkt.src_port){
   //    printf("ack diff <--- %u\n",pkt.tcp_ack-side_2->last_ack); 
   //    //printf("seq diff <--- %u\n",pkt.tcp_seq-side_2->last_seq);
      
   //    side_2->last_ack = pkt.tcp_ack;
   //    side_2->last_seq = pkt.tcp_seq;
   // }
}


}

