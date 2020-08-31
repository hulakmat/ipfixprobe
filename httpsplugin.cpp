/**
 * \file httpsplugin.cpp
 * \brief Plugin for parsing https traffic.
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2018
 */
/*
 * Copyright (C) 2018 CESNET
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
#include <sstream>

#include <stdio.h>

#include "httpsplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-elements.h"
#include "md5.h"

#define DEBUG_HTTPS

// Print debug message if debugging is allowed.
#ifdef DEBUG_HTTPS
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

using namespace std;

#define HTTPS_UNIREC_TEMPLATE "HTTPS_SNI"

UR_FIELDS (
   string HTTPS_SNI
)

HTTPSPlugin::HTTPSPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
   parsed_sni = 0;
   total = 0;
   flow_flush = false;
   ext_ptr = NULL;
}

HTTPSPlugin::HTTPSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
   parsed_sni = 0;
   total = 0;
   flow_flush = false;
   ext_ptr = NULL;
}
HTTPSPlugin::~HTTPSPlugin()
{
   if (ext_ptr != NULL) {
      delete ext_ptr;
   }
}

int HTTPSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   if (rec.src_port == 443 || rec.dst_port == 443) {
      add_https_record(rec, pkt);
   }

   return 0;
}

int HTTPSPlugin::pre_update(Flow &rec, Packet &pkt)
{
   if (rec.src_port == 443 || rec.dst_port == 443) {
      RecordExt *ext = rec.getExtension(https);
      if (ext != NULL) {
         return 0;
      }
      add_https_record(rec, pkt);
   }

   return 0;
}

bool HTTPSPlugin::parse_sni(const char *data, int payload_len, RecordExtHTTPS *rec)
{
   payload_data payload = {
      (char *) data,
      data + payload_len,
      true,
      0
   };
   tls_rec *tls = (tls_rec *) payload.data;

   total++;

   if (payload_len - sizeof(tls_rec) < 0 || tls->type != TLS_HANDSHAKE ||
       tls->version.major != 3 || tls->version.minor > 3) {
      return false;
   }
   payload.data += sizeof(tls_rec);

   tls_handshake *tls_hs = (tls_handshake *) payload.data;
   if (payload.data + sizeof(tls_handshake) > payload.end || tls_hs->type != TLS_HANDSHAKE_CLIENT_HELLO) {
      return false;
   }

   uint32_t hs_len = tls_hs->length1 << 16 | ntohs(tls_hs->length2);
   if (payload.data + hs_len > payload.end || tls_hs->version.major != 3 ||
       tls_hs->version.minor < 1 || tls_hs->version.minor > 3) {
      return false;
   }
   payload.data += sizeof(tls_handshake);

   stringstream ja3;
   ja3 << (uint16_t) tls_hs->version.version << ',';

   payload.data += 32;          // Skip random

   int tmp = *(uint8_t *) payload.data;
   if (payload.data + tmp + 2 > payload.end) {
      return false;
   }
   payload.data += tmp + 1;     // Skip session id

   get_ja3_cipher_suites(ja3, payload);
   if (!payload.valid) {
      return false;
   }

   tmp = *(uint8_t *) payload.data;
   if (payload.data + tmp + 2 > payload.end) {
      return false;
   }
   payload.data += tmp + 1;     // Skip compression methods

   const char *ext_end = payload.data + ntohs(*(uint16_t *) payload.data);
   payload.data += 2;

   if (ext_end > payload.end) {
      return false;
   }

   string ecliptic_curves;
   string ec_point_formats;

   while (payload.data + sizeof(tls_ext) <= ext_end) {
      tls_ext *ext = (tls_ext *) payload.data;
      uint16_t length = ntohs(ext->length);
      uint16_t type = ntohs(ext->type);

      payload.data += sizeof(tls_ext);
      if (type == TLS_EXT_SERVER_NAME) {
         get_tls_server_name(payload, rec);
      } else if (type == TLS_EXT_ECLIPTIC_CURVES) {
         ecliptic_curves = get_ja3_ecpliptic_curves(payload, rec);
      } else if (type == TLS_EXT_EC_POINT_FORMATS) {
         ec_point_formats = get_ja3_ec_point_formats(payload, rec);
      }

      if (!payload.valid) {
         return false;
      }

      ja3 << type;

      payload.data += length;
      if (payload.data + sizeof(tls_ext) <= ext_end) {
         ja3 << '-';
      }
   }

   ja3 << ',' << ecliptic_curves << ',' << ec_point_formats;
   DEBUG_MSG("%s\n", ja3.str().c_str());
   DEBUG_MSG("%s\n", md5(ja3.str()).c_str());

   return payload.sni_parsed != 0;
}

void HTTPSPlugin::get_ja3_cipher_suites(stringstream &ja3, payload_data &data)
{
   int cipher_suites_length = ntohs(*(uint16_t *) data.data);
   const char* section_end = data.data + cipher_suites_length;

   if (data.data + cipher_suites_length + 1 > data.end) {
      data.valid = false;
      return;
   }
   data.data += 2;

   for (; data.data <= section_end; data.data += 2) {
      ja3 << ntohs(*(uint16_t *) (data.data));
      if (data.data < section_end) {
         ja3 << '-';
      }
   }
   ja3 << ',';
}

void HTTPSPlugin::get_tls_server_name(payload_data &data, RecordExtHTTPS *rec)
{
   uint16_t list_len = ntohs(*(uint16_t *) data.data);
   uint16_t offset = sizeof(list_len);
   const char *list_end = data.data + list_len + offset;

   if (list_end > data.end) {
      data.valid = false;
      return;
   }

   while (data.data + sizeof(tls_ext_sni) + offset < list_end) {
      tls_ext_sni *sni = (tls_ext_sni *) (data.data + offset);
      uint16_t sni_len = ntohs(sni->length);

      offset += sizeof(tls_ext_sni);
      if (data.data + offset + ntohs(sni->length) > list_end) {
         break;
      }
      if (rec->sni[0] != 0) {
         RecordExtHTTPS *tmp_rec = new RecordExtHTTPS();
         rec->next = tmp_rec;
         rec = tmp_rec;
      }
      memcpy(rec->sni, data.data + offset, sni_len);
      rec->sni[sni_len] = 0;
      data.sni_parsed++;
      parsed_sni++;
   }
}

string HTTPSPlugin::get_ja3_ecpliptic_curves(payload_data &data, RecordExtHTTPS *rec)
{
   stringstream collected_types;
   uint16_t list_len = ntohs(*(uint16_t *) data.data);
   const char *list_end = data.data + list_len + sizeof(list_len);
   uint16_t offset = sizeof(list_len);

   if (list_end > data.end) {
      data.valid = false;
      return "";
   }

   while (data.data + sizeof(uint16_t) + offset <= list_end) {
      collected_types << ntohs(*(uint16_t *) (data.data + offset));
      offset += sizeof(uint16_t);
      if (data.data + sizeof(uint16_t) + offset <= list_end) {
         collected_types << '-';
      }
   }
   return collected_types.str();
}

string HTTPSPlugin::get_ja3_ec_point_formats(payload_data &data, RecordExtHTTPS *rec)
{
   stringstream collected_formats;
   uint8_t list_len = *data.data;
   uint16_t offset = sizeof(list_len);
   const char *list_end = data.data + list_len + offset;
   uint8_t format;

   if (list_end > data.end) {
      data.valid = false;
      return "";
   }

   while (data.data + sizeof(uint8_t) + offset <= list_end) {
      format = *(data.data + offset);
      collected_formats << (int) format;
      offset += sizeof(uint8_t);
      if (data.data + sizeof(uint8_t) + offset <= list_end) {
         collected_formats << '-';
      }
   }
   return collected_formats.str();
}

void HTTPSPlugin::add_https_record(Flow &rec, const Packet &pkt)
{
   if (ext_ptr == NULL) {
      ext_ptr = new RecordExtHTTPS();
   }

   if (parse_sni(pkt.payload, pkt.payload_length, ext_ptr)) {
      rec.addExtension(ext_ptr);
      ext_ptr = NULL;
   }
}

void HTTPSPlugin::finish()
{
   if (print_stats) {
      cout << "HTTPS plugin stats:" << endl;
      cout << "   Total HTTPS packets seen: " << total << endl;
      cout << "   Parsed SNI: " << parsed_sni << endl;
   }
}

const char *ipfix_https_template[] = {
   IPFIX_HTTPS_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **HTTPSPlugin::get_ipfix_string()
{
   return ipfix_https_template;
}

string HTTPSPlugin::get_unirec_field_string()
{
   return HTTPS_UNIREC_TEMPLATE;
}

bool HTTPSPlugin::include_basic_flow_fields()
{
   return true;
}
