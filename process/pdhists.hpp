/**
 * \file pdhists.hpp
 * \brief Plugin for parsing pdhists traffic.
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
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
 *
 *
 */

#ifndef IPXP_PROCESS_PDHISTS_HPP
#define IPXP_PROCESS_PDHISTS_HPP

#include <string>
#include <limits>
#include <sstream>

#ifdef WITH_NEMEA
# include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-basiclist.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp {


//#define PDHISTS_DEBUG_ENABLE
#ifdef PDHISTS_DEBUG_ENABLE
#define PDHISTS_DEBUG_RAW(x) std::cerr << x
#define PDHISTS_DEBUG(x) PDHISTS_DEBUG_RAW(x) << std::endl
#else
#define PDHISTS_DEBUG(x)
#define PDHISTS_DEBUG_RAW(x) 
#endif

#ifndef PDHISTS_MINLEN
# define PDHISTS_MINLEN 1
#endif

/* Offset == 0, Size == 8
 * 0-2      1. bin
 * 3-4      2. bin
 * 5-7     3. bin
 * 8-15    4. bin
 * 16-31    5. bin
 * 32-63   6. bin
 * 64-127  7. bin
 * 128-255  8. bin
 */
/* Offset == 2, Size == 8
 * 0-15     1. bin
 * 16-31    2. bin
 * 32-63    3. bin
 * 64-127   4. bin
 * 128-255  5. bin
 * 256-511  6. bin
 * 512-1023 7. bin
 * 1024 >   8. bin
 */
#define HISTOGRAM_OFFSET 0
#define HISTOGRAM_SIZE 10


/* Last bin larger than 1ms */
#define HISTOGRAM_IPT_OFFSET 0
#define HISTOGRAM_IPT_SIZE 20

#define PDHISTS_UNIREC_TEMPLATE "S_PDHISTS_CHAN,D_PDHISTS_CHAN,B_PDHISTS_CHAN,S_PDHISTS_INTF,D_PDHISTS_INTF,B_PDHISTS_INTF,S_PDHISTS_STORE,D_PDHISTS_STORE,B_PDHISTS_STORE,S_PTHISTS,D_PTHISTS,B_PTHISTS"
UR_FIELDS(
    uint32* S_PDHISTS_CHAN,
    uint32* D_PDHISTS_CHAN,
    uint32* B_PDHISTS_CHAN,
    uint32* S_PDHISTS_INTF,
    uint32* D_PDHISTS_INTF,
    uint32* B_PDHISTS_INTF,
    uint32* S_PDHISTS_STORE,
    uint32* D_PDHISTS_STORE,
    uint32* B_PDHISTS_STORE,
    uint32* S_PTHISTS,
    uint32* D_PTHISTS,
    uint32* B_PTHISTS
)

class PDHISTSOptParser : public OptionsParser
{
public:
   bool m_include_zeroes;

   PDHISTSOptParser() : OptionsParser("pdhists", "Processing plugin for packet distance histograms"), m_include_zeroes(false)
   {
      register_option("i", "includezeroes", "", "Include zero payload packets", [this](const char *arg){m_include_zeroes = true; return true;}, OptionFlags::NoArgument);
   }
};

/**
 * \brief Flow record extension header for storing parsed PDHISTS packets.
 */
struct RecordExtPDHISTS : public RecordExt {
   static const uint64_t dist_hist_empty_val; 
   static int REGISTERED_ID;

   typedef enum eHdrFieldID {
       SPdhistsChan = 1080,
       DPdhistsChan = 1081,
       BPdhistsChan = 1082,
       SPdhistsIntf = 1083,
       DPdhistsIntf = 1084,
       BPdhistsIntf = 1085,
       SPdhistsStore = 1086,
       DPdhistsStore = 1087,
       BPdhistsStore = 1088,
       SPthistsStore = 1086,
       DPthistsStore = 1087,
       BPthistsStore = 1088,
   } eHdrSemantic;
   
   uint32_t dist_hist_chan[3][HISTOGRAM_SIZE];
   uint32_t dist_hist_intf[3][HISTOGRAM_SIZE];
   uint32_t dist_hist_store[3][HISTOGRAM_SIZE];
   uint32_t ipt_hist[3][HISTOGRAM_IPT_SIZE];
   uint64_t last_pkt_index_channel[3];
   uint64_t last_pkt_index_intf[3];
   uint64_t last_pkt_index_store[3];
   struct PacketTimeval last_pkt_time[3];

   RecordExtPDHISTS() : RecordExt(REGISTERED_ID)
   {
      PDHISTS_DEBUG("Records create");
      // inicializing histograms with zeros
      for (int i = 0; i < 3; i++) {
          for (int z = 0; z < HISTOGRAM_SIZE; z++) {
            memset(dist_hist_chan[i], 0, sizeof(uint32_t) * HISTOGRAM_SIZE);
            memset(dist_hist_intf[i], 0, sizeof(uint32_t) * HISTOGRAM_SIZE);
            memset(dist_hist_store[i], 0, sizeof(uint32_t) * HISTOGRAM_SIZE);
            memset(ipt_hist[i], 0, sizeof(uint32_t) * HISTOGRAM_IPT_SIZE);
          }
         last_pkt_index_channel[i] = dist_hist_empty_val;
         last_pkt_index_intf[i] = dist_hist_empty_val;
         last_pkt_index_store[i] = dist_hist_empty_val;
         memset(&last_pkt_time[i], 0, sizeof(PacketTimeval));
      }
   }

   #ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      PDHISTS_DEBUG("Fill Unirec");
      ur_array_allocate(tmplt, record, F_S_PDHISTS_CHAN, HISTOGRAM_SIZE);
      ur_array_allocate(tmplt, record, F_D_PDHISTS_CHAN, HISTOGRAM_SIZE);
      ur_array_allocate(tmplt, record, F_B_PDHISTS_CHAN, HISTOGRAM_SIZE);
      ur_array_allocate(tmplt, record, F_S_PDHISTS_INTF, HISTOGRAM_SIZE);
      ur_array_allocate(tmplt, record, F_D_PDHISTS_INTF, HISTOGRAM_SIZE);
      ur_array_allocate(tmplt, record, F_B_PDHISTS_INTF, HISTOGRAM_SIZE);
      ur_array_allocate(tmplt, record, F_S_PDHISTS_STORE, HISTOGRAM_SIZE);
      ur_array_allocate(tmplt, record, F_D_PDHISTS_STORE, HISTOGRAM_SIZE);
      ur_array_allocate(tmplt, record, F_B_PDHISTS_STORE, HISTOGRAM_SIZE);
      ur_array_allocate(tmplt, record, F_S_PTHISTS, HISTOGRAM_IPT_SIZE);
      ur_array_allocate(tmplt, record, F_B_PTHISTS, HISTOGRAM_IPT_SIZE);
      ur_array_allocate(tmplt, record, F_D_PTHISTS, HISTOGRAM_IPT_SIZE);
      
      for (int i = 0; i < HISTOGRAM_SIZE; i++) {
         ur_array_set(tmplt, record, F_S_PDHISTS_CHAN, i, dist_hist_chan[0][i]);
         ur_array_set(tmplt, record, F_D_PDHISTS_CHAN, i, dist_hist_chan[1][i]);
         ur_array_set(tmplt, record, F_B_PDHISTS_CHAN, i, dist_hist_chan[2][i]);
         
         ur_array_set(tmplt, record, F_S_PDHISTS_INTF, i, dist_hist_intf[0][i]);
         ur_array_set(tmplt, record, F_D_PDHISTS_INTF, i, dist_hist_intf[1][i]);
         ur_array_set(tmplt, record, F_B_PDHISTS_INTF, i, dist_hist_intf[2][i]);
         
         ur_array_set(tmplt, record, F_S_PDHISTS_INTF, i, dist_hist_store[0][i]);
         ur_array_set(tmplt, record, F_D_PDHISTS_INTF, i, dist_hist_store[1][i]);
         ur_array_set(tmplt, record, F_B_PDHISTS_INTF, i, dist_hist_store[2][i]);
         
         ur_array_set(tmplt, record, F_S_PTHISTS, i, ipt_hist[0][i]);
         ur_array_set(tmplt, record, F_D_PTHISTS, i, ipt_hist[1][i]);
         ur_array_set(tmplt, record, F_B_PTHISTS, i, ipt_hist[2][i]);
      }
   }

   const char *get_unirec_tmplt() const
   {
      return PDHISTS_UNIREC_TEMPLATE;
   }
   #endif // ifdef WITH_NEMEA

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      int32_t bufferPtr;
      IpfixBasicList basiclist;
      PDHISTS_DEBUG("Ipfix Fill");

      basiclist.hdrEnterpriseNum = IpfixBasicList::CesnetPEM;
      // Check sufficient size of buffer
      int req_size = 9 * basiclist.HeaderSize()  /* sizes, times, flags, dirs */
        + 9 * HISTOGRAM_SIZE * sizeof(uint32_t); /* sizes */

      if (req_size > size) {
         return -1;
      }
      // Fill sizes
      // fill buffer with basic list header and SPdhistsSizes
      bufferPtr  = basiclist.FillBuffer(buffer, dist_hist_chan[0], HISTOGRAM_SIZE, (uint32_t) SPdhistsChan);
      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, dist_hist_chan[1], HISTOGRAM_SIZE, (uint32_t) DPdhistsChan);
      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, dist_hist_chan[2], HISTOGRAM_SIZE, (uint32_t) BPdhistsChan);
      
      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, dist_hist_intf[0], HISTOGRAM_SIZE, (uint32_t) SPdhistsIntf);
      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, dist_hist_intf[1], HISTOGRAM_SIZE, (uint32_t) DPdhistsIntf);
      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, dist_hist_intf[2], HISTOGRAM_SIZE, (uint32_t) BPdhistsIntf);
      
      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, dist_hist_store[0], HISTOGRAM_SIZE, (uint32_t) SPdhistsIntf);
      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, dist_hist_store[1], HISTOGRAM_SIZE, (uint32_t) DPdhistsIntf);
      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, dist_hist_store[2], HISTOGRAM_SIZE, (uint32_t) BPdhistsIntf);
      
      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, ipt_hist[0], HISTOGRAM_IPT_SIZE, (uint32_t) SPthistsStore);
      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, ipt_hist[1], HISTOGRAM_IPT_SIZE, (uint32_t) DPthistsStore);
      bufferPtr += basiclist.FillBuffer(buffer + bufferPtr, ipt_hist[2], HISTOGRAM_IPT_SIZE, (uint32_t) BPthistsStore);

      return bufferPtr;
   } // fill_ipfix

   const char **get_ipfix_tmplt() const
   {
      PDHISTS_DEBUG("Get Template");
      static const char *ipfix_tmplt[] = {
          IPFIX_PDHISTS_TEMPLATE(IPFIX_FIELD_NAMES)
          nullptr
      };

      return ipfix_tmplt;
   }

   std::string get_text() const
   {
      std::ostringstream out;
      PDHISTS_DEBUG("Get Text");
      char dirs_c[] = {'s', 'd', 'b'};
      
      for (size_t dir = 0; dir < sizeof(dirs_c); dir++) {
         out << dirs_c[dir] << "pdhistchan=(";
         for (size_t i = 0; i < HISTOGRAM_SIZE; i++) {
            out << dist_hist_chan[dir][i];
            if (i != HISTOGRAM_SIZE - 1) {
               out << ",";
            }
         }
         out << ")," << dirs_c[dir] << "pdhistintf=(";
         for (size_t i = 0; i < HISTOGRAM_SIZE; i++) {
            out << dist_hist_intf[dir][i];
            if (i != HISTOGRAM_SIZE - 1) {
               out << ",";
            }
         }
         out << ")," << dirs_c[dir] << "pdhiststore=(";
         for (size_t i = 0; i < HISTOGRAM_SIZE; i++) {
            out << dist_hist_store[dir][i];
            if (i != HISTOGRAM_SIZE - 1) {
               out << ",";
            }
         }
         out << ")," << dirs_c[dir] << "pthist=(";
         for (size_t i = 0; i < HISTOGRAM_IPT_SIZE; i++) {
            out << ipt_hist[dir][i];
            if (i != HISTOGRAM_IPT_SIZE - 1) {
               out << ",";
            }
         }
         out << "),";
      }
      return out.str();
   }
};

/**
 * \brief Flow store plugin for parsing PDHISTS packets.
 */
class PDHISTSPlugin : public ProcessPlugin
{
public:
   PDHISTSPlugin();
   ~PDHISTSPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new PDHISTSOptParser(); }
   std::string get_name() const { return "pdhists"; }
   RecordExt *get_ext() const { return new RecordExtPDHISTS(); }
   ProcessPlugin *copy();

   int post_create(Flow &rec, const Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);

private:
   bool use_zeros;

   void update_record(RecordExtPDHISTS *pdhists_data, const Packet &pkt);
   void update_hist(uint32_t value, uint32_t *histogram, size_t hist_offset, size_t hist_size);
   void pre_export(Flow &rec);
   uint64_t calculate_packet_dst(uint64_t ind, uint64_t last_val);
   uint64_t calculate_packet_ipt(const ipxp::PacketTimeval &val, const ipxp::PacketTimeval last_val);

   static const uint32_t log2_lookup32[32];

   static inline uint32_t fastlog2_32(uint32_t value)
   {
      value |= value >> 1;
      value |= value >> 2;
      value |= value >> 4;
      value |= value >> 8;
      value |= value >> 16;
      return log2_lookup32[(uint32_t) (value * 0x07C4ACDD) >> 27];
   }

   static inline uint32_t no_overflow_increment(uint32_t value)
   {
      if (value == std::numeric_limits<uint32_t>::max()) {
         return value;
      }
      return value + 1;
   }

};

}
#endif /* IPXP_PROCESS_PDHISTS_HPP */
