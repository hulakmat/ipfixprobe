/**
 * \file fragmentCache.hpp
 * \brief Cache for fragmented packets
 * \author Jakub Antonín Štigler xstigl00@xstigl00@stud.fit.vut.cz
 * \date 2023
 */
/*
 * Copyright (C) 2023 CESNET
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

#ifndef IPXP_STORAGE_FRAGMENTATION_CACHE_FRAGMENT_CACHE
#define IPXP_STORAGE_FRAGMENTATION_CACHE_FRAGMENT_CACHE

// the default value for max number of fragmented packets

#include "flat_hash_map.hpp"

#include <cstdint>
#include <vector>
#include <cstring>
#include <chrono>

#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipaddr.hpp>

namespace ipxp
{

class FragmentCache {
public:
   FragmentCache(timeval timeout) : keys(), buffer(), timeout(timeout) {}

   FragmentCache() : FragmentCache(timeval{ .tv_sec = 2 }) {}

   /**
    * @brief If the packet is fragmented, add it to cache or fill the missing info from chace
    *
    * @return true if the packet is fragmented
    */
   inline bool cache_packet(Packet &pkt) {
      // packet is fragmented if 'frag_off != 0 || more_fragments'
      // only the first fragment has always 'frag_off == 0 && more_fragments'
      if (pkt.frag_off == 0) {
         if (!pkt.more_fragments) {
            return false;
         }

         add_packet(pkt);
         return true;
      }

      // if fill_info returns false, this packet fragment came before
      // the first fragment
      fill_info(pkt);
      return true;
   }
private:
   // private types
   struct __attribute__((packed)) Key {
      // IP::v4 / IP::v6, 16-bit value only to align the struct size to 40
      uint16_t ipv;

      uint16_t vlan_id;
      uint32_t frag_id;

      // when ipv = 4, only first 4 bytes are set, the rest is 0
      ipaddr_t src_ip;
      ipaddr_t dst_ip;

      static Key from_packet(Packet &pkt);

      struct Equal
      {
         bool operator()(const Key &a, const Key &b) const;
      }; // Equal

      struct Hash
      {
         uint64_t operator()(const Key &key) const;
      };// Hash
   }; // Key

   struct Value {
      uint16_t src_port;
      uint16_t dst_port;
      timeval timestamp;

      static Value from_packet(Packet &pkt);
      void fill_packet(Packet &pkt) const;
   }; // Value

   // circullar buffer with the ability to resize
   class FIFO {
   public:
      struct Item
      {
         Key key;
         // timestamp of the info asociated with the key
         // it is used in the rare cases of key conflicts
         timeval timestamp;
      }; // Item

      // must be power of 2
      static constexpr size_t DEFAULT_SIZE = 16;

      FIFO() : read(0), write(0), buffer(DEFAULT_SIZE) {}

      // number of items in the fifo
      inline size_t count() const { return mod_size(write - read + buffer.size()); }
      // number of items this fifo is capable of holding at once
      inline size_t size() const { return buffer.size() - 1; }
      inline bool is_empty() const { return read == write; }
      inline bool is_full() const { return read == mod_size(write + 1); }

      // returns null if empty, otherwise pointer to value that is removed
      // the pointer is valid only until other non-const method call on FIFO
      Item *pop();
      // null if empty, otherwise value that would be returned by pop
      // without actualy removing the value
      const Item *peek() const;
      void push(Key &item, const Value &info);
   private:
      // read == write              => empty
      // read == (write + 1) % size => full
      size_t read;
      size_t write;

      // buffer.size is always power of 2
      std::vector<Item> buffer;

      // returns value % buffer.size
      inline size_t mod_size(size_t value) const
      {
         // buffer.size is always power of 2
         return value & (buffer.size() - 1);
      }

      void resize();
   };// FIFO

   // end of private types, continues FragmentCache

   // adds new packet to the cache
   void add_packet(Packet &pkt);
   // fills the missing info in pkt, returns false if the info is not in
   // the cache
   bool fill_info(Packet &pkt) const;
   // removes all entries older than the timeout
   void remove_old(const timeval &now);

   ska::flat_hash_map<Key, Value, Key::Hash, Key::Equal> keys;
   FIFO buffer;
   timeval timeout;
}; // FragmentCache

} // namespace ipxp

#endif // ifdef IPXP_STORAGE_FRAGMENTATION_CACHE_FRAGMENT_CACHE
