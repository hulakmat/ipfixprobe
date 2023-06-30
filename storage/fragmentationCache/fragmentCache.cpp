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

#include "fragmentCache.hpp"
#include "../xxhash.h"

namespace ipxp
{

// operators for working with timeval, the operators assume that:
//    abs(time.usec) < USEC_IN_SEC && sign(time.sec) == sing(time.usec)

static inline timeval operator-(const timeval &a, const timeval &b)
{
   // number of microseconds in second
   constexpr decltype(a.tv_usec) USEC_IN_SEC = 1000000;

   auto sec = a.tv_sec - b.tv_sec;
   auto usec = a.tv_usec - b.tv_usec;

   // ensure that abs(usec) < USEC_IN_SEC
   if (usec < -USEC_IN_SEC) {
      usec += USEC_IN_SEC;
      --sec;
   } else if (usec > USEC_IN_SEC) {
      usec -= USEC_IN_SEC;
      ++sec;
   }

   // ensure that sign(sec) == sign(usec)
   if (sec > 0 && usec < 0) {
      --sec;
      usec += 1;
   } else if (sec < 0 && usec > 0) {
      ++sec;
      usec -= 1;
   }

   return timeval{ .tv_sec = sec, .tv_usec = usec };
}

static constexpr bool operator>=(const timeval &a, const timeval &b)
{
   return a.tv_sec > b.tv_sec || (a.tv_sec == b.tv_sec && a.tv_usec >= b.tv_usec);
}

static constexpr bool operator==(const timeval &a, const timeval &b)
{
   return a.tv_sec == b.tv_sec && a.tv_usec == b.tv_usec;
}

FragmentCache::FIFO::Item *FragmentCache::FIFO::pop()
{
   if (is_empty()) {
      return nullptr;
   }

   auto res = &buffer[read];
   read = mod_size(read + 1);

   if (is_empty()) {
      // move the cursors to the optimal position
      read = 0;
      write = 0;
   }

   return res;
}

const FragmentCache::FIFO::Item *FragmentCache::FIFO::peek() const
{
   return is_empty() ? nullptr : &buffer[read];
}

void FragmentCache::FIFO::push(Key &item, const Value &info)
{
   if (is_full()) {
      resize();
   }

   buffer[write] = {
      .key = item,
      .timestamp = info.timestamp,
   };

   write = mod_size(write + 1);
}

void FragmentCache::FIFO::resize()
{
   // how much more is allocated
   size_t delta_size = buffer.size();
   // the new size must be power of 2
   size_t new_size = buffer.size() + delta_size;

   buffer.reserve(new_size);

   // no need to copy, simple resize
   if (read <= write) {
      buffer.resize(new_size);
      return;
   }

   // first resize to the size of the empty space, than copy the data
   // the space is already reserved so all the iterators will be valid
   auto old_end = buffer.end();
   buffer.resize(delta_size + read);
   buffer.insert(buffer.end(), buffer.begin() + read, old_end);

   read += delta_size;
}

FragmentCache::Key FragmentCache::Key::from_packet(Packet &pkt)
{
   return (Key) {
      .ipv = pkt.ip_version,
      .vlan_id = pkt.vlan_id,
      .frag_id = pkt.frag_id,
      .src_ip = pkt.src_ip,
      .dst_ip = pkt.dst_ip
   };
}

bool FragmentCache::Key::Equal::operator()(const Key &a, const Key &b) const
{
   if (a.ipv != b.ipv
      || a.vlan_id != b.vlan_id
      || a.frag_id != b.frag_id)
   {
      return false;
   }

   if (a.ipv == IP::v4) {
      return a.src_ip.v4 == b.src_ip.v4 && a.dst_ip.v4 == b.dst_ip.v4;
   }
   return memcmp(a.src_ip.v6, b.src_ip.v6, sizeof(a.src_ip.v6)) == 0
      && memcmp(a.dst_ip.v6, b.dst_ip.v6, sizeof(a.src_ip.v6)) == 0;
}

uint64_t FragmentCache::Key::Hash::operator()(const Key &key) const
{
   return XXH64(reinterpret_cast<const void *>(&key), sizeof(Key), 0);
}

FragmentCache::Value FragmentCache::Value::from_packet(Packet &pkt)
{
   return (Value) {
      .src_port = pkt.src_port,
      .dst_port = pkt.dst_port,
      .timestamp = pkt.ts,
   };
}

void FragmentCache::Value::fill_packet(Packet &pkt) const
{
   pkt.src_port = src_port;
   pkt.dst_port = dst_port;
}

void FragmentCache::add_packet(Packet &pkt)
{
   auto key = Key::from_packet(pkt);
   auto info = Value::from_packet(pkt);

   remove_old(pkt.ts);

   buffer.push(key, info);
   keys[std::move(key)] = std::move(info);
}

bool FragmentCache::fill_info(Packet &pkt) const
{
   auto key = Key::from_packet(pkt);
   auto val = keys.find(key);

   if (val == keys.end()) {
      return false; // the table doesn't have the key
   }

   val->second.fill_packet(pkt);
   return true;
}

void FragmentCache::remove_old(const timeval &now)
{
   auto cur = buffer.peek();

   while (cur != nullptr && now - cur->timestamp >= timeout) {
      buffer.pop();

      auto to_remove = keys.find(cur->key);

      // don't remove the value if it has already been overwritten with
      // another call to add_packet (in case of key conflict)
      if (to_remove != keys.end() && to_remove->second.timestamp == cur->timestamp) {
         keys.erase(to_remove);
      }

      cur = buffer.peek();
   }
}

} // namespace ipxp
