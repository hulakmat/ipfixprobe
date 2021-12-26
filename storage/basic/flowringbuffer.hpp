/**
 * \file flowringbuffer.hpp
 * \brief "Flow ring buffer" flow ring buffer
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2014-2016 CESNET
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
 * This software is provided ``as is'', and any express or implied
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

#ifndef IPXP_FLOW_RING_BUFFER_HPP
#define IPXP_FLOW_RING_BUFFER_HPP

#include <ipfixprobe/ring.h>
#include "record.hpp"

namespace ipxp {

class FlowRingBuffer
{
public:
   FlowRingBuffer() : m_queue(nullptr), m_ptrs(nullptr), m_records(nullptr), m_qsize(0), m_qidx(0)
   {
   }
   ~FlowRingBuffer()
   {
      delete [] m_ptrs;
      delete [] m_records;
   }
   void set_queue(ipx_ring_t *queue)
   {
      m_queue = queue;
      m_qsize = ipx_ring_size(queue);
      m_qidx = 0;
      m_ptrs = new FCRecord*[m_qsize];
      m_records = new FCRecord[m_qsize];
      for (size_t i = 0; i < m_qsize; i++) {
         m_ptrs[i] = &m_records[i];
      }
   }

   FCRecord *put(FCRecord *rec)
   {
      ipx_ring_push(m_queue, &rec->m_flow);
      std::swap(m_ptrs[m_qidx], rec);
      qinc();
      return rec;
   }

private:
   ipx_ring_t *m_queue;
   FCRecord **m_ptrs;
   FCRecord *m_records;
   size_t m_qsize;
   size_t m_qidx;
                                                                                                                                                                             
   void qinc()
   {
      m_qidx = (m_qidx + 1) % m_qsize;
   }
};

}
#endif //IPXP_FLOW_RING_BUFFER_HPP