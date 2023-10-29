#include "hashtablestore.hpp"
#include "flowcache.hpp"
#include <cstring>
#include <cstdio>

namespace ipxp {

HTFlowsStorePacketInfo HTFlowsStorePacketInfo::from_packet(Packet &pkt, bool bidir, bool inverse) {
    flow_key_t key;
    key.proto = pkt.ip_proto;
    key.ip_version = pkt.ip_version;
    
    if(!bidir) {
        key.src_port = !inverse ? pkt.src_port : pkt.dst_port;
        key.dst_port = !inverse ? pkt.dst_port : pkt.src_port;
        if (pkt.ip_version == IP::v4) {
            key.ip.v4.src_ip = !inverse ? pkt.src_ip.v4 : pkt.dst_ip.v4;
            key.ip.v4.dst_ip = !inverse ? pkt.dst_ip.v4 : pkt.src_ip.v4;
        } else if (pkt.ip_version == IP::v6) {
            memcpy(key.ip.v6.src_ip.data(), !inverse ? pkt.src_ip.v6 : pkt.dst_ip.v6, sizeof(pkt.src_ip.v6));
            memcpy(key.ip.v6.dst_ip.data(), !inverse ? pkt.dst_ip.v6 : pkt.src_ip.v6, sizeof(pkt.dst_ip.v6));
        }
    } else {
        bool pLower = pkt.src_port < pkt.dst_port;
        key.src_port = pLower ? pkt.src_port : pkt.dst_port;
        key.dst_port = pLower ? pkt.dst_port : pkt.src_port;
        
        if (pkt.ip_version == IP::v4) {
            bool ipLower = std::memcmp(&pkt.src_ip.v4, &pkt.dst_ip.v4, sizeof(pkt.src_ip.v4));
            key.ip.v4.src_ip = !ipLower ? pkt.src_ip.v4 : pkt.dst_ip.v4;
            key.ip.v4.dst_ip = !ipLower ? pkt.dst_ip.v4 : pkt.src_ip.v4;
        } else if (pkt.ip_version == IP::v6) {
            bool ipLower = std::memcmp(pkt.src_ip.v6, pkt.dst_ip.v6, sizeof(pkt.dst_ip.v6));
            memcpy(key.ip.v6.src_ip.data(), !ipLower ? pkt.src_ip.v6 : pkt.dst_ip.v6, sizeof(pkt.src_ip.v6));
            memcpy(key.ip.v6.dst_ip.data(), !ipLower ? pkt.dst_ip.v6 : pkt.src_ip.v6, sizeof(pkt.dst_ip.v6));
        }
    }
    return HTFlowsStorePacketInfo(pkt, inverse, key, bidir);
}

void HTFlowStore::init(HashTableStoreParser& parser)
{
   m_cache_size = parser.m_cache_size;
   m_line_size = parser.m_line_size;
   m_line_mask = (m_cache_size - 1) & ~(m_line_size - 1);
   m_line_new_idx = m_line_size / 2;
   m_biflowkey = parser.m_biflowkey;

   if (m_line_size > m_cache_size) {
      throw PluginError("flow cache line size must be greater or equal to cache size");
   }
   if (m_cache_size == 0) {
      throw PluginError("flow cache won't properly work with 0 records");
   }

   try {
      m_flow_table.resize(m_cache_size);
      m_flow_records.resize(m_cache_size);
      for (uint32_t i = 0; i < m_cache_size; i++) {
         m_flow_table[i] = &m_flow_records[i];
      }
   } catch (std::bad_alloc &e) {
      throw PluginError("not enough memory for flow cache allocation");
   }

#ifdef FLOW_CACHE_STATS
   stats_reset();
#endif /* FLOW_CACHE_STATS */
}

HTFlowStore::packet_info HTFlowStore::prepare(Packet &pkt, bool inverse = false)
{
   return HTFlowsStorePacketInfo::from_packet(pkt, m_biflowkey, inverse);
}

HTFlowStore::accessor HTFlowStore::lookup(packet_info &pkt)
{
    FlowIndex flowRow_index = makeRowIndex(pkt.getHash());
    FlowIndex flowIndex = searchLine(flowRow_index, pkt.getHash());
    if(flowIndex.valid) {
        auto ind = (m_flow_table.begin() + flowIndex.flow_index);
        return ind;
    }
    return lookup_end();
}

HTFlowStore::accessor HTFlowStore::lookup_empty(packet_info &pkt)
{
    FlowIndex flowRow_index = makeRowIndex(pkt.getHash());
    FlowIndex flowIndex = searchEmptyLine(flowRow_index);

#ifdef DBG
    if(flowIndex.valid) {
        std::cout << "FL Valid: " << flowIndex.valid << " Fl I: " <<  flowIndex.flow_index << " Fl R: " << flowIndex.line_index << " R I: " << flowIndex.flow_index - flowIndex.line_index << std::endl;
    }
#endif
    if(flowIndex.valid) {
        auto ind = (m_flow_table.begin() + flowIndex.flow_index);
        return ind;
    }
    return lookup_end();
}

HTFlowStore::accessor HTFlowStore::free(packet_info &pkt)
{
    FlowIndex flowRow_index = makeRowIndex(pkt.getHash());
//    std::cerr << "Free index: " << flowRow_index.line_index+m_line_size-1 << " Table length: " << m_flow_table.size() << " Table address: " << (*m_flow_table.begin()) << " Record Address: " << *(m_flow_table.begin()+flowRow_index.line_index+m_line_size-1) << std::endl;
    return (m_flow_table.begin()+flowRow_index.line_index+m_line_size-1);
}

HTFlowStore::accessor HTFlowStore::put(const accessor &acc)
{
    FlowIndex flowIndex = fromAccessor(acc);
#ifdef DBG
    std::cout << "FL Valid: " << flowIndex.valid << " Fl I: " <<  flowIndex.flow_index << " Fl R: " << flowIndex.line_index << " R I: " << flowIndex.flow_index - flowIndex.line_index << std::endl;
#endif
#ifdef FLOW_CACHE_STATS
    {
        StatsGuard stats(innerStats);
        stats->m_cacheline_max_index = std::max(stats->m_cacheline_max_index, flowIndex.flow_index - flowIndex.line_index);
    }
#endif
    moveToFront(flowIndex);
    return (m_flow_table.begin() + flowIndex.line_index);
}

HTFlowStore::accessor HTFlowStore::index_export(const accessor &acc, FlowRingBuffer &rb)
{
    FlowIndex flowRow_index = fromAccessor(acc);
    FCRecord *sw_rec = rb.put(m_flow_table[flowRow_index.flow_index]);
    m_flow_table[flowRow_index.flow_index] = sw_rec;
    sw_rec->erase();
    return (m_flow_table.begin() + flowRow_index.flow_index);
}

HTFlowStore::accessor HTFlowStore::iter_export(const iterator &iter, FlowRingBuffer &rb)
{
    uint32_t flow_index = iter - this->begin();
    FCRecord *sw_rec = rb.put(m_flow_table[flow_index]);
    m_flow_table[flow_index] = sw_rec;
    sw_rec->erase();
    return (m_flow_table.begin() + flow_index);
}
}
