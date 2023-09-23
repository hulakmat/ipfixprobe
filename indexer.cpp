#include "indexer.hpp"

ipxp::ThreadPacketIndexer* ipxp::ThreadPacketIndexer::_singleton= nullptr;;

bool ipxp::IndexLocalMinCMP(const ipxp::PacketIndexerStructLocalMinStruct& a, const ipxp::PacketIndexerStructLocalMinStruct& b)
{
    auto tsA =  std::get<0>(std::get<0>(a))->acc_ts;
    auto tsB = std::get<0>(std::get<0>(b))->acc_ts;
    if(tsA.ts.tv_sec < tsB.ts.tv_sec) return true;
    if(tsA.ts.tv_sec == tsB.ts.tv_sec && tsA.ts.tv_usec < tsB.ts.tv_usec) return true;
    if(tsA.ts.tv_sec == tsB.ts.tv_sec && tsA.ts.tv_usec == tsB.ts.tv_usec && tsA.tv_ns < tsB.tv_ns) return true;
    return false;
}
