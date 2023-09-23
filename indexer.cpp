#include "indexer.hpp"

ipxp::ThreadPacketIndexer* ipxp::ThreadPacketIndexer::_singleton= nullptr;;

bool ipxp::IndexLocalMinCMP(const ipxp::PacketIndexerStructLocalMinStruct& a, const ipxp::PacketIndexerStructLocalMinStruct& b)
{
    auto tsA =  std::get<0>(std::get<0>(a))->ts;
    auto tsB = std::get<0>(std::get<0>(b))->ts;
    if(tsA.tv_sec < tsB.tv_sec) return true;
    if(tsA.tv_sec == tsB.tv_sec && tsA.tv_usec < tsB.tv_usec) return true;
    return false;
}
