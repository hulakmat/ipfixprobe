#include "flowcache.hpp"
#include "hashtablestore.hpp"
#include "flowstoremonitor.hpp"
#include "flowstoreportfilter.hpp"
#include "hiearchyflowstore.hpp"
#include "cachedflowstore.hpp"
#include "flowstorestatswriter.hpp"
#include "flowstorepacketindexer.hpp"

#include <boost/core/demangle.hpp>


extern "C" {
struct FilteredStore {};
struct BaseStore {};
}

namespace ipxp {

template <typename F, typename Label>
class FlowStoreStatsWrapper : public FlowStoreProxySimple<F>
{
public:
    typedef typename F::packet_info PacketInfo;
    typedef typename F::accessor Access;
    typedef typename F::iterator Iter;
    typedef typename F::parser Parser;
    
    FlowStoreStat::Ptr stats_export() {
        auto ptr = this->m_flowstore.stats_export();
        std::string label = boost::core::demangle(typeid(Label).name());
        ptr->setName(label);
        return ptr;
    };
};

Plugin *cons_cached_storage_func()
{
    return new ipxp::FlowCache<
            FlowStorePacketIndexer<
            FlowStoreStatsWriter<
                FlowStoreMonitor<
                    FlowStoreCached<
                        //Cache storage
                        FlowStoreMonitor<
                            HTFlowStore
                        >,
                        //Base storage
                        FlowStoreMonitor<
                             HTFlowStore
                        >
                    >
                >
            >
            >
            >("cachedStorage");
};

__attribute__((constructor)) static void register_cached_storage_plugin()
{
   static PluginRecord rec = PluginRecord("cachedStorage", cons_cached_storage_func);
   register_plugin(&rec);
}


Plugin *cons_s_port_cache_func()
{
    return new FlowCache<
            FlowStoreStatsWriter<
               FlowStoreHiearchy<
                  FlowStorePortFilter<
                      FlowStoreMonitor<
                            HTFlowStore
                      >
                  >,
                  FlowStoreMonitor<
                        HTFlowStore
                  >
               >
            >
   >("s_port_cache");
};

__attribute__((constructor)) static void register_s_port_cache_plugin()
{
   static PluginRecord rec = PluginRecord("s_port_cache", cons_s_port_cache_func);
   register_plugin(&rec);
}

Plugin *cons_func()
{
    return new FlowCache<
                  FlowStoreStatsWriter<
                     FlowStoreHiearchy<
                        FlowStorePortFilter<
                            FlowStoreMonitor<
                                  HTFlowStore
                            >
                        >,
                        FlowStoreMonitor<
                              HTFlowStore
                        >,
                        HTFlowStore
                     >
                  >
            >("hiearcache");
};

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("hiearcache", cons_func);
   register_plugin(&rec);
}

}
