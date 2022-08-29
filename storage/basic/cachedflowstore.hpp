#ifndef IPXP_CACHEDFLOWSTORE_HPP
#define IPXP_CACHEDFLOWSTORE_HPP

#include "flowstore.hpp"
#include "record.hpp"
#include <cassert>
#include <utility>
#include <iterator>
#include <sstream>
#include <cassert>
#include <ipfixprobe/options.hpp>
#include "hiearchyflowstore.hpp"

namespace ipxp {

template <typename CacheFs, typename BaseFs>
class FlowStoreCached : public FlowStoreHiearchy<CacheFs, BaseFs>
{
protected:
    typedef FlowStoreHiearchy<CacheFs, BaseFs> Types;
    typedef FlowStoreHiearchy<CacheFs, BaseFs> Base;
public:
    typedef typename Types::range range;
    typedef typename Types::wrap_stores wrap_stores;
    typedef typename Base::iterator iterator;
    typedef typename Base::accessor accessor;
    typedef typename Base::packet_info packet_info;
    typedef typename Base::parser parser;
private:
    typedef std::map<FCRecord*, typename Base::packet_info> CachedPacketInfoMap;
    typedef typename CachedPacketInfoMap::value_type CachedPacketInfoMapPair;

public:

    FlowStoreCached() : Base()
    {
    }

    accessor lookup(packet_info &pkt) {
        //Lookup in cache flow store
        auto cachedFS = getCachedStore();
        auto cachedFSLookup = cachedFS.lookup(pkt);
        if(cachedFSLookup != this->lookup_end()) {
            return cachedFSLookup;
        }

        //Lookup in base flow store
        auto baseFS = getBaseStore();
        auto baseFSLookup = baseFS.lookup(pkt);
        if(baseFSLookup == this->lookup_end()) {
            //If not found return end
            return this->lookup_end();
        }

        //Move the flow into cachedFS
        auto insertEntry = cachedFS.lookup_empty(pkt);
        if(insertEntry == this->lookup_end()) {
            //Did not find empty space in cachedFS
            //Try to insert into baseFS
            insertEntry = cachedFS.free(pkt);
            if(insertEntry == this->lookup_end()) {
                //Caching Flowstore rejected flow movement
                return baseFSLookup;
            }
            auto basePktInfo = cachedPacketInfoMap.find(*insertEntry)->second;
            auto baseInsertEntry = baseFS.lookup_empty(basePktInfo);
            if(baseInsertEntry == this->lookup_end()) {
                //Did not find empty space in base
                baseInsertEntry = baseFS.free(basePktInfo);
                if(this->m_forced_callback) {
                    //The base Entry should be cleared by the force callback
                    baseInsertEntry = this->m_forced_callback(baseInsertEntry);
                } else {
                    assertm(false, "Cached store requires m_force_callback to be set");
                }
            }

            //Save the FCRecord into baseFS
            **baseInsertEntry = **insertEntry;
            baseFS.put(baseInsertEntry);
        }
        //Valid insertEntry insert lookup BaseFS FCRecord to cachedFS
        **insertEntry = **baseFSLookup;
        //Insert pkt to map for later movement
        cachedPacketInfoMap.insert(CachedPacketInfoMapPair(*insertEntry, pkt));

        //Remove the baseFSLookup from the BaseFS
        (*baseFSLookup)->erase();
        return insertEntry;
    }

    accessor lookup_empty(packet_info &pkt) {
        //Lookup in cached flow store
        auto cachedFS = getCachedStore();
        auto baseFS = getBaseStore();
        auto cachedFSLookup = cachedFS.lookup_empty(pkt);
        if(cachedFSLookup != this->lookup_end()) {
            //Always store in cached if empty spot is available
            cachedPacketInfoMap.insert(CachedPacketInfoMapPair(*cachedFSLookup, pkt));
            return cachedFSLookup;
        }

        auto insertEntry = cachedFS.free(pkt);
        if(insertEntry == this->lookup_end()) {
            //Caching Flowstore rejected flow movement
            return baseFS.lookup_empty(pkt);
        }

        //Move flow into base to make space for the new record in cacheFS
        auto basePktInfo = cachedPacketInfoMap.find(*insertEntry)->second;
        auto baseInsertEntry = baseFS.lookup_empty(basePktInfo);
        if(baseInsertEntry == this->lookup_end()) {
            //Did not find empty space in base
            baseInsertEntry = baseFS.free(basePktInfo);
            if(this->m_forced_callback) {
                //The base Entry should be cleared by the force callback
                baseInsertEntry = this->m_forced_callback(baseInsertEntry);
            } else {
                assertm(false, "Cached store requires m_force_callback to be set");
            }
        }
        //Save the FCRecord into baseFS
        **baseInsertEntry = **insertEntry;
        baseFS.put(baseInsertEntry);

        //Clear the cached entry
        (*insertEntry)->erase();
        cachedPacketInfoMap.insert(CachedPacketInfoMapPair(*insertEntry, pkt));
        return insertEntry;
    }

    accessor free(packet_info &pkt) {
        auto cachedFS = getCachedStore();
        auto baseFS = getBaseStore();
        auto cachedFSFree = cachedFS.free(pkt);
        if(cachedFSFree != this->lookup_end()) {
            //CacheFS accepted this pkt
            cachedPacketInfoMap.insert(CachedPacketInfoMapPair(*cachedFSFree, pkt));
            return cachedFSFree;
        }

        //The base cannot reject free
        return baseFS.free(pkt);
    }

private:
    inline FSHiearchyWrapper<CacheFs, CacheFs, BaseFs>& getCachedStore() {
        return std::get<0>(
                std::get<0>(this->m_fstores)
               );
    }

    inline FSHiearchyWrapper<BaseFs, CacheFs, BaseFs>& getBaseStore() {
        return std::get<0>(
                std::get<1>(this->m_fstores)
               );
    }

    CachedPacketInfoMap cachedPacketInfoMap;
};

}

#endif // IPXP_CACHEDFLOWSTORE_HPP
