#ifndef IPXP_CACHEDFLOWSTORE_HPP
#define IPXP_CACHEDFLOWSTORE_HPP

#include "flowstore.hpp"
#include "record.hpp"
#include <cassert>
#include <utility>
#include <iterator>
#include <sstream>
#include <ipfixprobe/options.hpp>
#include "hiearchyflowstore.hpp"

#include <iomanip>

#define CACHEDSTORE_DEBUG

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
    typedef std::map<FCHash, typename Base::packet_info> CachedPacketInfoMap;
    typedef typename CachedPacketInfoMap::value_type CachedPacketInfoMapPair;

public:


    void debugArray(const unsigned char* data, size_t len) {
        std::ios_base::fmtflags f( std::cout.flags() );
        for (size_t i = 0; i < len; ++i) {
            std::cerr << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << (((int)data[i]) & 0xFF) << " ";
        }
        std::cerr << std::endl;
        std::cerr.flags( f );
    }

    void printHash(FCHash hash)
    {
        debugArray((uint8_t*)&hash, sizeof(hash));
    }

    FlowStoreCached() : Base()
    {
        m_cached_lookups = 0;
        m_item_moves = 0;
        m_item_move_rejects = 0;
        m_move_exports = 0;
    }

    accessor lookup(packet_info &pkt) {
        //Lookup in cache flow store
        std::cerr << "Lookup Cached pkt: " << pkt.getPacket() << std::endl;
        auto cachedFS = getCachedFStore();
        auto cachedPktInfo = cachedFS.prepare(*pkt.getPacket(), pkt.isInverse());
        printHash(cachedPktInfo.getHash());
        auto cachedFSLookup = cachedFS.lookup(cachedPktInfo);
        if(cachedFSLookup != this->lookup_end()) {
            m_cached_lookups++;
            std::cerr << "Returing record of cached store" << std::endl;
            // Pkt needs to be kept uptoday with the accessor
            pkt = cachedPktInfo;
            return cachedFSLookup;
        }

        //Lookup in base flow store
        auto baseFS = getBaseFStore();
        auto basePktInfo = baseFS.prepare(*pkt.getPacket(), pkt.isInverse());
        auto baseFSLookup = baseFS.lookup(basePktInfo);
        if(baseFSLookup == this->lookup_end()) {
            //If not found return end
            std::cerr << "Entry not found in both stores" << std::endl;
            return this->lookup_end();
        }
        std::cerr << "Base lookup entry" << std::endl;
        printHash((*baseFSLookup)->getHash());


        std::cerr << "Moving entry to cached store" << std::endl;
        //Move the flow into cachedFS
        auto insertEntry = cachedFS.lookup_empty(cachedPktInfo);
        if(insertEntry == this->lookup_end()) {
            //Did not find empty space in cachedFS
            //Try to insert into baseFS
            insertEntry = cachedFS.free(cachedPktInfo);
            if(insertEntry == this->lookup_end()) {
                m_item_move_rejects++;
                //Caching Flowstore rejected flow movement
                // Pkt needs to be kept uptoday with the accessor
                pkt = basePktInfo;
                return baseFSLookup;
            }
            auto cacheInfoIt = cachedPacketInfoMap.find((*insertEntry)->getHash());
#ifdef CACHEDSTORE_DEBUG
            if(cacheInfoIt == cachedPacketInfoMap.end()) {
                printHash((*insertEntry)->getHash());
                throw std::logic_error("Hash not stored in map");
            }
#endif
            auto basePrevPktInfo = cacheInfoIt->second;
            std::cerr << "Inserting into base" << std::endl;
            printHash(basePrevPktInfo.getHash());

#ifdef CACHEDSTORE_DEBUG
            auto baseInsertEntryCh = baseFS.lookup(basePrevPktInfo);
            if(baseInsertEntryCh != this->lookup_end()) {
                printHash(basePrevPktInfo.getHash());
                throw std::logic_error("Entry already in base");
            }
#endif

            auto baseInsertEntry = baseFS.lookup_empty(basePrevPktInfo);
            if(baseInsertEntry == this->lookup_end()) {
                std::cerr << "Base does not have empty line" << std::endl;
                m_move_exports++;
                //Did not find empty space in base
                baseInsertEntry = baseFS.free(basePrevPktInfo);
                if(this->m_forced_callback) {
                    //The base Entry should be cleared by the force callback
                    baseInsertEntry = this->m_forced_callback(baseInsertEntry);
                } else {
                    throw std::logic_error("Cached store requires m_force_callback to be set");
                }
            }

            //Save the FCRecord into baseFS
            **baseInsertEntry = **insertEntry;

            /* Watch out for put due to invalidating nature for existing accessors (baseFSLookup) */
            //TODO: should be called at the end of function
//            baseFS.put(baseInsertEntry);

            //Clear the free entry in cached store
            std::cerr << "Clearing cached entry: " << *insertEntry << std::endl;
            printHash((*insertEntry)->getHash());
            cachedPacketInfoMap.erase((*insertEntry)->getHash());
            (*insertEntry)->erase();
            m_item_moves++;

            std::cerr << "Cleared cached entry: " << *insertEntry << std::endl;
            printHash((*insertEntry)->getHash());
        }

        std::cerr << "Inserting into cached: " << *insertEntry << std::endl;
        printHash(cachedPktInfo.getHash());
        printHash((*baseFSLookup)->getHash());

        //Valid insertEntry insert lookup BaseFS FCRecord to cachedFS
        **insertEntry = **baseFSLookup;
        //Insert pkt to map for later movement

        std::cerr << "Inserted entry" << std::endl;
        printHash((*insertEntry)->getHash());

#ifdef CACHEDSTORE_DEBUG
        auto insertCh = cachedPacketInfoMap.find(cachedPktInfo.getHash());
        if(insertCh != cachedPacketInfoMap.end()) {
            printHash(cachedPktInfo.getHash());
            throw std::logic_error("Entry already in cache map");
        }
#endif

        cachedPacketInfoMap.insert(CachedPacketInfoMapPair(cachedPktInfo.getHash(), basePktInfo));

        //Remove the baseFSLookup from the BaseFS
        (*baseFSLookup)->erase();

        // Pkt needs to be kept uptoday with the accessor
        pkt = cachedPktInfo;
        return insertEntry;
    }

    accessor lookup_empty(packet_info &pkt) {
        //Lookup in cached flow store
        std::cerr << "Lookup empty Cached pkt: " << pkt.getPacket() << std::endl;
        auto cachedFS = getCachedFStore();
        auto cachedPktInfo = cachedFS.prepare(*pkt.getPacket(), pkt.isInverse());
        auto cachedFSLookup = cachedFS.lookup_empty(cachedPktInfo);
        printHash(cachedPktInfo.getHash());
        auto baseFS = getBaseFStore();
        auto basePktInfo = baseFS.prepare(*pkt.getPacket(), pkt.isInverse());
        if(cachedFSLookup != this->lookup_end()) {
#ifdef CACHEDSTORE_DEBUG
            auto insertCh = cachedPacketInfoMap.find(cachedPktInfo.getHash());
            if(insertCh != cachedPacketInfoMap.end()) {
                printHash(cachedPktInfo.getHash());
                throw std::logic_error("Entry already in cache map");
            }
#endif
            //Always store in cached if empty spot is available
            cachedPacketInfoMap.insert(CachedPacketInfoMapPair(cachedPktInfo.getHash(), basePktInfo));
            std::cerr << "Returing empty of cached store" << std::endl;
            // Pkt needs to be kept uptoday with the accessor
            pkt = cachedPktInfo;
            return cachedFSLookup;
        }

        std::cerr << "Freeing space in cached store" << std::endl;
        auto insertEntry = cachedFS.free(cachedPktInfo);
        if(insertEntry == this->lookup_end()) {
            //Caching Flowstore rejected flow movement
            std::cerr << "Returing empty of base store - cached rejected free" << std::endl;
            // Pkt needs to be kept uptoday with the accessor
            pkt = basePktInfo;
            return baseFS.lookup_empty(basePktInfo);
        }


        std::cerr << "Moving record from cached store to base store" << std::endl;
        //Move flow into base to make space for the new record in cacheFS

        auto cacheInfoIt = cachedPacketInfoMap.find((*insertEntry)->getHash());
#ifdef CACHEDSTORE_DEBUG
        if(cacheInfoIt == cachedPacketInfoMap.end()) {
            printHash((*insertEntry)->getHash());
            throw std::logic_error("Hash not stored in map");
        }
#endif
        auto basePrevPktInfo = cacheInfoIt->second;

#ifdef CACHEDSTORE_DEBUG
        auto baseInsertEntryCh = baseFS.lookup(basePrevPktInfo);
        if(baseInsertEntryCh != this->lookup_end()) {
            printHash(basePrevPktInfo.getHash());
            throw std::logic_error("Entry already in base");
        }
#endif
        auto baseInsertEntry = baseFS.lookup_empty(basePrevPktInfo);
        if(baseInsertEntry == this->lookup_end()) {
            std::cerr << "Freeing space in base store by exporting " << std::endl;
            m_move_exports++;
            //Did not find empty space in base
            baseInsertEntry = baseFS.free(basePrevPktInfo);
            if(this->m_forced_callback) {
                //The base Entry should be cleared by the force callback
                baseInsertEntry = this->m_forced_callback(baseInsertEntry);
            } else {
                throw std::logic_error("Cached store requires m_force_callback to be set");
            }
            (*baseInsertEntry)->erase();
        }

        //Save the FCRecord into baseFS
        **baseInsertEntry = **insertEntry;
        baseFS.put(baseInsertEntry);
        m_item_moves++;
        std::cerr << "Moved record from cached store to base" << std::endl;

        //Clear the cached entry
        cachedPacketInfoMap.erase((*insertEntry)->getHash());
        (*insertEntry)->erase();

#ifdef CACHEDSTORE_DEBUG
        auto insertCh = cachedPacketInfoMap.find(cachedPktInfo.getHash());
        if(insertCh != cachedPacketInfoMap.end()) {
            printHash(cachedPktInfo.getHash());
            throw std::logic_error("Entry already in cache map");
        }
#endif
        cachedPacketInfoMap.insert(CachedPacketInfoMapPair(cachedPktInfo.getHash(), basePktInfo));
        std::cerr << "Returing cleared record of cached store" << std::endl;
        // Pkt needs to be kept uptoday with the accessor
        pkt = cachedPktInfo;
        return insertEntry;
    }

    accessor free(packet_info &pkt) {
        std::cerr << "Free Cached pkt: " << pkt.getPacket() << std::endl;
        auto cachedFS = getCachedFStore();
        auto baseFS = getBaseFStore();
        auto basePktInfo = baseFS.prepare(*pkt.getPacket(), pkt.isInverse());
        auto cachedPktInfo = cachedFS.prepare(*pkt.getPacket(), pkt.isInverse());
        printHash(cachedPktInfo.getHash());
        auto cachedFSFree = cachedFS.free(cachedPktInfo);
        if(cachedFSFree != this->lookup_end()) {
            //Remove key in map. Record will be exported. TODO: Maybe do in index_export instead
            cachedPacketInfoMap.erase((*cachedFSFree)->getHash());

#ifdef CACHEDSTORE_DEBUG
            auto insertCh = cachedPacketInfoMap.find(cachedPktInfo.getHash());
            if(insertCh != cachedPacketInfoMap.end()) {
                printHash(cachedPktInfo.getHash());
                throw std::logic_error("Entry already in cache map");
            }
#endif
            //CacheFS accepted this pkt
            cachedPacketInfoMap.insert(CachedPacketInfoMapPair(cachedPktInfo.getHash(), basePktInfo));
            // Pkt needs to be kept uptoday with the accessor
            pkt = cachedPktInfo;
            return cachedFSFree;
        }

        // Pkt needs to be kept uptoday with the accessor
        pkt = basePktInfo;
        //The base cannot reject free
        return baseFS.free(basePktInfo);
    }

    template<int N, typename... Ts> using NthTypeOf =
        typename std::tuple_element<N, std::tuple<Ts...>>::type;

    template<int N, typename... Ts>
    auto &getIndex(boost::variant<Ts...> &v) {
        using target = NthTypeOf<N, Ts...>;
        return boost::get<target>(v);
    }

    template<int N, typename... Ts>
    auto &getIndex(const boost::variant<Ts...> &v) {
        using target = NthTypeOf<N, Ts...>;
        return boost::get<target>(v);
    }

    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I == sizeof...(Tp), void>::type
    cached_index_export_for_each(std::tuple<Tp...> &, const accessor&) // Unused arguments are given no names.
    {
    }

    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I < sizeof...(Tp), void>::type
    cached_index_export_for_each(std::tuple<Tp...>& t, const accessor& index)
    {
        auto &p = std::get<I>(t);
        auto &fstore = std::get<1>(p);
        auto indexStore = getIndex<I+1>(index.getFStore());

        if(&fstore != indexStore) { //Fstores needs to be lazy checked in case of same types
            return cached_index_export_for_each<I + 1, Tp...>(t, index);
        }
        cachedPacketInfoMap.erase((*index)->getHash());
    }

    accessor index_export(const accessor &index, FlowRingBuffer &rb) {
        cached_index_export_for_each(this->m_fstores, index);
        return Base::index_export(index, rb);
    }


    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I == sizeof...(Tp), void>::type
    cached_iter_export_for_each(std::tuple<Tp...> &, const iterator&) // Unused arguments are given no names.
    {
    }

    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I < sizeof...(Tp), void>::type
    cached_iter_export_for_each(std::tuple<Tp...>& t, const iterator& index)
    {
        auto &p = std::get<I>(t);
        auto &fstore = std::get<1>(p);
        auto storeTup = typename Base::Types().storeFromRange(index);
        auto indexStore = getIndex<I>(storeTup);
        if(&fstore != indexStore) {
            return cached_iter_export_for_each<I + 1, Tp...>(t, index);
        }
        cachedPacketInfoMap.erase((*index)->getHash());
    }

    accessor iter_export(const iterator &index, FlowRingBuffer &rb) {
        cached_iter_export_for_each(this->m_fstores, index);
        return Base::iter_export(index, rb);
    }


    FlowStoreStat::Ptr stats_export() {
        auto cachedFS = getCachedStore();
        auto baseFS = getBaseStore();
        auto cStats = cachedFS.stats_export();
        cStats->setName("cachedStore");
        auto bStats = baseFS.stats_export();
        bStats->setName("baseStore");
        FlowStoreStat::PtrVector statVec = {
            make_FSStatPrimitive("cached_lookups" , m_cached_lookups),
            make_FSStatPrimitive("item_moves" , m_item_moves),
            make_FSStatPrimitive("item_move_rejects" , m_item_move_rejects),
            make_FSStatPrimitive("move_exports" , m_move_exports),
            cStats,
            bStats
        };
        return std::make_shared<FlowStoreStatVector>("", statVec);
    }

private:
    inline FSHiearchyWrapper<CacheFs, CacheFs, BaseFs>& getCachedFStore() {
        auto &fStorePair = std::get<0>(this->m_fstores);
        auto &fhstore = std::get<0>(fStorePair);
        return fhstore;
    }

    inline FSHiearchyWrapper<BaseFs, CacheFs, BaseFs>& getBaseFStore() {
        auto &fStorePair = std::get<1>(this->m_fstores);
        auto &fhstore = std::get<0>(fStorePair);
        return fhstore;
    }

    inline CacheFs& getCachedStore() {
        auto &fStorePair = std::get<0>(this->m_fstores);
        auto &fstore = std::get<1>(fStorePair);
        return fstore;
    }

    inline BaseFs& getBaseStore() {
        auto &fStorePair = std::get<1>(this->m_fstores);
        auto &fstore = std::get<1>(fStorePair);
        return fstore;
    }

    CachedPacketInfoMap cachedPacketInfoMap;

    uint32_t m_cached_lookups;
    uint32_t m_item_moves;
    uint32_t m_item_move_rejects;
    uint32_t m_move_exports;
};

}

#endif // IPXP_CACHEDFLOWSTORE_HPP
