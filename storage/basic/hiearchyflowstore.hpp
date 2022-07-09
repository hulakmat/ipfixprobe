
#ifndef IPXP_HIEARCHY_STORE_HPP
#define IPXP_HIEARCHY_STORE_HPP

#include "flowstore.hpp"
#include "record.hpp"
#include <cassert>
#include <utility>
#include <iterator>
#include <sstream>
#include <ipfixprobe/options.hpp>
#include "hiearchyjoiniterator.hpp"

#include <boost/variant.hpp>


namespace ipxp {

namespace std14
{
	template<typename T, T... Ints>
	struct integer_sequence
	{
		typedef T value_type;
		static constexpr std::size_t size() { return sizeof...(Ints); }
	};
	
	template<std::size_t... Ints>
	using index_sequence = integer_sequence<std::size_t, Ints...>;
	
	template<typename T, std::size_t N, T... Is>
	struct make_integer_sequence : make_integer_sequence<T, N-1, N-1, Is...> {};
	
	template<typename T, T... Is>
	struct make_integer_sequence<T, 0, Is...> : integer_sequence<T, Is...> {};
	
	template<std::size_t N>
	using make_index_sequence = make_integer_sequence<std::size_t, N>;
	
	template<typename... T>
	using index_sequence_for = make_index_sequence<sizeof...(T)>;

   /// Finds the size of a given tuple type.
   template<typename _Tp>
     struct tuple_size;
 
   /// class tuple_size
   template<typename... _Elements>
     struct tuple_size<::std::tuple<_Elements...> >
     {
       static const std::size_t value = sizeof...(_Elements);
     };
 
   template<typename... _Elements>
     const std::size_t tuple_size<::std::tuple<_Elements...> >::value;
}

using ::ipxjoin::join_many;
using ::ipxjoin::join_iterator_identifier;

template<typename... Args>
constexpr std::size_t length(Args...)
{
    return sizeof...(Args);
}

template <typename F, typename ...Fs>
class FSHiearchyWrapper;

namespace pinfo {
    struct InverseVisitor : public boost::static_visitor<bool>
    {
        bool over;
        bool inverse;
        template <typename T>
        bool operator () (T accessor) const
        {
            if(over) {
                return inverse;
            }
            return accessor.isInverse();
        }
    };
    template <>
    bool InverseVisitor::operator()<boost::blank>(boost::blank accessor) const
    {
        if(over) {
            return inverse;
        }
        return false;
    }


    struct HashVisitor : public boost::static_visitor<FCHash>
    {
        template <typename T>
        FCHash operator () (T accessor) const
        {
            return accessor.getHash();
        }
    };

    template <>
    FCHash HashVisitor::operator()<boost::blank>(boost::blank accessor) const
    {
        return 0;
    }

    struct PacketVisitor : public boost::static_visitor<Packet*>
    {
        bool over;
        Packet *packet;
        template <typename T>
        Packet *operator () (T accessor)
        {
            if(over) {
                return packet;
            }
            return accessor.getPacket();
        }
    };

#define assertm(exp, msg) assert(((void)msg, exp))
    template <>
    Packet *PacketVisitor::operator()<boost::blank>(boost::blank accessor)
    {
        return packet;
    }


    struct ValidVisitor : public boost::static_visitor<bool>
    {
        bool over = false;
        template <typename T>
        bool operator () (T accessor) const
        {
            if(over) return true;
            return accessor.isValid();
        }
    };
    template <>
    bool ValidVisitor::operator()<boost::blank>(boost::blank accessor) const
    {
        if(over) return true;
        return false;
    }
}

template <typename ...Fs>
class FSHierarchyPacketInfo : public FCPacketInfo
{
public:
    FSHierarchyPacketInfo(Packet &packet, bool inverse) : FCPacketInfo(packet, inverse) {}
    template <typename S, typename P>
    FSHierarchyPacketInfo(S *fstore, P packet_info) : 
        m_fstore(fstore), m_packet_info(packet_info) {}


    boost::variant<Fs*...> getFStore() const { return m_fstore; };
    boost::variant<boost::blank, typename Fs::packet_info...> &getInfo() { return m_packet_info; };


    bool isValid() const {
        auto vis = pinfo::ValidVisitor();
        vis.over = dummy;
        return apply_visitor(vis, m_packet_info);
    }


    bool isInverse() const {
        auto vis = pinfo::InverseVisitor();
        vis.over = this->dummy;
        vis.inverse = FCPacketInfo::isInverse();
        return apply_visitor(vis, m_packet_info);
    }


    Packet *getPacket() {
        auto vis = pinfo::PacketVisitor();
        vis.over = this->dummy;
        vis.packet = FCPacketInfo::getPacket();
        return apply_visitor(vis, m_packet_info);
    }


    FCHash getHash() const { 
        return apply_visitor(pinfo::HashVisitor(), m_packet_info);
    }

    bool dummy = true;
private:
    boost::variant<Fs*...> m_fstore;
    boost::variant<boost::blank, typename Fs::packet_info...> m_packet_info;

    template <typename _F, typename ..._Fs>
    friend class FSHiearchyWrapper;
};



struct DerefVisitor : public boost::static_visitor<FCRecordPtr>
{
    template <typename T>
    FCRecordPtr operator () (T accessor) const
    {
        return *accessor;
    }
};

template <>
FCRecordPtr DerefVisitor::operator()<boost::blank>(boost::blank accessor) const
{
    return nullptr;
}

template <typename ...Fs>
class FSHierarchyAccessor
{
public:
    FSHierarchyAccessor() {}; //To allows construct end iterators
    FSHierarchyAccessor(const FSHierarchyAccessor &it) : m_fstore(it.m_fstore), m_accessor(it.m_accessor) {}

    template <typename A>
    FSHierarchyAccessor(boost::variant<Fs*...> fstore, A accessor) : 
        m_fstore(fstore), m_accessor(accessor) {}

    template <typename U, typename A>
    FSHierarchyAccessor(U *fstore, A accessor) : 
        m_fstore(fstore), m_accessor(accessor) {}


    // Get the data element at this position
    FCRecordPtr operator*() const
    {
        return apply_visitor(DerefVisitor(), m_accessor);
    }

    // Get the data element at this position
    FCRecordPtr operator->() const
    {
        return apply_visitor(DerefVisitor(), m_accessor);
    }

    boost::variant<boost::blank, Fs*...> getFStore() const { return m_fstore; };
    boost::variant<boost::blank, typename Fs::accessor...> getAccessor() const { return m_accessor; };

    // // Comparison operators
    bool operator== (const FSHierarchyAccessor &lhs) const
    {   
        return m_accessor == lhs.m_accessor;
    }
    bool operator!= (const FSHierarchyAccessor &lhs) const { return !((*this) == lhs);}

private:
    boost::variant<boost::blank, Fs*...> m_fstore;
    boost::variant<boost::blank, typename Fs::accessor...> m_accessor;

    template <typename _F, typename ..._Fs>
    friend class FSHiearchyWrapper;
};

template <typename F, typename ...Fs>
class FSHierarchyIterator  
    : public boost::iterator_adaptor<
        FSHierarchyIterator<F, Fs...>   // Derived
      , typename F::iterator            // Base
      , boost::use_default              // Value
      , boost::forward_traversal_tag    // CategoryOrTraversal
    >
{
    typedef typename F::iterator iterator;
    typedef FSHierarchyAccessor<Fs...> accessor;
public:
    FSHierarchyIterator() : FSHierarchyIterator::iterator_adaptor() {}
    FSHierarchyIterator(const FSHierarchyIterator &it) : FSHierarchyIterator::iterator_adaptor(it.base()),  m_fstore(it.m_fstore) {}
    FSHierarchyIterator(F *fstore, iterator it) : FSHierarchyIterator::iterator_adaptor(it), m_fstore(fstore) {}

    boost::variant<Fs*...> getFStore() const { return m_fstore; };
    iterator getIter() const {return this->base(); }

    // Comparison operators
    bool operator== (const FSHierarchyIterator &lhs) const { 
        return this->base() == lhs.base();
    };
    bool operator!= (const FSHierarchyIterator &lhs) const { return !((*this) == lhs); };
private:
    boost::variant<Fs*...> m_fstore;
};

template <typename F, typename ...Fs>
class FSHiearchyWrapper : public FlowStore<FSHierarchyPacketInfo<Fs...>, FSHierarchyAccessor<Fs...>, FSHierarchyIterator<F, Fs...>, typename F::parser>
{
public:
    typedef FSHierarchyPacketInfo<Fs...> packet_info;
    typedef FSHierarchyAccessor<Fs...> accessor;
    typedef FSHierarchyIterator<F, Fs...> iterator;
    typedef typename F::parser parser;

    void init(parser &parser) { m_fstore->init(parser); }

    iterator begin() { return iterator(m_fstore, m_fstore->begin()); }
    iterator end() { return iterator(m_fstore, m_fstore->end()); }
    packet_info prepare(Packet &pkt, bool inverse) { return packet_info(m_fstore, m_fstore->prepare(pkt, inverse)); }
    accessor lookup(packet_info &pkt) {
        return accessor(m_fstore, m_fstore->lookup(boost::get<typename F::packet_info>(pkt.getInfo())));
    }
    accessor lookup_empty(packet_info &pkt) {
        return accessor(m_fstore, m_fstore->lookup_empty(boost::get<typename F::packet_info>(pkt.getInfo())));
    }
    accessor lookup_end() {
        return accessor(m_fstore, m_fstore->lookup_end());
    }
    accessor free(packet_info &pkt) {
        return accessor(m_fstore, m_fstore->free(boost::get<typename F::packet_info>(pkt.getInfo())));
    }
    accessor put(const accessor& acc) {
        return accessor(m_fstore, m_fstore->put(boost::get<typename F::accessor>(acc.getAccessor())));
    }
    accessor index_export(const accessor &acc, FlowRingBuffer &rb) {
        return accessor(m_fstore, m_fstore->index_export(boost::get<typename F::accessor>(acc.getAccessor()), rb));
    }
    accessor iter_export(const iterator &it, FlowRingBuffer &rb) {
        return accessor(m_fstore, m_fstore->iter_export(it.getIter(), rb));
    }

    void setFStore(F* store) {
        this->m_fstore = store;
    }

private:
    F* m_fstore;
};



template <typename ...Fs>
class FlowStoreHiearchyParser : public OptionsParser {
public:
    typedef std::tuple<
        std::pair<
            std::string,
            typename Fs::parser
        >...
    > ParserOptions;

    ParserOptions m_hiearchy_options;

    ParserOptions& get_options()
    {
        return m_hiearchy_options;
    }

    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I == sizeof...(Tp), void>::type
    register_options_for_each(std::tuple<Tp...> &) // Unused arguments are given no names.
    { 
    }

    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I < sizeof...(Tp), void>::type
    register_options_for_each(std::tuple<Tp...>& t)
    {
        auto &p = std::get<I>(t);
        auto &destStr = std::get<0>(p);
        auto &parser = std::get<1>(p);
        parser.setDelim('|');
        
        std::stringstream ss;
        ss << std::endl;
        parser.usage(ss, 8);
        register_option((std::to_string(I)), ("--" + std::to_string(I)), std::string("ARG1|ARG2|ARG3"), std::string(ss.str()),
                [&](const char *arg) {
                    destStr = std::string(arg);
                    return true;
                }, OptionFlags::RequiredArgument);
        register_options_for_each<I + 1, Tp...>(t);
    }

    FlowStoreHiearchyParser(const std::string &name = "hiearchy", const std::string &desc = "Desc") : OptionsParser(name, desc)
    {
        register_options_for_each(m_hiearchy_options);
    }


    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I == sizeof...(Tp), void>::type
    parse_for_each(const std::tuple<Tp...> &) const// Unused arguments are given no names.
    { 
    }

    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I < sizeof...(Tp), void>::type
    parse_for_each(const std::tuple<Tp...>& t) const
    {
        auto &p = std::get<I>(t);
        auto &destStr = std::get<0>(p);
        auto &parser = std::get<1>(p);
        parser.parse(destStr.c_str());
        parse_for_each<I + 1, Tp...>(t);
    }

    void parse(const char *args) const
    {
        OptionsParser::parse(args);
        parse_for_each(this->m_hiearchy_options);
    }
};


template <typename ...Fs>
struct FSHTypes
{
    typedef std::tuple<
        std::pair<
            FSHiearchyWrapper<Fs, Fs...>,
            Fs
        >
    ...> wrap_stores;
    typedef decltype(
        join_many(
            std::declval<
                FSHiearchyWrapper<Fs, Fs...>    
            >()...
        )
    ) range;
    
    typedef typename range::iterator iter;
    typedef FSHierarchyPacketInfo<Fs...> info;
    typedef FSHierarchyAccessor<Fs...> access; 
    typedef FlowStoreHiearchyParser<Fs...> parser; 
    typedef FlowStore
    <
        info, 
        access, 
        iter, 
        parser
    > Base;

    template<typename Function, typename Tuple, size_t ... I>
    auto call(Function f, Tuple t, std14::index_sequence<I ...>)
    {
        return f(std::get<I>(t) ...);
    }

    template<typename Function, typename Tuple>
    auto call(Function f, Tuple t)
    {
        static constexpr auto size = std14::tuple_size<Tuple>::value;
        return call(f, t, std14::make_index_sequence<size>{});
    }

    struct WrapVisitor {
        template<typename P>
        auto operator()(P p) 
        {
            return std::get<0>(p);
        }
    };

    template<typename Tuple, size_t ... I>
    auto extractWrap(Tuple &t, std14::index_sequence<I ...>)
    {
        return std::make_tuple((std::get<0>(std::get<I>(t)))...);
    }

    template<typename Tuple>
    auto extractWrap(Tuple &t)
    {
        static constexpr auto size = std14::tuple_size<Tuple>::value;
        return extractWrap(t, std14::make_index_sequence<size>{});
    }

    template<typename T>
    range expandTupleRange(T &input) 
    {
        return call(join_many, extractWrap(input));
    }

    template<typename T>
    inline typename std::enable_if<std::is_base_of<join_iterator_identifier, T>::value, boost::variant<Fs*...>>::type
    storeFromRange(T rangeIterator)
    {
        if (rangeIterator.m_section)
        {
            return storeFromRange(rangeIterator.m_it.it2());
        }
        else {
            return storeFromRange(rangeIterator.m_it.it1());
        }
    }

    template<typename T>
    inline typename std::enable_if<!std::is_base_of<join_iterator_identifier, T>::value, boost::variant<Fs*...>>::type
    storeFromRange(T rangeIterator)
    {
        return rangeIterator.getFStore();
    }


    template<typename T, typename Fh>
    inline typename std::enable_if<std::is_base_of<join_iterator_identifier, T>::value, access>::type
    iterExportRange(T rangeIterator, Fh &flowStore, FlowRingBuffer &rb)
    {
        if (rangeIterator.m_section)
        {
            return iterExportRange(rangeIterator.m_it.it2(), flowStore, rb);
        }
        else {
            return iterExportRange(rangeIterator.m_it.it1(), flowStore, rb);
        }
    }

    template<typename T, typename Fh>
    inline typename std::enable_if<!std::is_same<typename Fh::iterator, T>::value, access>::type
    iterExportRangeCall(T iter, Fh &flowStore, FlowRingBuffer &rb)
    {
        return access();
    }

    template<typename T, typename Fh>
    inline typename std::enable_if<std::is_same<typename Fh::iterator, T>::value, access>::type
    iterExportRangeCall(T iterator, Fh &flowStore, FlowRingBuffer &rb)
    {
        return flowStore.iter_export(iterator, rb);
    }


    template<typename T, typename Fh>
    inline typename std::enable_if<!std::is_base_of<join_iterator_identifier, T>::value, access>::type
    iterExportRange(T rangeIterator, Fh &flowStore, FlowRingBuffer &rb)
    {
        return iterExportRangeCall(rangeIterator, flowStore, rb);
    }
 };

template <typename ...Fs>
class FlowStoreHiearchy : public FSHTypes<Fs...>::Base
{
    typedef FSHTypes<Fs...> Types;
    typedef typename FSHTypes<Fs...>::Base Base;
public:    
    typedef typename Types::range range;
    typedef typename Types::wrap_stores wrap_stores;
    typedef typename Base::iterator iterator;
    typedef typename Base::accessor accessor;
    typedef typename Base::packet_info packet_info;
    typedef typename Base::parser parser;


    struct ConstuctVisitor : public boost::static_visitor<void>
    {
        template <typename F>
        void operator () (F &pair) const
        {
            auto &wrapper = std::get<0>(pair);
            wrapper.setFStore(&std::get<1>(pair));
        }
    };

    FlowStoreHiearchy() : Base() 
    {
        for_each(m_fstores, ConstuctVisitor());
    }


    template<std::size_t I = 0, 
        template<typename...> class Tuple,
        typename... Tp, typename... Opt
    >
    inline typename std::enable_if<I == sizeof...(Tp), void>::type
    init_for_each(Tuple<Tp...>&, Tuple<Opt...>&) // Unused arguments are given no names.
    { 
    }

    template<std::size_t I = 0, 
        template<typename...> class Tuple,
        typename... Tp, typename... Opt
    >
    inline typename std::enable_if<I < sizeof...(Tp), void>::type
    init_for_each(Tuple<Tp...>& t, Tuple<Opt...>& opt)
    {
        auto &p = std::get<I>(t);
        auto &store = std::get<1>(p);
        auto &optP = std::get<I>(opt);
        auto &parser = std::get<1>(optP);
        store.init(parser);
        init_for_each<I + 1>(t, opt);
    }

    void init(parser &parser) { 
        init_for_each(m_fstores, parser.get_options());
    }

    range m_current_range;
    iterator begin() {
        m_current_range = Types().expandTupleRange(m_fstores);
        return m_current_range.begin();
    }

    iterator end() {
        return m_current_range.end();
    }

    packet_info prepare(Packet &pkt, bool inverse = false) { 
        //Prepare from all.
        return packet_info(pkt, inverse);
    }


    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I == sizeof...(Tp), accessor>::type
    loopup_for_each(std::tuple<Tp...> &, packet_info &) // Unused arguments are given no names.
    { 
        return lookup_end();
    }

    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I < sizeof...(Tp), accessor>::type
    loopup_for_each(std::tuple<Tp...>& t, packet_info &pkt)
    {
        auto &p = std::get<I>(t);
        auto &fstore = std::get<0>(p);
        auto pktInfo = fstore.prepare(*pkt.getPacket(), pkt.isInverse());
        auto lRes = fstore.lookup(pktInfo);
        if(lRes == fstore.lookup_end()) {
            return loopup_for_each<I + 1, Tp...>(t, pkt);
        }
        pkt = pktInfo;
        pkt.dummy = false;
        return lRes;
    }

    accessor lookup(packet_info &pkt) {
        return loopup_for_each(m_fstores, pkt);
    }


    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I == sizeof...(Tp), accessor>::type
    loopup_empty_for_each(std::tuple<Tp...> &, packet_info &) // Unused arguments are given no names.
    { 
        return lookup_end();
    }

    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I < sizeof...(Tp), accessor>::type
    loopup_empty_for_each(std::tuple<Tp...>& t, packet_info &pkt)
    {
        auto &p = std::get<I>(t);
        auto &fstore = std::get<0>(p);
        auto pktInfo = fstore.prepare(*pkt.getPacket(), pkt.isInverse());
        auto lRes = fstore.lookup_empty(pktInfo);
        if(lRes == fstore.lookup_end()) {
            return loopup_empty_for_each<I + 1, Tp...>(t, pkt);
        }
        pkt = pktInfo;
        pkt.dummy = false;
        return lRes;
    }

    accessor lookup_empty(packet_info &pkt) {
        return loopup_empty_for_each(m_fstores, pkt);
    }

    accessor lookup_end() {
        return accessor();
    }


    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I == sizeof...(Tp), accessor>::type
    free_for_each(std::tuple<Tp...> &, packet_info &) // Unused arguments are given no names.
    {
        return lookup_end();
    }

    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I < sizeof...(Tp), accessor>::type
    free_for_each(std::tuple<Tp...>& t, packet_info &pkt)
    {
        auto &p = std::get<I>(t);
        auto &fstore = std::get<0>(p);
        auto pktInfo = fstore.prepare(*pkt.getPacket(), pkt.isInverse());
        auto lRes = fstore.free(pktInfo);
        if(lRes == fstore.lookup_end()) {
            return free_for_each<I + 1, Tp...>(t, pkt);
        }
        pkt = pktInfo;
        pkt.dummy = false;
        return lRes;
    }

    accessor free(packet_info &pkt) {   
        return free_for_each(m_fstores, pkt);
    }


    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I == sizeof...(Tp), accessor>::type
    put_for_each(std::tuple<Tp...> &, const accessor& index) // Unused arguments are given no names.
    { 
        return lookup_end();
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
    inline typename std::enable_if<I < sizeof...(Tp), accessor>::type
    put_for_each(std::tuple<Tp...>& t, const accessor& index)
    {
        auto &p = std::get<I>(t);
        auto &fhstore = std::get<0>(p);
        auto &fstore = std::get<1>(p);
        if(index.getFStore().which() != I+1) {
            return put_for_each<I + 1, Tp...>(t, index);
        }
        auto indexStore = getIndex<I+1>(index.getFStore());
        if(&fstore != indexStore) {
            return put_for_each<I + 1, Tp...>(t, index);
        }
        return fhstore.put(index);
    }

    accessor put(const accessor& index) {
        return put_for_each(m_fstores, index);
    }


    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I == sizeof...(Tp), accessor>::type
    index_export_for_each(std::tuple<Tp...> &, const accessor& index, FlowRingBuffer &rb) // Unused arguments are given no names.
    { 
        return lookup_end();
    }

    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I < sizeof...(Tp), accessor>::type
    index_export_for_each(std::tuple<Tp...>& t, const accessor& index, FlowRingBuffer &rb)
    {
        auto &p = std::get<I>(t);
        auto &fhstore = std::get<0>(p);
        auto &fstore = std::get<1>(p);
        if(index.getFStore().which() != I+1) {
            return index_export_for_each<I + 1, Tp...>(t, index, rb);
        }
        auto indexStore = getIndex<I+1>(index.getFStore());
        if(&fstore != indexStore) {
            return index_export_for_each<I + 1, Tp...>(t, index, rb);
        }
        return fhstore.index_export(index, rb);
    }

    accessor index_export(const accessor &index, FlowRingBuffer &rb) {
        return index_export_for_each(m_fstores, index, rb);
    }

    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I == sizeof...(Tp), FlowStoreStat::Ptr>::type
    stats_export_for_each(std::tuple<Tp...> &, FlowStoreStat::Ptr agg) // Unused arguments are given no names.
    {
        return agg;
    }

    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I < sizeof...(Tp), FlowStoreStat::Ptr>::type
    stats_export_for_each(std::tuple<Tp...>& t, FlowStoreStat::Ptr agg)
    {
        auto &p = std::get<I>(t);
        auto &fhstore = std::get<0>(p);
        auto &fstore = std::get<1>(p);
        auto ptr = fstore.stats_export();
        FlowStoreStat::PtrVector ptrVec = { ptr };
        return stats_export_for_each<I + 1, Tp...>(t, FlowStoreStatExpand(agg, ptrVec));
    }

    FlowStoreStat::Ptr stats_export() {
        return stats_export_for_each(m_fstores, std::make_shared<FlowStoreStatVector>(""));
    };


    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I == sizeof...(Tp), accessor>::type
    iter_export_for_each(std::tuple<Tp...> &, const iterator& index, FlowRingBuffer &rb) // Unused arguments are given no names.
    { 
        return lookup_end();
    }

    template<std::size_t I = 0, typename... Tp>
    inline typename std::enable_if<I < sizeof...(Tp), accessor>::type
    iter_export_for_each(std::tuple<Tp...>& t, const iterator& index, FlowRingBuffer &rb)
    {
        auto &p = std::get<I>(t);
        auto &fhstore = std::get<0>(p);
        auto &fstore = std::get<1>(p);
        auto storeTup = Types().storeFromRange(index);
        if(storeTup.which() != I) {
            return iter_export_for_each<I + 1, Tp...>(t, index, rb);
        }
        auto indexStore = getIndex<I>(storeTup);
        if(&fstore != indexStore) {
            return iter_export_for_each<I + 1, Tp...>(t, index, rb);
        }
        return Types().iterExportRange(index, fhstore, rb);
    }

    accessor iter_export(const iterator &index, FlowRingBuffer &rb) {
        return iter_export_for_each(m_fstores, index, rb);
    }

private:
    template<std::size_t I = 0, typename FuncT, typename... Tp>
    inline typename std::enable_if<I == sizeof...(Tp), void>::type
    for_each(std::tuple<Tp...> &, FuncT) // Unused arguments are given no names.
    { }

    template<std::size_t I = 0, typename FuncT, typename... Tp>
    inline typename std::enable_if<I < sizeof...(Tp), void>::type
    for_each(std::tuple<Tp...>& t, FuncT f)
    {
        f(std::get<I>(t));
        for_each<I + 1, FuncT, Tp...>(t, f);
    }
    wrap_stores m_fstores;
};

}


#endif //IPXP_HIEARCHY_STORE_HPP
