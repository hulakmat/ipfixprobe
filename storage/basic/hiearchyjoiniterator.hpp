

// Boost.Range library 
//
//  Copyright Neil Groves 2009. Use, modification and
//  distribution is subject to the Boost Software License, Version
//  1.0. (See accompanying file LICENSE_1_0.txt or copy at
//  http://www.boost.org/LICENSE_1_0.txt)
//
// Acknowledgements:
// aschoedl contributed an improvement to the determination
// of the Reference type parameter.
//
// Leonid Gershanovich reported Trac ticket 7376 about the dereference operator
// requiring identical reference types due to using the ternary if.
//
// For more information, see http://www.boost.org/libs/range/
//

#include <valarray>
#include <iterator>
#include <boost/assert.hpp>
#include <boost/range/iterator_range_core.hpp>
#include <boost/iterator/iterator_traits.hpp>
#include <boost/iterator/iterator_facade.hpp>
#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <boost/range/empty.hpp>
#include <boost/range/detail/demote_iterator_traversal_tag.hpp>
#include <boost/range/value_type.hpp>
#include <boost/type_traits/add_const.hpp>
#include <boost/type_traits/add_reference.hpp>
#include <boost/type_traits/remove_const.hpp>
#include <boost/type_traits/remove_reference.hpp>
#include <boost/next_prior.hpp>
#include <boost/range/concepts.hpp>

namespace ipxjoin {
    using ::boost::iterator_value;
    using ::boost::iterator_facade;
    using ::boost::iterator_range;
    using ::boost::range_value;
    using ::boost::range_iterator;
    using ::boost::is_reference;
    using ::boost::SinglePassRangeConcept;
    using ::boost::mpl::if_c;
    using ::boost::iterator_reference;
    using ::boost::remove_reference;
    using ::boost::add_const;
    using ::boost::remove_const;
    using ::boost::is_const;
    using ::boost::iterator_traversal;
    using ::boost::range_detail::demote_iterator_traversal_tag;

    namespace range_detail
    {

template<typename Iterator1, typename Iterator2>
struct join_iterator_link
{
public:
    join_iterator_link(Iterator1 last1, Iterator2 first2)
        :    last1(last1)
        ,    first2(first2)
    {
    }

    Iterator1 last1;
    Iterator2 first2;

private:
    join_iterator_link() /* = delete */ ;
};

class join_iterator_begin_tag {};
class join_iterator_end_tag {};

template<typename Iterator1
       , typename Iterator2
       , typename Reference
>
class join_iterator_union
{
public:
    typedef Iterator1 iterator1_t;
    typedef Iterator2 iterator2_t;

    join_iterator_union() {}
    join_iterator_union(unsigned int /*selected*/, const iterator1_t& it1, const iterator2_t& it2) : m_it1(it1), m_it2(it2) {}

    iterator1_t& it1() { return m_it1; }
    const iterator1_t& it1() const { return m_it1; }

    iterator2_t& it2() { return m_it2; }
    const iterator2_t& it2() const { return m_it2; }

    Reference dereference(unsigned int selected) const
    {
        return selected ? *m_it2 : *m_it1;
    }

    bool equal(const join_iterator_union& other, unsigned int selected) const
    {
        return selected
            ? m_it2 == other.m_it2
            : m_it1 == other.m_it1;
    }

private:
    iterator1_t m_it1;
    iterator2_t m_it2;
};

template<class Iterator, class Reference>
class join_iterator_union<Iterator, Iterator, Reference>
{
public:
    typedef Iterator iterator1_t;
    typedef Iterator iterator2_t;

    join_iterator_union() {}

    join_iterator_union(unsigned int selected, const iterator1_t& it1, const iterator2_t& it2)
        : m_it(selected ? it2 : it1)
    {
    }

    iterator1_t& it1() { return m_it; }
    const iterator1_t& it1() const { return m_it; }

    iterator2_t& it2() { return m_it; }
    const iterator2_t& it2() const { return m_it; }

    Reference dereference(unsigned int) const
    {
        return *m_it;
    }

    bool equal(const join_iterator_union& other, unsigned int selected) const
    {
        return m_it == other.m_it;
    }

private:
    iterator1_t m_it;
};

class join_iterator_identifier {};

template<typename Iterator1
       , typename Iterator2
       , typename ValueType = typename iterator_value<Iterator1>::type
       // find least demanding, commonly supported reference type, in the order &, const&, and by-value:
       , typename Reference = typename if_c<
                !is_reference<typename iterator_reference<Iterator1>::type>::value
             || !is_reference<typename iterator_reference<Iterator2>::type>::value,
                        typename remove_const<
                            typename remove_reference<
                                typename iterator_reference<Iterator1>::type
                            >::type
                        >::type,
                        typename if_c<
                            is_const<
                                typename remove_reference<
                                    typename iterator_reference<Iterator1>::type
                                >::type
                            >::value
                            || is_const<
                                typename remove_reference<
                                    typename iterator_reference<Iterator2>::type
                                >::type
                            >::value,
                            typename add_const<
                                typename iterator_reference<Iterator2>::type
                            >::type,
                            typename iterator_reference<Iterator1>::type
                        >::type
                    >::type
       , typename Traversal = typename demote_iterator_traversal_tag<
                                  typename iterator_traversal<Iterator1>::type
                                , typename iterator_traversal<Iterator2>::type>::type
>
class join_iterator
    : public iterator_facade<join_iterator<Iterator1,Iterator2,ValueType,Reference,Traversal>, ValueType, Traversal, Reference>, public join_iterator_identifier
{
    typedef join_iterator_link<Iterator1, Iterator2> link_t;
    typedef join_iterator_union<Iterator1, Iterator2, Reference> iterator_union;
public:
    typedef Iterator1 iterator1_t;
    typedef Iterator2 iterator2_t;

    join_iterator()
        : m_section(0u)
        , m_it(0u, iterator1_t(), iterator2_t())
        , m_link(link_t(iterator1_t(), iterator2_t()))
    {}

    join_iterator(unsigned int section, Iterator1 current1, Iterator1 last1, Iterator2 first2, Iterator2 current2)
        : m_section(section)
        , m_it(section, current1, current2)
        , m_link(link_t(last1, first2))
        {
        }

    template<typename Range1, typename Range2>
    join_iterator(Range1& r1, Range2& r2, join_iterator_begin_tag)
        : m_section(boost::empty(r1) ? 1u : 0u)
        , m_it(boost::empty(r1) ? 1u : 0u, boost::begin(r1), boost::begin(r2))
        , m_link(link_t(boost::end(r1), boost::begin(r2)))
    {
    }

    template<typename Range1, typename Range2>
    join_iterator(const Range1& r1, const Range2& r2, join_iterator_begin_tag)
        : m_section(boost::empty(r1) ? 1u : 0u)
        , m_it(boost::empty(r1) ? 1u : 0u, boost::const_begin(r1), boost::const_begin(r2))
        , m_link(link_t(boost::const_end(r1), boost::const_begin(r2)))
    {
    }

    template<typename Range1, typename Range2>
    join_iterator(Range1& r1, Range2& r2, join_iterator_end_tag)
        : m_section(1u)
        , m_it(1u, boost::end(r1), boost::end(r2))
        , m_link(link_t(boost::end(r1), boost::begin(r2)))
    {
    }

    template<typename Range1, typename Range2>
    join_iterator(const Range1& r1, const Range2& r2, join_iterator_end_tag)
        : m_section(1u)
        , m_it(1u, boost::const_end(r1), boost::const_end(r2))
        , m_link(link_t(boost::const_end(r1), boost::const_begin(r2)))
    {
    }

public:
    void increment()
    {
        if (m_section)
            ++m_it.it2();
        else
        {
            ++m_it.it1();
            if (m_it.it1() == m_link.last1)
            {
                m_it.it2() = m_link.first2;
                m_section = 1u;
            }
        }
    }

    void decrement()
    {
        if (m_section)
        {
            if (m_it.it2() == m_link.first2)
            {
                m_it.it1() = boost::prior(m_link.last1);
                m_section = 0u;
            }
            else
                --m_it.it2();
        }
        else
            --m_it.it1();
    }

    typename join_iterator::reference dereference() const
    {
        return m_it.dereference(m_section);
    }

    bool equal(const join_iterator& other) const
    {
        return m_section == other.m_section
            && m_it.equal(other.m_it, m_section);
    }

    void advance(typename join_iterator::difference_type offset)
    {
        if (m_section)
            advance_from_range2(offset);
        else
            advance_from_range1(offset);
    }

    typename join_iterator::difference_type distance_to(const join_iterator& other) const
    {
        typename join_iterator::difference_type result;
        if (m_section)
        {
            if (other.m_section)
                result = other.m_it.it2() - m_it.it2();
            else
            {
                result = (m_link.first2 - m_it.it2())
                       + (other.m_it.it1() - m_link.last1);

                BOOST_ASSERT( result <= 0 );
            }
        }
        else
        {
            if (other.m_section)
            {
                result = (m_link.last1 - m_it.it1())
                       + (other.m_it.it2() - m_link.first2);
            }
            else
                result = other.m_it.it1() - m_it.it1();
        }
        return result;
    }

    void advance_from_range2(typename join_iterator::difference_type offset)
    {
        typedef typename join_iterator::difference_type difference_t;
        BOOST_ASSERT( m_section == 1u );
        if (offset < 0)
        {
            difference_t r2_dist = m_link.first2 - m_it.it2();
            BOOST_ASSERT( r2_dist <= 0 );
            if (offset >= r2_dist)
                std::advance(m_it.it2(), offset);
            else
            {
                difference_t r1_dist = offset - r2_dist;
                BOOST_ASSERT( r1_dist <= 0 );
                m_it.it1() = m_link.last1 + r1_dist;
                m_section = 0u;
            }
        }
        else
            std::advance(m_it.it2(), offset);
    }

    void advance_from_range1(typename join_iterator::difference_type offset)
    {
        typedef typename join_iterator::difference_type difference_t;
        BOOST_ASSERT( m_section == 0u );
        if (offset > 0)
        {
            difference_t r1_dist = m_link.last1 - m_it.it1();
            BOOST_ASSERT( r1_dist >= 0 );
            if (offset < r1_dist)
                std::advance(m_it.it1(), offset);
            else
            {
                difference_t r2_dist = offset - r1_dist;
                BOOST_ASSERT( r2_dist >= 0 );
                m_it.it2() = m_link.first2 + r2_dist;
                m_section = 1u;
            }
        }
        else
            std::advance(m_it.it1(), offset);
    }

    unsigned int m_section;
    iterator_union m_it;
    link_t m_link;

    friend class ::boost::iterator_core_access;
};

    } // namespace range_detail
   namespace range_detail
    {

template<class SinglePassRange1, class SinglePassRange2>
class joined_type
{
public:
    typedef iterator_range<
        range_detail::join_iterator<
            BOOST_DEDUCED_TYPENAME range_iterator<SinglePassRange1>::type,
            BOOST_DEDUCED_TYPENAME range_iterator<SinglePassRange2>::type,
            BOOST_DEDUCED_TYPENAME range_value<SinglePassRange1>::type
        >
    > type;
};

    } // namespace range_detail

namespace range
{

template<class SinglePassRange1, class SinglePassRange2>
class joined_range
    : public range_detail::joined_type<SinglePassRange1, SinglePassRange2>::type
{
    typedef range_detail::join_iterator<
        BOOST_DEDUCED_TYPENAME range_iterator<SinglePassRange1>::type,
        BOOST_DEDUCED_TYPENAME range_iterator<SinglePassRange2>::type,
        BOOST_DEDUCED_TYPENAME range_value<SinglePassRange1>::type
        > iterator_t;

    typedef BOOST_DEDUCED_TYPENAME range_detail::joined_type<
                    SinglePassRange1, SinglePassRange2>::type base_t;
public:
    joined_range(SinglePassRange1& rng1, SinglePassRange2& rng2)
        : base_t(
            iterator_t(rng1, rng2, range_detail::join_iterator_begin_tag()),
            iterator_t(rng1, rng2, range_detail::join_iterator_end_tag())
        )
    {
    }
};

template<class SinglePassRange1, class SinglePassRange2>
joined_range<const SinglePassRange1, const SinglePassRange2>
join(const SinglePassRange1& r1, const SinglePassRange2& r2)
{
    BOOST_RANGE_CONCEPT_ASSERT(( SinglePassRangeConcept<SinglePassRange1> ));
    BOOST_RANGE_CONCEPT_ASSERT(( SinglePassRangeConcept<SinglePassRange2> ));

    return joined_range<const SinglePassRange1, const SinglePassRange2>(r1, r2);
}

template<class SinglePassRange1, class SinglePassRange2>
joined_range<SinglePassRange1, SinglePassRange2>
join(SinglePassRange1& r1, SinglePassRange2& r2)
{
    BOOST_RANGE_CONCEPT_ASSERT(( SinglePassRangeConcept<SinglePassRange1> ));
    BOOST_RANGE_CONCEPT_ASSERT(( SinglePassRangeConcept<SinglePassRange2> ));

    return joined_range<SinglePassRange1, SinglePassRange2>(r1, r2);
}

} // namespace range

using ::ipxjoin::range_detail::join_iterator_identifier;
using ::ipxjoin::range::joined_range;
using ::ipxjoin::range::join;

// for ADL purposes
using ::std::begin;
using ::std::end;
using ::boost::make_iterator_range;
struct join_type {
    template<class C>
    auto operator()(C&& c) const
    -> decltype(make_iterator_range(begin(c), end(c)))
    {
        return make_iterator_range(begin(c), end(c));
    }

    template<typename First, typename Second, typename... Rest>
    auto operator()(First&& first, Second&& second, Rest&&... rest) const
    -> decltype( (*this)(join(make_iterator_range(begin(first), end(first)), make_iterator_range(begin(second), end(second))), std::forward<Rest>(rest)...) )
    {
        return (*this)(join(make_iterator_range(begin(first), end(first)), make_iterator_range(begin(second), end(second))), std::forward<Rest>(rest)...);
    }
};

constexpr join_type join_many {};

}
