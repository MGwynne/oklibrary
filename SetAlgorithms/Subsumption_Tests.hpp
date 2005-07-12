// Oliver Kullmann, 2.7.2005 (Swansea)

#ifndef SUBSUMPTIONTESTS_119jBd

#define SUBSUMPTIONTESTS_119jBd

#include <set>
#include <list>
#include <algorithm>
#include <functional>

#include <boost/assign/list_of.hpp>

#include "TestBaseClass.hpp"
#include "TestExceptions.hpp"

#include "OrderConstructions.hpp"
    
namespace OKlib {

  namespace SetAlgorithms {

    template
    <template <class ContainerSets,
               class UniquenessTag = SubsumptionsTags::hyperedges_may_not_be_unique,
               class OrderTag = SubsumptionsTags::hyperedges_may_not_be_sorted_by_size,
               class SizeTag = typename boost::mpl::if_<typename OKlib::MetaProgramming::has_size_function<ContainerSets>::type, SubsumptionsTags::use_size_of_hyperedges, SubsumptionsTags::do_not_use_size_of_hyperedges>::type>
    class Subsumption_elimination>
    class Test_Subsumption_elimination : public ::OKlib::TestSystem::TestBase {
    public :
      typedef Test_Subsumption_elimination test_type;
      Test_Subsumption_elimination() {
        insert(this);
      }
    private :
      
      void perform_test_trivial() {

        {
          typedef int value_type;
          typedef std::set<value_type> set_type;
          typedef std::set<set_type> container_type;
          typedef container_type::iterator container_iterator;
          typedef Subsumption_elimination<container_type> elimination_type;
          elimination_type sub_elim;

          { // empty sequence
            container_type empty;
            sub_elim.upward(empty, empty.begin(), empty.end());
            OKLIB_TEST_EQUAL_RANGES(empty, container_type());
            sub_elim(empty);
            OKLIB_TEST_EQUAL_RANGES(empty, container_type());
          }
          { // example sequence
            container_type seq;
            seq.insert(boost::assign::list_of(1) (2));
            const container_iterator first_subsumption = seq.insert(boost::assign::list_of(1) (2) (3)).first;
            container_iterator second_subsumption = seq.insert(boost::assign::list_of(2) (3) (4)).first;
            seq.insert(boost::assign::list_of(3) (4));
            const container_type orig(seq);
            seq.erase(first_subsumption);
            {
              container_type seq2(orig);
              sub_elim.upward(seq2, seq2.begin(), seq2.end());
              OKLIB_TEST_EQUAL_W2(seq2, seq);
              seq.erase(second_subsumption);
              sub_elim.upward(seq2, seq2.rbegin(), seq2.rend());
              OKLIB_TEST_EQUAL_W2(seq2, seq);
            }
            {
              container_type seq2(orig);
              sub_elim(seq2);
              OKLIB_TEST_EQUAL_W2(seq2, seq);
            }
            {
              typedef std::list<set_type> container_type;
              container_type seq2(orig.begin(), orig.end());
              typedef Subsumption_elimination<container_type> elimination_type;
              elimination_type sub_elim;
              sub_elim(seq2);
              OKLIB_TEST_EQUAL_RANGES(seq2, seq);
            }
            {
              typedef std::list<set_type> container_type;
              container_type seq2(orig.begin(), orig.end());
              seq2.insert(seq2.end(), orig.begin(), orig.end());
              seq2.sort(OKlib::OrderRelations::SizeLessThan<std::less<set_type> >());
              seq2.erase(std::unique(seq2.begin(), seq2.end()), seq2.end());
              typedef Subsumption_elimination<container_type, SubsumptionsTags::hyperedges_are_unique, SubsumptionsTags::hyperedges_sorted_by_size> elimination_type;
              elimination_type sub_elim;
              sub_elim(seq2);
              OKLIB_TEST_EQUAL_RANGES(seq2, seq);
            }
          }
        }

      }

    };

    /*!
      \class Test_Subsumption_elimination
      \todo Systematic tests of all 8 combinations for the tags.
    */

  }

}

#endif
