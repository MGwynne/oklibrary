// Oliver Kullmann, 5.12.2005

/*!
  \file TestBaseClass_DesignStudy.hpp
  \brief Design studies for the new test hierarchy.
  \todo Log messages must contain automatic information, and must be easily recognisable.
  \todo For convenience three standard instantiations of the three streams are provided:
   - normal run:
     error = std::cerr, messages = log = std::cout, normal messages on, log messages off
   - nightly run:
     error = error-file, messages = log = log-file, normal messages on, log messages on,
     error is copied to log-file
   - normal run with file storage:
     error = error-file, messages = std::cout, log = log-file, normal messages on, log messages on,
     error is copied to std::cerr and log_file, messages is copied to log_file.
   To implement these, we must investigate the standard iostream and buffer classes, and the
   boost iostreams library.
   \todo Try to extend the level hierarchy.
   \todo In case an unknown exception is thrown, there should be a global option to
   let this exception through.
*/

#ifndef TESTBASECLASSTEMPORARY_8uXXzs

#define TESTBASECLASSTEMPORARY_8uXXzs

#include <cstdlib>
#include <exception>
#include <cassert>

#include <boost/ptr_container/ptr_list.hpp>
#include <boost/timer.hpp>

#include "TimeHandling.hpp"

#include "TestExceptions_DesignStudy.hpp"

namespace OKlib {

  namespace TestSystem {

    class Basic;

    /*!
      \class Test
      \brief The root of the (polymorphic) test hierarchy; containers of testobjects are
      containers of Test pointers.

      The member function template perform is to be called by a "visitor" from the level
      hierarchy.
    */

    struct Test {
      virtual ~Test() {}
      template <class TestLevel>
      void perform(TestLevel, std::ostream& log) {
        perform_(TestLevel(), log);
      }
      
    private :
      virtual void perform_(Basic, std::ostream& log) = 0;
    };

    // ###################################################

    /*!
      \class TestLevel
      \brief The root of the (polymorphic) test-level hierarchy.
    */

    struct TestLevel {
      virtual void perform(Test& test, std::ostream& log) const = 0;
      virtual const char* description() const = 0;
      virtual ~TestLevel() {}
    };

    struct Basic : TestLevel {
      void perform(Test& test, std::ostream& log) const {
        test.perform(Basic(), log);
      }
      const char* description() const { return "Basic test level"; }
    };
    struct Full : Basic {
      void perform(Test& test, std::ostream& log) const {
        test.perform(Full(), log);
      }
      const char* description() const { return "Full test level"; }
    };
    struct Extensive : Full {
      void perform(Test& test, std::ostream& log) const {
        test.perform(Extensive(), log);
      }
      const char* description() const { return "Extensive test level"; }
    };

    inline const TestLevel* test_level(const char* const level_description) {
      switch (level_description[0]) {
      case 'f' : return new Full;
      case 'e' : return new Extensive;
      default : return new Basic;
      }
    }

    // ###################################################

    /*!
      \class TestBase
      \brief Derived from the test, to be used as immediate base class for test-meta-functions.
    */

    template <class TestFunction>
    class TestBase : public Test {
    protected :
      typedef TestFunction test_type;
    private :
      void perform_(Basic, std::ostream& log) {
        perform_and_catch(Basic(), log);
      }
      template <class TestLevel>
      void perform_and_catch(TestLevel, std::ostream& log) {
        typedef TestLevel level_type;
        try {
          test(TestLevel(), log);
        }
        catch(const TestException&) {
          throw;
        }
        catch(const std::exception& e) {
          TestException e_new(std::string("std::exception\n   what = \"") + e.what() + "\"\n   type = " + typeid(e).name());
          e_new.add(OKLIB_TESTDESCRIPTION);
          throw e_new;
        }
        catch(...) {
          TestException e("unknown exception");
          e.add(OKLIB_TESTDESCRIPTION);
          throw e;
        }
      }
      virtual void test(Basic, std::ostream& log) = 0;
    };


    // ###################################################


    
    class RunTest {
      RunTest(const RunTest&); // not available
      RunTest& operator =(const RunTest&); // not available

    public :
      typedef Test test_type;
      typedef Test* test_pointer_type;

      typedef boost::ptr_list<test_type> container_type;

    private :

      static container_type& handle_test_objects(const test_pointer_type p = 0) {
        static container_type test_objects;
        if (p)
          test_objects.push_back(p);
        return test_objects;
      }

    public :

      RunTest(Test* const test) {
        // takes over ownership of test object
        handle_test_objects(test);
      }

      static int run_tests(std::ostream& err, std::ostream& messages, std::ostream& log, const TestLevel* const level) {
        return run_tests(err, messages, log, level, handle_test_objects());
      }
        
      static int run_tests(std::ostream& err, std::ostream& messages, std::ostream& log, const TestLevel* const level, container_type& test_objects) {
        // does not take ownership of level object
        assert(level);

        messages << "OKlib::TestSystem::RunTest " << "\n";
        messages << TimeHandling::currentDateTime("%A, %B %e, %Y; %H:%M:%S%n");
        messages << level -> description() << "\n";
        typedef container_type::size_type size_type;
        {
          const size_type& size(test_objects.size());
          messages << size << " testobject";
          if (size != 1) messages << "s";
          messages << ".\n";
        }
        messages << std::endl;

        int return_value = 0;
        boost::timer timer;
        TimeHandling::WallTime total_time;

        typedef container_type::iterator iterator;
        const iterator& end(test_objects.end());
        size_type counter = 1;
        size_type err_counter = 0;
        for (iterator i(test_objects.begin()); i != end; ++i, ++counter) {
          log << "No. " << counter << std::endl;
          try {
            level -> perform(*i, log);
          }
          catch(const OKlib::TestSystem::TestException& e) {
            ++err_counter;
            err << e << std::endl;
            return_value = EXIT_FAILURE;
          }
          log << "\n";
        }

        {
          messages << err_counter << " error";
          if (err_counter != 1) messages << "s";
          messages << ".\n";
        }
        messages << "\nElapsed system time: " << timer.elapsed() << "s\n";
        messages << "Elapsed total time: " << double(total_time) << "s\n";
        return return_value;
      }
    };

  }
  
}

#endif
