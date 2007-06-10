// Oliver Kullmann, 18.11.2006 (Swansea)

/*!
  \file Parallelism/plans/Parallelism.hpp
  \brief Plans for the module on parallelism

  \todo Run through examples from [C++ Cookbook 2006, Chapter 12]
  <ul>
   <li> 12.1 "Creating a Thread" : DONE (Parallelism/demo_Example_12_1.cpp) </li>
   <li> 12.1 Remarks about thread_group </li>
   <li> 12.2 "Making a Resource Thread-Safe" </li>
   <li> 12.3 "Notifying One Thread from Another" </li>
   <li> 12.4 "Initializing Shared Recources Once" </li>
   <li> 12.5 "Passing an Argument to a Thread Function" </li>
  </ul>

  \todo New test system
  <ol>
   <li> Transfer the tests. </li>
   <li> Extend the test-functionality so that the point where the assert
   happens (see bug-reports) can be pinpointed. </li>
   <li> How to do it right? </li>
  </ol>

  \todo Investigate libraries for processes and threads
  <ul>
   <li> Boost-1_34_0 (Threads and ???) </li>
   <li> Poco </li>
   <li> ACE </li>
  </ul>

  \todo Decide, how to handle parallel computations for the OKlibrary.

*/

/*!
  \namespace OKlib::Parallelism
  \brief Components for parallelising algorithms
*/

namespace OKlib {
  namespace Parallelism {
  }
}

