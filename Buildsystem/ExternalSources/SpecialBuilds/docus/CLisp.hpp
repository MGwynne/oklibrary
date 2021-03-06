// Oliver Kullmann, 26.12.2007 (Swansea)
/* Copyright 2007, 2008, 2009 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Buildsystem/ExternalSources/SpecialBuilds/docus/CLisp.hpp
  \brief Documentation on how to build CLisp


  <h1> Installing CLisp </h1>


  <h2> On the purpose of CLisp </h2>

  The computer algebra system Maxima is implemented in "Common Lisp", and
  CLisp is an implementation of this form of Lisp.

  We do not use CLisp directly, only indirectly through Maxima.


  <h2> What the installation yields </h2>

  <ul>
   <li> The clisp-executable, used for compiling lisp-files as well as an
   interactive interpreter. </li>
   <li> Documentation on Common Lisp in general, and on the usage of
   the clisp-executable. </li>
   <li> Library-files, needed to execute lisp-files. </li>
  </ul>


  <h2> Current state of installation </h2>

  <ul>
   <li> Recommended version: $(clisp_recommended_version_number_okl) </li>
   <li> Checking the installation:
    <ol>
     <li> clisp-program call = <code>$(clisp_call_okl)</code> </li>
     <li> ready: $(clisp_call_ready_okl)
      <ul>
       <li> location = $(location_clisp_call_okl) </li>
       <li> version = <code>$(version_clisp_call_okl)</code> </li>
      </ul>
     </li>
    </ol>
   </li>
   <li> Documentation: $(clisp_html_documentation_index_location_tag_okl) </li>
  </ul>


  <h2> How to install </h2>

  <ul>
   <li> CLisp comes with Linux distributions, so you could install it
   with your distribution tool, however then you need to configure
   the build-system of the OKlibrary accordingly. </li>
   <li> We recommend local installation. </li>
  </ul>


  <h3> Prerequisites </h3>

  <ul>
   <li> "libsigsegv" is needed (the clisp installation process will
   tell you about it); it can be installed as shown below. </li>
   <li> At least on 64-bit machines also "libffcall" is needed;
   it can be installed as shown below. </li>
   <li> Using target <code>clispall</code> below is the easiest
   way to build CLisp (this takes care of all prerequisites). </li>
  </ul>


  <h3> Make targets </h3>

  Only local installation currently.
  <table>
   <tr>
    <td> <code> clisp </code> </td>
    <td> Build the recommended version of clisp. </td>
   </tr>
   <tr>
    <td> <code> cleanclisp </code> </td>
    <td> Removes the clisp build directory. </td>
   </tr>
   <tr>
    <td> <code> cleanallclisp </code> </td>
    <td> Removes all clisp build/installation/documentation directories. </td>
   </tr>
   <tr>
    <td> <code> libsigsegv </code> </td>
    <td> Build the recommended version of libsigsegv. </td>
   </tr>
   <tr>
    <td> <code> cleanlibsigsegv </code> </td>
    <td> Removes the libsigsegv build directory. </td>
   </tr>
   <tr>
    <td> <code> cleanalllibsigsegv </code> </td>
    <td> Removes all libsigsegv build/installation/documentation directories. </td>
   </tr>
   <tr>
    <td> <code> libffcall </code> </td>
    <td> Build the recommended version of libffcall. </td>
   </tr>
   <tr>
    <td> <code> cleanlibffcall </code> </td>
    <td> Removes the libffcall build directory. </td>
   </tr>
   <tr>
    <td> <code> cleanalllibffcall </code> </td>
    <td> Removes all libffcall build/installation/documentation directories. </td>
   </tr>
   <tr>
    <td> <code> clispall </code> </td>
    <td> Calls libsigsegv, libffcall and clisp. </td>
   </tr>
   <tr>
    <td> <code> cleanclispall </code> </td>
    <td> Calls cleanlibsigsegv, cleanlibffcall and cleanclisp. </td>
   </tr>
   <tr>
    <td> <code> cleanallclispall </code> </td>
    <td> Calls cleanalllibsigsegv, cleanalllibffcall and cleanallclisp. </td>
   </tr>
  </table>


  <h3> Configuration </h3>

  <ul>
   <li> To install a different version of CLisp, set variable
   <code>clisp_recommended_version_number_okl</code> accordingly. </li>
   <li> To install a different version of Libsigsegv, set variable
   <code>libsigsegv_recommended_version_number_okl</code> accordingly. </li>
    <li> To install a different version of Libffcall, set variable
   <code>libffcall_recommended_version_number_okl</code> accordingly. </li>
 </ul>


*/

