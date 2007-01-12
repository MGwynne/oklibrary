// Oliver Kullmann, 28.2.2006 (Swansea)

/*!
  \file Buildsystem/plans/ExternalSources.hpp
  \brief Plans for the makefile responsible for handling external sources

  \bug Building gcc_doc 
   - does not work (that is, the link at
     system_directories/doc/index.html is not working),
     since apparently the man-pages need to be build.
  
  \todo Corrections mhash

   - We need some user-information for mhash (how to use the installed files).
   - It seems that cleanmhash should also remove the installation directory.
     (MH) Isn't it the case that we want cleanmhash only to remove the build
     directory - so that the local installation can still be used after cleaning?
     Then to clean everything there is already the target "cleanallmhash".

  \bug Building Boost

  <ul>
  <li>
  Suddenly building boost on cs-wsok with a local gcc (version 3.4.3 or
  3.4.6 for example) doesn't work anymore, but there are linking errors.
  It seems that on csltok everything works, so that it could be a
  64bit thing.
  
  What did change?? And it seems that gcc versions for example 4.1.1
  do work?? Since versions below 4.0.0 don't work, while above work,
  it seems that the system-gcc (4.0.2) interferes; perhaps it tries to
  link with the 32bit-version, can't do that, and then falls back to the
  system version?

  What is the role of LD_LIBRARY_PATH ?? (On cs-wsok it is empty.)

  OK (12.1.2007): When building boost with gcc-version 3.4.3 or 3.4.6, we get

  ...failed updating 10 targets...
  ...skipped 14 targets...

  Why this?

  We should check in general whether building boost links to the 32bit
  or to the 64bit version.
  </li>
  </ul>

  \todo General
   - It would ge good, if after doing a local installation, easily the installation could also be
     make global.
   - Optionally there should be also local versions of valgrind and doxygen (and other tools).
     This is necessary on systems where the user does not have root access.

  \todo Gcc
   - When building some gcc-version, only the necessary directories
     should be created. This should be handled as we have it now with boost (using
     timestamp-files).
   - If variable "gcc-version" is set, then it should have one of the allowed values (while otherwise we get
     an error).
   - We must understand, how gcc interacts with 32- and 64-bit environments, and how to
     take control of this.
   - There should be make-variables, which allow control over some settings for the
     compilation of gcc.
     - Building gcc should be outsourced to ExternalSources/gcc.mak. DONE

  \todo Boost
   - When building boost (in some variation) using "gcc-version=...", then as a subtarget
     we have the build of the gcc-version (so that, if necessary, gcc is build).
   - Installation of bjam should be improved: Having exactly one bjam-installation for each boost-version,
     and no need to recreate it if it's already there. Or, perhaps better: We just leave it in
     the distribution directory?
   - Building boost should include copying the documentation to doc (in the subdirectory
     boost-1_33_1 for example).
   - Building Boost should be outsourced to ExternalSources/boost.mak. DONE

  \todo Usage documentation location
   - The appropriate location for the usage documentation should be
     in the file Buildsystem/ExternalSources.hpp not distributed over
     the makefiles in Buildsystem/ExternalSources. Because that is the
     makefile which the user really uses. DONE

  \todo PostgreSQL
   - Update PostgreSQL to version 8.1 (or later; and test it).
   - "make initialise-database" should work with the recommended version (and no specification
     of the pgsql-version should be needed).
   - A detailed user-manual is needed (on how to use the installed database).

  \todo Other sources:
   - Build a local version of Xerces.
   - Build a local version of gmp.
   - Build the R system (locally and globally).
   - Build and incorporate graphviz (the dot-tool is needed by doxygen for creating the graphs)
     and tulip.
   - SOCI (soci.sourceforge.net) ?
   - gcc-xml (www.gccxml.org) ?

  \todo Tools
   - Investigate the NiX system (a system for managing libraries).

*/
