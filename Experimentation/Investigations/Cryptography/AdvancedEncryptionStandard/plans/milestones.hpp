// Oliver Kullmann, 1.1.2011 (Swansea)
/* Copyright 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Experimentation/Investigations/Cryptography/AdvancedEncryptionStandard/plans/milestones.hpp

  \module_version Investigations/Cryptography/AdvancedEncryptionStandard 0.1.5.1 (8.2.2011)


  \par Version 0.1.6 :

  \par
   In Cryptography/AdvancedEncryptionStandard/plans/general.hpp the
   following topics are handled:
    - Explain how to replace various AES boxes with identity or random boxes
    - Summary of previous experimental results
    - Merge SAT2011 plans with module one level higher : DONE
    - Add milestones : DONE
    - Replace "merge_cnf.sh" with "AppendDimacs" : DONE
    - Update scripts : DONE

  \par
   In Cryptography/AdvancedEncryptionStandard/plans/Benchmarks.hpp the
   following topics are handled:
    - Prepare benchmarks for SAT 2011

  \par
   In Cryptography/AdvancedEncryptionStandard/plans/EncryptionDecryption.hpp the
   following topics are handled:
    - Update instructions

  \par
   In Cryptography/AdvancedEncryptionStandard/plans/Representations/general.hpp
   the following topics are handled:
    - Add milestones
    - Standard naming scheme for experiment files
    - Scripts for generating statistics on random boxes

  \par
   In Cryptography/AdvancedEncryptionStandard/plans/Experimentation.hpp
   the following topics are handled:
    - Prepare experiments for the SAT 2012 paper
    - Solvers to be used for experimentation

  \par
   In Cryptography/AdvancedEncryptionStandard/plans/KeyDiscovery/general.hpp
   the following topics are handled:
    - Add milestones
    - Explanations

  \par
   In Cryptography/AdvancedEncryptionStandard/plans/KeyDiscovery/128/4_4_8/0_23_13.hpp
   the following topics are handled:
    - Problems sizes : DONE


  \par Version 0.1.7 :

  \par
   In Cryptography/AdvancedEncryptionStandard/plans/general.hpp the
   following topics are handled:
    - Separate key-schedule and block-cipher
    - Notions for AES operation
    - Investigating conditions and their representations

  \par
   In Cryptography/AdvancedEncryptionStandard/plans/Experimentation.hpp
   the following topics are handled:
    - Move experiment data to investigation-reports
    - Update experiment script

  \par
   In Cryptography/AdvancedEncryptionStandard/plans/Representations/general.hpp
   the following topics are handled:
    - Find "best" solver(s) and local search algorithms for minimisation

  \par
   In Cryptography/AdvancedEncryptionStandard/plans/Representations/Methods.hpp the
   following topics are handled:
    - Tidy hitting-clause-set todos and move method here
    - Add instructions for using Pseudo-boolean SAT solvers for minimisation

  \par
   Create further milestones.

  \par
   Create an outline of the experiments.


  \par Version 0.1.8 :

  \par
   In Cryptography/AdvancedEncryptionStandard/plans/general.hpp the
   following topics are handled:
    - Using SBSAT
    - Merge SAT2011 plans with module one level higher

  \par
   In Cryptography/AdvancedEncryptionStandard/plans/Experimentation.hpp
   the following topics are handled:
    - Investigating dimensions

  \par
   In Cryptography/AdvancedEncryptionStandard/plans/CryptographicProperties.hpp
   the following topics are handled:
    - Cryptographic properties of AES
    - Keys for which AES encrypts P to P
    - Create sub-module

  \par
   In Experimentation/Investigations/plans/CurrentExperiments.hpp the section
   on AES is updated.


  \par Version 0.1.9 :

  \par
   In Cryptography/AdvancedEncryptionStandard/plans/general.hpp the
   following topics are handled:
    - Open problems


  \par Version 0.2 : PLANNING SAT2012 COMPLETED

  \par
   In Cryptography/AdvancedEncryptionStandard/plans/general.hpp the
   following topics are handled:
    - SAT 2012

  \par
   In Cryptography/AdvancedEncryptionStandard/plans/Representations/Sbox_8.hpp
   the following topics are handled:
    - Generate good CNF hitting clause-sets
    - Extracting prime implicate representations from the hitting-cls-representations
    - Find the symmetries of the AES Sbox DNF
    - Find the symmetries of the AES inversion DNF



  -------------------------------------------------------------------------------------------------------------------------------------

  \par Version history

   - 0.1   : 1.1.2011; initial version number (various plans and first results regarding AES "box" representations).
   - 0.1.1 : 1.1.2011; started serious planning for the SAT2011 contributions.
   - 0.1.2 : 1.1.2011; removed/transferred completed todos, updates links.
   - 0.1.3 : 2.1.2011; tidied general todos and updated SAT2011 sub-module.
   - 0.1.4 : 5.1.2011; created "Representations" sub-module with associated information.
   - 0.1.5 : 8.1.2011; tidied plans, introduced method descriptions and started experiment plans files.

*/

