// Matthew Gwynne, 16.5.2011 (Swansea)
/* Copyright 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Investigations/Cryptography/DataEncryptionStandard/plans/Sboxes/Sbox_7.hpp
  \brief On investigations into Sbox seven of the Data Encryption Standard


  \todo Basic data
  <ul>
   <li> Generating the full CNF representation:
    <ol>
     <li> The CNF-file "DES_Sbox_7_fullCNF.cnf" is created by the Maxima-function
     output_dessbox_fullcnf_stdname(7) in
     ComputerAlgebra/Cryptology/Lisp/Cryptanalysis/DataEncryptionStandard/Sboxes.mac,
     which is a full clause-set with 10
     variables and 2^10 - 2^6 = 960 clauses:
     \verbatim
> cat DES_Sbox_7_fullCNF.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
10 960 9600 0 9600 1 1
 length count
10 960
     \endverbatim
     </li>
     <li> This clause-set is also computed by
     bf2relation_fullcnf_fcs(des_sbox_bf(7),6). </li>
    </ol>
   </li>
   <li> The minimum CNF representation has at most 67 clauses. See
   "Using weighted MaxSAT to compute small CNFs". </li>
  </ul>


  \todo Using weighted MaxSAT to compute small CNFs (mincl_rinf <= 67)
  <ul>
   <li> Computing the weighted MaxSAT problem:
   \verbatim
shell> QuineMcCluskeySubsumptionHypergraph-n16-O3-DNDEBUG DES_Sbox_7_fullCNF.cnf > DES_Sbox_7_shg.cnf
shell> cat DES_Sbox_7_shg.cnf | MinOnes2WeightedMaxSAT-O3-DNDEBUG > DES_Sbox_7_shg.wcnf
   \endverbatim
   </li>
   <li> Running then:
   \verbatim
shell> ubcsat-okl  -alg gsat -w -runs 100 -cutoff 400000 -wtarget 67 -solve 1 -seed 1856244582 -i DES_Sbox_7_shg.wcnf -r model DES_Sbox_7_s67.ass;
shell> cat DES_Sbox_7_fullCNF.cnf_primes | FilterDimacs DES_Sbox_7_s67.ass > DES_Sbox_7_s67.cnf
shell> cat DES_Sbox_7_s67.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
10 66 368 0 368 1 1
 length count
5 28
6 38
   \endverbatim
   </li>
   <li> The hardness of this "minimum" representation is 3:
    <ul>
     <li> See "Hardness of boolean function representations" in
     Experimentation/Investigations/BooleanFunctions/plans/general.hpp
     for a description of the notion of hardness, and method of computation.
     </li>
     <li> Computing the hardness:
     \verbatim
maxima> Sbox_min_F : read_fcl_f("DES_Sbox_7_s67.cnf")$
maxima> Sbox_primes_F : read_fcl_f("DES_Sbox_7_fullCNF.cnf_primes")$
maxima> hardness_wpi_cs(setify(Sbox_min_F[2]), setify(Sbox_primes_F[2]));
3
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>


  \todo 1-base : mincl_r1 <= 123
  <ul>
   <li> Computing an 1-base
   \verbatim
shell> QuineMcCluskey-n16-O3-DNDEBUG DES_Sbox_7_fullCNF.cnf > DES_Sbox_7_pi.cnf
shell> RandomShuffleDimacs-O3-DNDEBUG 148 < DES_Sbox_7_pi.cnf | SortByClauseLength-O3-DNDEBUG > DES_Sbox_7_sortedpi.cnf
shell> RUcpGen-O3-DNDEBUG DES_Sbox_7_sortedpi.cnf > DES_Sbox_7_gen.cnf
shell> RandomShuffleDimacs-O3-DNDEBUG 2 < DES_Sbox_7_gen.cnf | SortByClauseLengthDescending-O3-DNDEBUG | RUcpBase-O3-DNDEBUG > DES_Sbox_7_1base.cnf
shell> cat DES_Sbox_7_1base.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
10 123 663 0 663 0 1
 length count
5 75
6 48
   \endverbatim
   </li>
  </ul>


  \todo Move Sbox-1-specific investigations here

*/
