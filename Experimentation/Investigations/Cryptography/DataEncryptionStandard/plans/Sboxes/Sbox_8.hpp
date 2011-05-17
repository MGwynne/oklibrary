// Matthew Gwynne, 16.5.2011 (Swansea)
/* Copyright 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Investigations/Cryptography/DataEncryptionStandard/plans/Sboxes/Sbox_8.hpp
  \brief On investigations into Sbox eight of the Data Encryption Standard


  \todo Basic data
  <ul>
   <li> Generating the full CNF representation:
    <ol>
     <li> The CNF-file "DES_Sbox_8_fullCNF.cnf" is created by the Maxima-function
     output_dessbox_fullcnf_stdname(8) in
     ComputerAlgebra/Cryptology/Lisp/Cryptanalysis/DataEncryptionStandard/Sboxes.mac,
     which is a full clause-set with 10
     variables and 2^10 - 2^6 = 960 clauses:
     \verbatim
> cat DES_Sbox_8_fullCNF.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
10 960 9600 0 9600 1 1
 length count
10 960
     \endverbatim
     </li>
     <li> This clause-set is also computed by
     bf2relation_fullcnf_fcs(des_sbox_bf(8),6). </li>
    </ol>
   </li>
  </ul>


  \todo 1-base : mincl_r1 <= 152
  <ul>
   <li> Computing an 1-base
   \verbatim
shell> QuineMcCluskey-n16-O3-DNDEBUG DES_Sbox_8_fullCNF.cnf > DES_Sbox_8_pi.cnf
shell> RandomShuffleDimacs-O3-DNDEBUG 167 < DES_Sbox_8_pi.cnf | SortByClauseLength-O3-DNDEBUG > DES_Sbox_8_sortedpi.cnf
shell> RUcpGen-O3-DNDEBUG DES_Sbox_8_sortedpi.cnf > DES_Sbox_8_gen.cnf
shell> RandomShuffleDimacs-O3-DNDEBUG 1 < DES_Sbox_8_gen.cnf | SortByClauseLengthDescending-O3-DNDEBUG | RUcpBase-O3-DNDEBUG > DES_Sbox_8_1base.cnf
shell> cat DES_Sbox_8_1base.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
10 152 844 0 844 0 1
 length count
5 68
6 84
   \endverbatim
   </li>
  </ul>


  \todo Move Sbox-1-specific investigations here

*/