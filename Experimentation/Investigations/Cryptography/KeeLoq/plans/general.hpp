// Matthew Gwynne, 13.2.2012 (Swansea)
/* Copyright 2012, 2013 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Investigations/Cryptography/KeeLoq/plans/general.hpp
  \brief On investigations into KeeLoq cipher


  \todo Overview
  <ul>
   <li> KeeLoq is a 528-round iterated shift-register cipher with
   32-bit plaintext, and ciphertext, and 64-bit keys. </li>
   <li> The KeeLoq encryption cipher consists of the following:
   </li>
   <li> A key point here is that the KeeLoq round function is
   the combination of a small XXX and the XOR of X more bits,
   meaning that the entire round function is a XX bit boolean
   function. </li>
   <li> Algebraic attacks using SAT solvers are discussed in
   [Algebraic and Slide Attacks on KeeLoq; Bard, Courtois, Wagner 2008],
   theoretically breaking the cipher in time equivalent to 2^53
   encryptions, compared to 2^64 for brute-force. </li>
  </ul>


  \todo Analysing the KeeLoq round function
  <ul>
   <li> The KeeLoq round function is given as a boolean function
   by the Maxima function keeloq_round_bf in
   Cryptology/Lisp/CryptoSystems/DataEncryptionStandard/Cipher.mac.
   </li>
   <li> Computing statistics:
   \verbatim
maxima> Round_DNF : bf2fulldnf_fcl(keeloq_round_bf,9)$
maxima> statistics_fcs(Round_DNF);
 [9,256,2304,9,9]

maxima> Round_CNF : bf2fullcnf_fcl(keeloq_round_bf,9)$
maxima> statistics_fcs(Round_CNF);
 [9,256,2304,9,9]

maxima> output_fcs("KeeLoq Round Function", Round_CNF, "KeeLoq_Round_full.cnf")$

shell> QuineMcCluskeySubsumptionHypergraphWithFullStatistics-n16-O3-DNDEBUG KeeLoq_Round_full.cnf > KeeLoq_Round_full.cnf_shg
shell> cat KeeLoq_Round_full.cnf_primes_stats
     pn      pc      n    nmi       c        l     n0   n0mi      c0       l0  cmts
      9     224      9      9     224     1760     NA     NA     224     1760     0
 length   count
      7      32
      8     192
shell> cat KeeLoq_Round_full.cnf_shg_stats
     pn      pc      n    nmi       c        l     n0   n0mi      c0       l0  cmts
    224     256    224    224     256      512     NA     NA     256      512     0
 length   count
      2     256

shell> ${OKplatform}/OKlib/Satisfiability/Optimisation/minimise_cnf_cryptominisat KeeLoq_Round_full.cnf > KeeLoq_Round_min.cnf
shell> cat KeeLoq_Round_min.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG
     pn      pc      n    nmi       c        l     n0   n0mi      c0       l0  cmts
      9      96      9      9      96      736     NA     NA      96      736     1
 length   count
      7      32
      8      64

maxima> Round_primes : read_fcl_f("KeeLoq_Round_full.cnf_primes")$
maxima> Round_min : read_fcl_f("KeeLoq_Round_min.cnf")$
maxima> hardness_wpi_cs(setify(Round_min[2]), setify(Round_primes[2]));
 1
   \endverbatim
   So the minimum representation has hardness 1! </li>
   <li> Investigating the ANF to CNF encoding for the KeeLoq round used
   in Section 6.1 of
   [Algebraic and Slide Attacks on KeeLoq; Bard, Courtois, Wagner 2008]:
   \verbatim
/*  The variable mapping from Section 6.1 of
   [Algebraic and Slide Attacks on KeeLoq; Bard, Courtois, Wagner 2008] is:

   v_1 = k_{i mod 64}
   v_2 = L_i
   v_3 = L_16
   v_4 = L_{i+31}
   v_5 = L_{i+26}
   v_6 = L_{i+20}
   v_7 = L_{i+9}
   v_8 = L_{i+1}
   v_9 = y (i.e., the result bit for the round)
   v10 = v4 * v6 (i.e. v10 = "L_{i+31} * L_{i+20}")
   v11 = v4 * v8 (i.e., v11 = "beta_i" = "L_{i+31} * L_{i+1}")
   v12 = v5 * v6 (i.e., v12 = "L_{i+26} * L_{i+20}")
   v13 = v5 * v8 (i.e., v13 = "L_{i+26} * L_{i+1}")
   v14 = v6 * v7 (i.e., v14 = "L_{i+20} * L_{i+9}")
   v15 = v7 * v8 (i.e., v15 = "L_{i+9} * L_{i+1}")
   v16 = v11 * v7 (i.e., v16 = "beta_i * L_{i+9}" = "L_{i+31} * L_{i+1} * L_{i+9}")
   v17 = v11 * v6 (i.e., v17 = "beta_i * L_{i+20}" = "L_{i+31} * L_{i+1} * L_{i+20}")
   v18 = v20 * v7 (i.e., v18 = "alpha_i * L_{i+9}" = "L_{i+31} * L_{i+26} * L_{i+9}")
   v19 = v20 * v6 (i.e., v19 = "alpha_i * L_{i+20}" = "L_{i+31} * L_{i+26} * L_{i+20}")
   v20 = v4 * v5 (i.e., v20 = "alpha_i" = "L_{i+31} * L_{i+26}"). */
/* Translating the multiplications: */
maxima> Round_anf : lappend(map(lambda([v,C], cons(adjoin(v,map("-",C)),create_list({-v,l},l,listify(C)))),[10,11,12,13,14,15,16,17,18,19,20],[{4,6},{4,8},{5,6},{5,8},{6,7},{7,8},{11,7},{11,6},{20,7},{20,6},{4,5}]))$
/* Splitting the large XOR of the above multiplications into 4 and
   then translating each directly and then adding the results:
     v1  + v2  + v3  + v7   = v21
     v8  + v10 + v11 + v12  = v22
     v13 + v14 + v15 + v16  = v23
     v17 + v18 + v19        = v24
     v21 + v22 + v23 + v24  = v9 (adding the results to produce the output bit)
*/
maxima> Round_par_anf : append(
              even_parity_wv_cl([1,2,3,7,21]),
              even_parity_wv_cl([8,10,11,12,22]),
              even_parity_wv_cl([13,14,15,16,23]),
              even_parity_wv_cl([17,18,19,24]),
              even_parity_wv_cl([21,22,23,24,9]));
maxima> Round_anf : append(Round_anf,Round_par_anf);
maxima> statistics_cs(Round_anf);
 [24,105,429,5,2]
/* Checking we compute the right function: */
maxima> for C in Round_CNF[2] do assert(ucp_0_cs(apply_pa_cs(comp_sl(C),setify(Round_anf))) = {{}});
 done
maxima> for C in Round_DNF[2] do assert(ucp_0_cs(apply_pa_cs(C,setify(Round_anf))) = {});
 done
 /* Computing a lower-bound on the hardness, the hardness w.r.t the prime
    implicates on the original variables: */
 maxima> hardness_wpi_cs(setify(NLF_nv), setify(Round_primes[2]));
 2
   \endverbatim
   So the ANF representation used has a higher hardness, and is also a larger
   representation. The minimum 1-base above should be a much better representation
   of the KeeLoq round function. </li>
   <li> KeeLoq should be implemented at the Maxima level, and then translated,
   so that we can compare these translations. </li>
  </ul>

*/
