// Matthew Gwynne, 19.7.2011 (Swansea)
/* Copyright 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file AdvancedEncryptionStandard/plans/SAT2011/KeyDiscovery/064/4_4_4/2_13.hpp
  \brief Investigations into small scale AES key discovery for 2 round AES with a 4x4 plaintext matrix and 4-bit field elements (1+1/3)


  \todo Add problem specification


  \todo Using the canonical box translation
  <ul>
   <li> Translating the AES cipher treating Sboxes and field multiplications
   as whole boxes and translating these boxes using the canonical translation.
   </li>
   <li> Generating aes(2,4,4,4):
   \verbatim
num_rounds : 2$
num_rows : 4$
num_columns : 4$
exp : 4$
final_round_b : false$
box_tran : aes_ts_box$
seed : 1$
mc_tran : aes_mc_bidirectional$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r2_c4_rw4_e4_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
5224 39056 121000 0 121000 5225 1
 length count
1 8
2 29696
3 1248
4 64
5 4096
9 3712
16 232
   \endverbatim
   </li>
   <li> Then we can generate a random assignment with the plaintext and
   ciphertext, leaving the key unknown:
   \verbatim
maxima> for seed : 1 thru 20 do output_ss_random_pc_pair(seed,num_rounds,num_columns,num_rows,exp,final_round_b);
   \endverbatim
   </li>
   <li> Considering 20 plaintext-ciphertext pairs, randomising the clause-set
   5 different ways:
    <ul>
     <li> Generate 20 random assignment with the plaintext and ciphertext,
     leaving the key unknown:
     \verbatim
maxima> for seed : 1 thru 20 do output_ss_random_pc_pair(seed,num_rounds,num_columns,num_rows,exp,final_round_b);
     \endverbatim
     </li>
     <li> Running minisat-2.2.0:
     \verbatim
shell> row=4; col=4; e=4; r=2;
  for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    minisat-2.2.0 r${r}_k${k}.cnf > minisat_r${r}_k${k}.result 2>&1;
done;
     \endverbatim
     is still running after a week...
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> row=4; col=2; e=4; r=1;
  for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    OKsolver_2002-O3-DNDEBUG r${r}_k${k}.cnf > oksolver_r${r}_k${k}.result 2>&1;
done;
     \endverbatim
     is still running after a week...
     </li>
    </ul>
   </li>
  </ul>


*/
