// Matthew Gwynne, 19.7.2011 (Swansea)
/* Copyright 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/KeyDiscovery/032/2_4_4/2_13.hpp
  \brief Investigations into small scale AES key discovery for 2+1/3 round AES with a 2x4 plaintext matrix and 4-bit field elements


  \todo Problem specification
  <ul>
   <li> We investigate the 2 + 1/3 round small-scale AES with 2 row,
   4 column, using the 4-bit field size. </li>
   <li> We denote this AES instance by aes(2,2,4,4). </li>
   <li> aes(2,2,4,4) takes a 32-bit plaintext and 32-bit key and
   outputs a 32-bit ciphertext. </li>
   <li> For the full specification of this AES instance, see
   "Problem specification" in
   Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/KeyDiscovery/032/2_4_4/general.hpp.
   </li>
   <li> Note that we consider the canonical CNF translation, as
   this is an example of the "hardest" representation without
   new variables. See "Hardness of boolean function representations"
   in
   Experimentation/Investigations/BooleanFunctions/plans/general.hpp. </li>
  </ul>


  \todo Using the canonical box translation
  <ul>
   <li> Translation of aes(2,2,4,4):
    <ul>
     <li> The MixColumns operation is decomposed into it's field
     multiplications (02 and 03) and addition operations. </li>
     <li> The MixColumns operation is translated by translating both
     the MixColumns operation and it's inverse (it is self-inverse). </li>
     <li> We treat S-boxes, field multiplications and additions as boxes.
     </li>
     <li> The S-box and field multiplications are considered as a 8-bit to
     1-bit boolean functions, translated using the canonical translation;
     see dualts_fcl in
     ComputerAlgebra/Satisfiability/Lisp/FiniteFunctions/TseitinTranslation.mac.
     </li>
     <li> Additions of arity k are considered bit-wise as (k+1)-bit to 1-bit
     boolean functions; translated using their prime implicates. </li>
    </ul>
   </li>
   <li> Generating small scale AES for 1 + 1/3 round:
   \verbatim
num_rounds : 2$
num_rows : 2$
num_columns : 4$
exp : 4$
final_round_b : false$
box_tran : aes_ts_box$
seed : 1$
mc_tran : aes_mc_bidirectional$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r2_c4_rw2_e4_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
1976 13372 38568 0 38568 1977 1
 length count
1 8
2 10752
3 1120
4 64
9 1344
16 84
   \endverbatim
   </li>
   <li> In this translation, we have:
    <ul>
     <li> 2 full round (Key Addition, SubBytes, and MixColumns operation).
     </li>
     <li> 20 Sboxes:
      <ul>
       <li> 16 from SubBytes = 8 byte * 2 rounds; </li>
       <li> 4 from key schedule = 2 row * 1 word * 2 rounds. </li>
      </ul>
     </li>
     <li> 32 multiplications by 02: 2 rows * 1 multiplication * 4 columns *
     2 rounds * 2 directions (forward + inverse). </li>
     <li> 32 multiplications by 03: 2 rows * 1 multiplication * 4 columns *
     2 rounds * 2 directions (forward + inverse). </li>
     <li> 288 additions:
      <ul>
       <li> 280 additions of arity 2:
        <ul>
         <li> 64 from key additions = 32 bits * 2 rounds; </li>
         <li> 32 from final key addition = 32 bits; </li>
         <li> 56 from the key schedule = (32 bits - 4 bits) * 2 round. </li>
         <li> 64 from forward MixColumns = 2 rows * 4 column * 4 bits *
         2 rounds; </li>
         <li> 64 from inverse MixColumns = 2 rows * 4 column * 4 bits * 2
         rounds. </li>
        </ul>
       </li>
       <li> 8 additions of arity 3:
        <ul>
         <li> 8 from the key schedule = 4 bits * 2 rounds. </li>
        </ul>
       </li>
      </ul>
     </li>
     <li> 8 bits for the constant in the key schedule = 4 bits * 2 rounds.
     </li>
    </ul>
   </li>
   <li> The number of clauses of each length in the canonical translation:
   \verbatim
maxima> ncl_list_full_dualts(8,16);
[[2,128],[9,16],[16,1]]
   \endverbatim
   </li>
   <li> This instance has 84 boxes = 20 S-boxes + 64 multiplications.
   </li>
   <li> This instance has the following number of clauses of length: XXX
    <ul>
     <li> 1 : 8 = key schedule constant * 1; </li>
     <li> 2 : 10752 = 84 boxes * 128; </li>
     <li> 3 : 1120 = 280 additions (arity 2) * 4; </li>
     <li> 4 : 64 = 8 additions (arity 3) * 8; </li>
     <li> 9 : 1344 = 84 boxes * 16; </li>
     <li> 16 : 84 = 84 boxes * 1. </li>
    </ul>
   </li>
   <li> Considering 20 plaintext-ciphertext pairs:
    <ul>
     <li> Generate 20 random assignment with the plaintext and ciphertext,
     leaving the key unknown:
     \verbatim
maxima> for seed : 1 thru 20 do output_ss_random_pc_pair(seed,num_rounds,num_columns,num_rows,exp,final_round_b);
     \endverbatim
     </li>
     <li> Running minisat-2.2.0:
     \verbatim
shell> row=2; col=4; e=4; r=2; for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    (time minisat-2.2.0 r${r}_k${k}.cnf) > minisat_r${r}_k${k}.result 2>&1;
done;
shell> echo "n  c  t  sat  cfs dec rts r1 mem ptime stime cfl r k" > minisat_results;
  for k in $(seq 1 20); do
    cat minisat_r${r}_k${k}.result | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractMinisat.awk | awk " { print \$0 \"  $r  $k\" }";
done >> minisat_results;
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("minisat_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
r    n     c        t sat      cfs      dec   rts       r1 mem ptime  stime
2 1976 13332 7.445463   1 59467.15 66110.15 170.7 37217602 9.4  0.01 0.0155
    cfl r    k
1307613 2 10.5
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> row=2; col=4; e=4; r=2; for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    OKsolver_2002-O3-DNDEBUG r${r}_k${k}.cnf > oksolver_r${r}_k${k}.result 2>&1;
done;
     \endverbatim
     is currently running.
     </li>
    </ul>
   </li>
  </ul>


  \todo Using the "minimum" box translation
  <ul>
   <li> Translating the AES cipher treating S-boxes and field multiplications
   as whole boxes and translating these boxes using the smallest CNF
   translations. </li>
   <li> Generating aes(2,2,4,4):
   \verbatim
shell> mkdir aes_2_4_4/min
shell> cd aes_2_4_4/min
shell> oklib --maxima
oklib_load_all()$
num_rounds : 2$
num_rows : 2$
num_columns : 4$
exp : 4$
final_round_b : false$
box_tran : aes_small_box$
mc_tran : aes_mc_bidirectional$
oklib_monitor : true$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r2_c4_rw2_e4_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
632 2432 7632 0 7632 633 1
 length count
1 8
2 160
3 1792
4 432
5 40
   \endverbatim
   </li>
   <li> In this translation, we have:
    <ul>
     <li> 2 full round (Key Addition, SubBytes, and MixColumns operation).
     </li>
     <li> 20 Sboxes:
      <ul>
       <li> 16 from SubBytes = 8 byte * 2 rounds; </li>
       <li> 4 from key schedule = 2 row * 1 word * 2 rounds. </li>
      </ul>
     </li>
     <li> 32 multiplications by 02: 2 rows * 1 multiplication * 4 columns *
     2 rounds * 2 directions (forward + inverse). </li>
     <li> 32 multiplications by 03: 2 rows * 1 multiplication * 4 columns *
     2 rounds * 2 directions (forward + inverse). </li>
     <li> 288 additions:
      <ul>
       <li> 280 additions of arity 2:
        <ul>
         <li> 64 from key additions = 32 bits * 2 rounds; </li>
         <li> 32 from final key addition = 32 bits; </li>
         <li> 56 from the key schedule = (32 bits - 4 bits) * 2 round. </li>
         <li> 64 from forward MixColumns = 2 rows * 4 column * 4 bits *
         2 rounds; </li>
         <li> 64 from inverse MixColumns = 2 rows * 4 column * 4 bits * 2
         rounds. </li>
        </ul>
       </li>
       <li> 8 additions of arity 3:
        <ul>
         <li> 8 from the key schedule = 4 bits * 2 rounds. </li>
        </ul>
       </li>
      </ul>
     </li>
     <li> 8 bits for the constant in the key schedule = 4 bits * 2 rounds.
     </li>
    </ul>
   </li>
   <li> The number of clauses of each length in the canonical translation:
   \verbatim
maxima> ncl_list_fcl(ev_hm(ss_sbox_cnfs,4));
[[3,8],[4,12],[5,2]]
maxima> ncl_list_fcl(ev_hm(ss_field_cnfs,[4,2]));
[[2,5],[3,4]]
maxima> ncl_list_fcl(ev_hm(ss_field_cnfs,[4,3]));
[[3,12],[4,4]]
   \endverbatim
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 8 = key schedule constant * 1; </li>
     <li> 2 : 160 = 32 multiplications by 02 * 5; </li>
     <li> 3 : 1792 = 280 additions (arity 2) * 4 + 20 S-boxes * 8 +
     32 multiplications by 02 * 4 + 32 multiplications by 03 * 12; </li>
     <li> 4 : 432 = 8 additions (arity 3) * 8 + 20 S-boxes * 12 +
     32 multiplications by 03 * 4; </li>
     <li> 5 : 40 = 20 boxes * 2; </li>
    </ul>
   </li>
   <li> Generating 20 random plaintext-ciphertext pairs and running
   solvers instances instantiated with these pairs to find the key:
    <ul>
     <li> Computing the random plaintext-ciphertext pairs:
     \verbatim
for seed : 1 thru 20 do output_ss_random_pc_pair(seed,num_rounds,num_columns,num_rows,exp,final_round_b);
     \endverbatim
     </li>
     <li> Running minisat-2.2.0:
     \verbatim
shell> row=2; col=4; e=4; r=2; for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    (time minisat-2.2.0 r${r}_k${k}.cnf) > minisat_r${r}_k${k}.result 2>&1;
done;
shell> echo "n  c  t  sat  cfs dec rts r1 mem ptime stime cfl r k" > minisat_results;
  for k in $(seq 1 20); do
    cat minisat_r${r}_k${k}.result | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractMinisat.awk | awk " { print \$0 \"  $r  $k\" }";
done >> minisat_results;
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("minisat_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r   n    c        t sat      cfs      dec   rts       r1 mem ptime stime
1 2 632 2392 3.266455   1 103968.8 113826.2 279.4 14517307   8     0     0
      cfl r    k
1 1614210 2 10.5
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
row=2; col=4; e=4; r=2; for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    OKsolver_2002-O3-DNDEBUG r${r}_k${k}.cnf > oksolver_r${r}_k${k}.result 2>&1;
done;
     \endverbatim
     is currently running.
     </li>
    </ul>
   </li>
  </ul>


  \todo Using the 1-base box translation
  <ul>
   <li> Translating the AES cipher treating Sboxes and field multiplications
   as whole boxes and translating these boxes using the 1-base translation.
   </li>
   <li> Generating simplest small scale AES for 20 rounds:
   \verbatim
shell> mkdir aes_4_2_4/1base
shell> cd aes_4_2_4/1base
shell> oklib --maxima
oklib_load_all()$
num_rounds : 2$
num_rows : 2$
num_columns : 4$
exp : 4$
final_round_b : false$
box_tran : aes_rbase_box$
mc_tran : aes_mc_bidirectional$
oklib_monitor : true$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r2_c4_rw2_e4_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
632 2820 8872 0 8872 633 1
 length count
1 8
2 192
3 2000
4 620
   \endverbatim
   </li>
   <li> In this translation, we have:
    <ul>
     <li> 2 full round (Key Addition, SubBytes, and MixColumns operation).
     </li>
     <li> 20 Sboxes:
      <ul>
       <li> 16 from SubBytes = 8 byte * 2 rounds; </li>
       <li> 4 from key schedule = 2 row * 1 word * 2 rounds. </li>
      </ul>
     </li>
     <li> 32 multiplications by 02: 2 rows * 1 multiplication * 4 columns *
     2 rounds * 2 directions (forward + inverse). </li>
     <li> 32 multiplications by 03: 2 rows * 1 multiplication * 4 columns *
     2 rounds * 2 directions (forward + inverse). </li>
     <li> 288 additions:
      <ul>
       <li> 280 additions of arity 2:
        <ul>
         <li> 64 from key additions = 32 bits * 2 rounds; </li>
         <li> 32 from final key addition = 32 bits; </li>
         <li> 56 from the key schedule = (32 bits - 4 bits) * 2 round. </li>
         <li> 64 from forward MixColumns = 2 rows * 4 column * 4 bits *
         2 rounds; </li>
         <li> 64 from inverse MixColumns = 2 rows * 4 column * 4 bits * 2
         rounds. </li>
        </ul>
       </li>
       <li> 8 additions of arity 3:
        <ul>
         <li> 8 from the key schedule = 4 bits * 2 rounds. </li>
        </ul>
       </li>
      </ul>
     </li>
     <li> 8 bits for the constant in the key schedule = 4 bits * 2 rounds.
     </li>
    </ul>
   </li>
   <li> The number of clauses of each length in the canonical translation:
   \verbatim
maxima> ncl_list_fcl(ev_hm(ss_sbox_rbase_cnfs,4));
[[3,12],[4,15]]
maxima> ncl_list_fcl(ev_hm(ss_field_rbase_cnfs,[4,2]));
[[2,6],[3,4]]
maxima> ncl_list_fcl(ev_hm(ss_field_rbase_cnfs,[4,3]));
[[3,16],[4,8]]
   \endverbatim
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 8 = key schedule constant * 1; </li>
     <li> 2 : 192 = 32 multiplications by 02 * 6; </li>
     <li> 3 : 2000 = 280 additions (arity 2) * 4 + 20 S-boxes * 12 +
     32 multiplications by 02 * 6 + 32 multiplications by 03 * 16; </li>
     <li> 4 : 620 = 8 additions (arity 3) * 8 + 20 S-boxes * 15 +
     32 multiplications by 03 * 8; </li>
    </ul>
   </li>
   <li> Generating 20 random plaintext-ciphertext pairs and running
   solvers instances instantiated with these pairs to find the key:
    <ul>
     <li> Computing the random plaintext-ciphertext pairs:
     \verbatim
for seed : 1 thru 20 do output_ss_random_pc_pair(seed,num_rounds,num_columns,num_rows,exp,final_round_b);
     \endverbatim
     </li>
     <li> Running minisat-2.2.0:
     \verbatim
shell> row=2; col=4; e=4; r=2; for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    (time minisat-2.2.0 r${r}_k${k}.cnf) > minisat_r${r}_k${k}.result 2>&1;
done;
shell> echo "n  c  t  sat  cfs dec rts r1 mem ptime stime cfl r k" > minisat_results;
  for k in $(seq 1 20); do
    cat minisat_r${r}_k${k}.result | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractMinisat.awk | awk " { print \$0 \"  $r  $k\" }";
done >> minisat_results;
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("minisat_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r   n    c        t sat      cfs      dec   rts       r1 mem ptime stime
1 2 632 2780 3.280103   1 98072.45 106752.2 252.9 13197617   8     0     0
      cfl r    k
1 1452887 2 10.5
     \endverbatim
     is currently running.
    </ul>
   </li>
  </ul>

*/



