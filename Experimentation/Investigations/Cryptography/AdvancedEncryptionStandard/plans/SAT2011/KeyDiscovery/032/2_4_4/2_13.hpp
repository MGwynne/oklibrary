// Matthew Gwynne, 19.7.2011 (Swansea)
/* Copyright 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/KeyDiscovery/032/2_4_4/2_13.hpp
  \brief Investigations into small scale AES key discovery for 2+1/3 round AES with a 2x4 plaintext matrix and 4-bit field elements


  \todo Add problem specification


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
shell> row=2; col=4; e=4; r=2; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    echo "Seed ${s}; Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf | RandomShuffleDimacs-O3-DNDEBUG $s > r${r}_k${k}_s${s}.cnf;
    (time minisat-2.2.0 r${r}_k${k}_s${s}.cnf) > minisat_r${r}_k${k}_s${s}.result 2>&1;
  done;
done;
shell> echo "n  c  t  sat  cfs dec rts r1 mem ptime stime cfl r k s" > minisat_results; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    cat minisat_r${r}_k${k}_s${s}.result | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractMinisat.awk | awk " { print \$0 \"  $r  $k $s\" }";
  done;
done >> minisat_results;
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("minisat_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r    n        c       t sat      cfs      dec    rts       r1  mem ptime
1 2 1976 13285.85 7.69152   1 61403.33 68238.92 175.85 38757356 9.36  0.01
   stime     cfl r    k s
1 0.0197 1323512 2 10.5 3
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> row=2; col=4; e=4; r=2; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    echo "Seed ${s}; Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf | RandomShuffleDimacs-O3-DNDEBUG $s > r${r}_k${k}_s${s}.cnf;
    OKsolver_2002-O3-DNDEBUG r${r}_k${k}_s${s}.cnf > oksolver_r${r}_k${k}_s${s}.result 2>&1;
  done;
done;
     \endverbatim
     </li>
     <li> Some instances when randomising using seed 5 take > 1 day to solve!?
     </li>
     <li> Looking at results from randomising using seeds 1 to 4:
     \verbatim
shell> echo "n  c  l  t  sat  nds  r1  r2  pls  ats h file n2cr  dmcl dn  dc  dl snds qnds mnds  tel  oats  n2cs  m2cs r k s" > oksolver_results; for s in $(seq 1 4); do
  for k in $(seq 1 20); do
    cat oksolver_r${r}_k${k}_s${s}.result | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractOKsolver.awk | awk " { print \$0 \"  $r  $k $s\" }";
  done;
done >> oksolver_results;
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("oksolver_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r    n     c     l        t sat      nds r1       r2 pls    ats      h file
1 2 1976 13436 38632 63.53375   1 192058.0 72 16326164   0 0.1375 20.075   NA
   n2cr dmcl dn  dc  dl     snds qnds    mnds tel oats n2cs m2cs r    k   s
1 10880    0 72 232 744 2646.637    0 81.1875   0    0    0    0 2 10.5 2.5
     \endverbatim
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
   <li> Statistics must be explained for this instance. </li>
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
shell> row=2; col=4; e=4; r=2; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    echo "Seed ${s}; Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf | RandomShuffleDimacs-O3-DNDEBUG $s > r${r}_k${k}_s${s}.cnf;
    minisat-2.2.0 r${r}_k${k}_s${s}.cnf > minisat_r${r}_k${k}_s${s}.result 2>&1;
  done;
done;
shell> echo "n  c  t  sat  cfs dec rts r1 mem ptime stime cfl r k s" > minisat_results; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    cat minisat_r${r}_k${k}_s${s}.result | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractMinisat.awk | awk " { print \$0 \"  $r  $k $s\" }";
  done;
done >> minisat_results;
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("minisat_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r   n       c        t sat      cfs      dec    rts       r1 mem ptime stime
1 2 632 2343.54 2.897058   1 93571.27 102325.1 249.48 12922114   8     0     0
      cfl r    k s
1 1450262 2 10.5 3
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> col=4; row=2; e=4; r=2; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    echo "Seed ${s}; Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf | RandomShuffleDimacs-O3-DNDEBUG $s > r${r}_k${k}_s${s}.cnf;
    OKsolver_2002-O3-DNDEBUG r${r}_k${k}_s${s}.cnf > oksolver_r${r}_k${k}_s${s}.result 2>&1;
  done;
done;
shell> echo "n  c  l  t  sat  nds  r1  r2  pls  ats h file n2cr  dmcl dn  dc  dl snds qnds mnds  tel  oats  n2cs  m2cs r k s" > oksolver_results; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    cat oksolver_r${r}_k${k}_s${s}.result | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractOKsolver.awk | awk " { print \$0 \"  $r  $k $s\" }";
  done;
done >> oksolver_results;
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("oksolver_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r   n    c    l      t sat      nds r1      r2 pls  ats    h file n2cr dmcl
1 2 632 2496 7696 49.528   1 881205.1 72 1866517   0 0.03 27.7   NA  288    0
  dn  dc  dl   snds qnds   mnds tel oats n2cs m2cs r    k s
1 72 232 744 439.98    0 362.03   0    0    0    0 2 10.5 3
     \endverbatim
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

shell> cat ssaes_r20_c1_rw1_e4_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
492 2136 6528 0 6528 493 1
 length count
1 80
2 320
3 1136
4 600
   \endverbatim
   </li>
   <li> Statistics need to be added and explained. </li>
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
shell> row=2;col=4; e=4; r=2; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    echo "Seed ${s}; Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf | RandomShuffleDimacs-O3-DNDEBUG $s > r${r}_k${k}_s${s}.cnf;
    minisat-2.2.0 r${r}_k${k}_s${s}.cnf > minisat_r${r}_k${k}_s${s}.result 2>&1;
  done;
done;
shell> echo "n  c  t  sat  cfs dec rts r1 mem ptime stime cfl r k s" > minisat_results; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    cat minisat_r${r}_k${k}_s${s}.result | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractMinisat.awk | awk " { print \$0 \"  $r  $k $s\" }";
  done;
done >> minisat_results;
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("minisat_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r   n       c        t sat      cfs      dec   rts       r1 mem ptime stime
1 2 632 2728.56 2.562270   1 78078.94 85143.06 213.5 10391662   8     0 6e-04
      cfl r    k s
1 1160730 2 10.5 3
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> row=2; col=4; e=4; r=2; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    echo "Seed ${s}; Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf | RandomShuffleDimacs-O3-DNDEBUG $s > r${r}_k${k}_s${s}.cnf;
    OKsolver_2002-O3-DNDEBUG r${r}_k${k}_s${s}.cnf > oksolver_r${r}_k${k}_s${s}.result 2>&1;
  done;
done;
shell> echo "n  c  l  t  sat  nds  r1  r2  pls  ats h file n2cr  dmcl dn  dc  dl snds qnds mnds  tel  oats  n2cs  m2cs r k s" > oksolver_results; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    cat oksolver_r${r}_k${k}_s${s}.result | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractOKsolver.awk | awk " { print \$0 \"  $r  $k $s\" }";
  done;
done >> oksolver_results;
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("oksolver_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r   n    c    l      t sat      nds r1      r2 pls  ats     h file n2cr dmcl
1 2 632 2884 8936 54.559   1 822484.6 72 1435966   0 0.07 27.49   NA  320    0
  dn  dc  dl    snds qnds   mnds tel oats n2cs m2cs r    k s
1 72 232 744 1294.09    0 909.72   0    0    0    0 2 10.5 3
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>

*/



