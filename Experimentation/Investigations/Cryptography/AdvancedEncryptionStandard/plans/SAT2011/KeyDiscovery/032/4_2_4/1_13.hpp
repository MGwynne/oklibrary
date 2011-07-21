// Matthew Gwynne, 15.2.2011 (Swansea)
/* Copyright 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/KeyDiscovery/032/4_2_4/1_13.hpp
  \brief Investigations into small-scale AES key discovery for 1+1/3 round AES with a 4x2 plaintext matrix and 4-bit field elements


  \todo Problem specification
  <ul>
   <li> We investigate the 1 + 1/3 round small-scale AES with 4 row,
   2 column, using the 4-bit field size. </li>
   <li> We denote this AES instance by aes(1,4,2,4). </li>
   <li> aes(1,4,2,4) takes a 32-bit plaintext and 32-bit key and
   outputs a 32-bit ciphertext. </li>
   <li> For the full specification of this AES instance, see
   "Problem specification" in
   Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/KeyDiscovery/032/4_2_4/general.hpp.
   </li>
   <li> Note that we consider the canonical CNF translation, as
   this is an example of the "hardest" representation without
   new variables. See "Hardness of boolean function representations"
   in
   Experimentation/Investigations/BooleanFunctions/plans/general.hpp. </li>
  </ul>


  \todo Using the canonical box translation
  <ul>
   <li> Translation of aes(1,4,2,4):
    <ul>
     <li> The MixColumns operation is decomposed into its field
     multiplications (02 and 03) and addition operations. </li>
     <li> The MixColumns operation is translated by translating both
     the MixColumns operation and its inverse. </li>
     <li> We treat S-boxes, field multiplications and additions as boxes.
     </li>
     <li> The S-box and field multiplications are considered as a 8x1
     boolean functions, translated using the canonical translation;
     see dualts_fcl in
     ComputerAlgebra/Satisfiability/Lisp/FiniteFunctions/TseitinTranslation.mac.
     </li>
     <li> Additions of arity k are considered bit-wise as (k+1)-bit to 1-bit
     boolean functions; translated using their prime implicates. </li>
    </ul>
   </li>
   <li> Generating small-scale AES for 1 + 1/3 round:
   \verbatim
num_rounds : 1$
num_rows : 4$
num_columns : 2$
exp : 4$
final_round_b : false$
box_tran : aes_ts_box$
seed : 1$
mc_tran : aes_mc_bidirectional$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r1_c2_rw4_e4_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
1396 10128 31316 0 31316 1397 1
 length count
1 4
2 7680
3 368
4 32
5 1024
9 960
16 60
   \endverbatim
   </li>
   <li> In this translation, we have:
    <ul>
     <li> 1 full round (Key Addition, SubBytes, and MixColumns operation).
     </li>
     <li> 12 S-boxes:
      <ul>
       <li> 8 from SubBytes = 8 byte * 1 rounds; </li>
       <li> 4 from key schedule = 4 row * 1 word * 1 rounds. </li>
      </ul>
     </li>
     <li> 8 multiplications by 02 = 4 rows * 1 multiplication * 2 columns *
     1 round * 1 direction (forward). </li>
     <li> 8 multiplications by 03 = 4 rows * 1 multiplication * 2 columns *
     1 round * 1 directions (forward). </li>
     <li> 8 multiplications by 09 = 4 rows * 1 multiplication * 2 columns *
     1 round * 1 directions (inverse). </li>
     <li> 8 multiplications by 11 = 4 rows * 1 multiplication * 2 columns *
     1 round * 1 directions (inverse). </li>
     <li> 8 multiplications by 13 = 4 rows * 1 multiplication * 2 columns *
     1 round * 1 directions (inverse). </li>
     <li> 8 multiplications by 14 = 4 rows * 1 multiplication * 2 columns *
     1 round * 1 directions (inverse). </li>
     <li> 160 additions:
      <ul>
       <li> 92 additions of arity 2:
        <ul>
         <li> 32 from key additions = 32 bits * 1 round; </li>
         <li> 32 from final key addition = 32 bits; </li>
         <li> 28 from the key schedule = (32 bits - 4 bits) * 1 round. </li>
        </ul>
       </li>
       <li> 4 additions of arity 3:
        <ul>
         <li> 4 from the key schedule = 4 bits * 1 rounds. </li>
        </ul>
       </li>
       <li> 64 additions of arity 4:
        <ul>
         <li> 32 from forward MixColumns = 4 rows * 2 column * 4 bits *
         1 rounds; </li>
         <li> 32 from inverse MixColumns = 4 rows * 2 column * 4 bits * 1
         rounds. </li>
        </ul>
       </li>
      </ul>
     </li>
     <li> 4 bits for the constant in the key schedule = 4 bits * 1 rounds.
     </li>
    </ul>
   </li>
   <li> The number of clauses of each length in the translation, computed by:
   \verbatim
maxima> ncl_list_full_dualts(8,16);
[[2,128],[9,16],[16,1]]
   \endverbatim
   </li>
   <li> This instance has 60 boxes = 12 S-boxes + 48 multiplications.
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 4 = key schedule constant * 1; </li>
     <li> 2 : 7680 = 60 boxes * 128; </li>
     <li> 3 : 368 = 92 additions (arity 2) * 4; </li>
     <li> 4 : 32 = 4 additions (arity 3) * 8; </li>
     <li> 5 : 1024 = 64 additions (arity 4) * 16; </li>
     <li> 9 : 960 = 60 boxes * 16; </li>
     <li> 16 : 60 = 60 boxes * 1. </li>
    </ul>
   </li>
   <li> Considering a single plaintext-ciphertext pair:
    <ul>
     <li> Then we can generate a random assignment with the plaintext and
     ciphertext, leaving the key unknown:
     \verbatim
maxima> output_ss_random_pc_pair(seed,num_rounds,num_columns,num_rows,exp,final_round_b);
     \endverbatim
     and the merging the assignment with the translation:
     \verbatim
shell> AppendDimacs-O3-DNDEBUG ssaes_r1_c2_rw4_e4_f0.cnf ssaes_pkpair_r1_c2_rw4_e4_f0_s1.cnf > r1_keyfind.cnf
     \endverbatim
     </li>
     <li> OKsolver_2002:
     \verbatim
shell> OKsolver_2002-O3-DNDEBUG r1_keyfind.cnf
c running_time(sec)                     42.8
c number_of_nodes                       2915
c number_of_2-reductions                25478
     \endverbatim
     </li>
     <li> minisat-2.2.0 and glucose:
     \verbatim
shell> minisat-2.2.0 r1_keyfind.cnf
restarts              : 126
conflicts             : 38174          (11967 /sec)
decisions             : 41318          (0.00 % random) (12952 /sec)
propagations          : 15523483       (4866296 /sec)
CPU time              : 3.19 s

shell> minisat2 r1_keyfind.cnf
<snip>
restarts              : 14
conflicts             : 43604          (1401 /sec)
decisions             : 47364          (1.34 % random) (1522 /sec)
propagations          : 17037471       (547477 /sec)
CPU time              : 31.12 s
shell> glucose r1_keyfind.cnf
<snip>
c restarts              : 8
c conflicts             : 16554          (13035 /sec)
c decisions             : 21834          (1.56 % random) (17192 /sec)
c propagations          : 3407020        (2682693 /sec)
c CPU time              : 1.27 s
     \endverbatim
     </li>
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
shell> row=4; col=2; e=4; r=1; for s in $(seq 1 5); do
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
  r    n        c        t sat      cfs      dec    rts       r1 mem  ptime
1 1 1396 10052.97 3.065744   1 32123.65 35573.64 106.46 12966258   9 0.0098
   stime     cfl r    k s
1 0.0147 1007711 1 10.5 3
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> row=4; col=2; e=4; r=1; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    echo "Seed ${s}; Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf | RandomShuffleDimacs-O3-DNDEBUG $s > r${r}_k${k}_s${s}.cnf;
    OKsolver_2002-O3-DNDEBUG r${r}_k${k}_s${s}.cnf > oksolver_r${r}_k${k}_s${s}.result 2>&1;
  done;
done;
     \endverbatim
     yields:
     \verbatim
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
  r    n     c     l      t sat    nds r1       r2 pls ats     h file n2cr dmcl
1 1 1396 10192 31380 49.499   1 3760.9 68 229450.3   0   0 12.88   NA 7808    0
  dn  dc  dl snds qnds mnds tel oats n2cs m2cs r    k s
1 68 212 660    0    0    0   0    0    0    0 1 10.5 3
     \endverbatim
     </li>
    </ul>
   </li>
   <li> We can check we get the right result with:
   \verbatim
shell> OKsolver_2002-O3-DNDEBUG -O r1_keyfind.cnf | grep "^v" | $OKlib/Experimentation/Investigations/Cryptography/AdvancedEncryptionStandard/validate_aes_assignment 1 2 4 4 0 && echo "VALID"
VALID
   \endverbatim
   </li>
  </ul>


  \todo Using the "minimum" box translation
  <ul>
   <li> Translating the AES cipher treating S-boxes and field multiplications
   as whole boxes and translating these boxes using the smallest CNF
   translations. </li>
   <li> Generating aes(2,4,2,4):
   \verbatim
shell> mkdir aes_4_2_4/min
shell> cd aes_4_2_4/min
shell> oklib --maxima
oklib_load_all()$
num_rounds : 1$
num_rows : 4$
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
shell> row=4; col=2; e=4; r=1; for s in $(seq 1 5); do
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
  r   n       c         t sat      cfs      dec   rts      r1 mem ptime  stime
1 1 436 2231.11 0.8882344   1 33807.72 36215.41 107.5 3798884   8     0 0.0067
       cfl r    k s
1 500397.7 1 10.5 3
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> row=4; col=2; e=4; r=1; for s in $(seq 1 5); do
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
  r   n    c    l     t sat      nds r1       r2 pls  ats     h file n2cr dmcl
1 1 436 2372 9244 13.91   1 55539.19 68 71163.17   0 2.66 22.53   NA  232    0
  dn  dc  dl   snds qnds   mnds tel  oats n2cs m2cs r    k s
1 68 212 660 129.11 0.05 146.15   0 13.23    0    0 1 10.5 3
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
   <li> Generating aes(1,4,2,4):
   \verbatim
shell> mkdir aes_4_2_4/1base
shell> cd aes_4_2_4/1base
shell> oklib --maxima
oklib_load_all()$
num_rounds : 1$
num_rows : 4$
num_columns : 2$
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
shell> row=4;col=2; e=4; r=1; for s in $(seq 1 5); do
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
  r   n       c         t sat      cfs      dec   rts      r1 mem ptime  stime
1 1 436 2506.91 0.8407917   1 29661.36 31636.49 97.27 3094054   8     0 0.0099
       cfl r    k s
1 446043.1 1 10.5 3
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> row=4; col=2; e=4; r=1; for s in $(seq 1 5); do
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
  r   n    c     l      t sat      nds r1       r2 pls  ats     h file n2cr
1 1 436 2648 10132 13.367   1 43111.14 68 52635.96   0 0.14 20.69   NA  256
  dmcl dn  dc  dl   snds qnds   mnds tel oats n2cs m2cs r    k s
1    0 68 212 660 197.69    0 104.08   0    0    0    0 1 10.5 3
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>


  \todo Using the canonical CNF translation
  <ul>
   <li> Translation of aes(2,2,2,4):
    <ul>
     <li> The MixColumns operation is decomposed into its field
     multiplications (02 and 03) and addition operations. </li>
     <li> The MixColumns operation is translated by translating both
     the MixColumns operation and its inverse (it is self-inverse). </li>
     <li> We treat S-boxes, field multiplications and additions as boxes.
     </li>
     <li> The S-box and field multiplications are considered as a 8x1
     boolean function, translated using the canonical CNF translation;
     see ss_sbox_fullcnf_fcs in
     ComputerAlgebra/Cryptology/Lisp/Cryptanalysis/Rijndael/SboxAnalysis.mac.
     see ssmult_fullcnf_fcs in
     ComputerAlgebra/Cryptology/Lisp/Cryptanalysis/Rijndael/FieldOperationsAnalysis.mac.
     </li>
     <li> Additions of arity k are considered bit-wise as (k+1)-bit to 1-bit
     boolean functions; translated using their prime implicates. </li>
    </ul>
   </li>
   <li> Generating small-scale AES for two rounds:
   \verbatim
shell> mkdir aes_2_2_4/full
shell> cd aes_2_2_4/full
shell> oklib --maxima
oklib_load_all()$
num_rounds : 2$
num_rows : 2$
num_columns : 2$
exp : 4$
final_round_b : false$
box_tran : aes_full_box$
mc_tran : aes_mc_bidirectional$
oklib_monitor : true$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r2_c2_rw2_e4_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
328 11176 86376 0 86376 329 1
 length count
1 8
3 544
4 64
8 10560
   \endverbatim
   </li>
   <li> In this translation, we have:
    <ul>
     <li> 2 full rounds (Key Addition, SubBytes, and MixColumns operation).
     </li>
     <li> 12 Sboxes:
      <ul>
       <li> 8 from SubBytes = 4 byte * 2 rounds; </li>
       <li> 4 from key schedule = 2 row * 1 word * 2 rounds. </li>
      </ul>
     </li>
     <li> 16 multiplications by 02: 2 rows * 1 multiplication * 2 columns
     * 2 rounds * 2 directions (forward + inverse). </li>
     <li> 16 multiplications by 03: 2 rows * 1 multiplication * 2 columns
     * 2 rounds * 2 directions (forward + inverse). </li>
     <li> 144 additions:
      <ul>
       <li> 76 additions of arity 2:
        <ul>
         <li> 32 from key additions = 16 bits * 2 round; </li>
         <li> 16 from final key addition = 16 bits; </li>
         <li> 24 from the key schedule = (16 bits - 4 bits) * 2 round. </li>
         <li> 32 from forward MixColumns = 2 rows * 2 column * 4 bits *
         2 round; </li>
         <li> 32 from inverse MixColumns = 2 rows * 2 column * 4 bits * 2
         round. </li>
        </ul>
        <li> 8 additions of arity 3:
         <ul>
          <li> 8 from the key schedule = 4 bits * 2 round. </li>
         </ul>
        </li>
       </li>
      </ul>
     </li>
     <li> 8 bits for the constant in the key schedule = 4 bits * 2 rounds.
     </li>
    </ul>
   </li>
   <li> All boxes are represented by their canonical CNFs. Each box
   is a 4-bit permutation considered as an 8x1 boolean function, and
   so the canonical CNF has 2^8 - 2^4 = 240 clauses of length 8.
   </li>
   <li> This instances has 44 boxes = 12 S-boxes + 32 multiplications.
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 8 = key schedule constant * 1; </li>
     <li> 3 : 544 = 136 additions (arity 2) * 4; </li>
     <li> 4 : 64 = 4 additions (arity 3) * 8; </li>
     <li> 8 : 10560 = 44 boxes * 240. </li>
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
shell> col=2; row=2; e=4; r=2; for s in $(seq 1 5); do
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
  r   n       c      t sat      cfs      dec   rts       r1 mem  ptime  stime
1 2 328 11122.3 0.4875   1 18593.56 22750.68 69.45 851741.4  20 0.0028 0.0845
       cfl r    k s
1 225584.2 2 10.5 3
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> col=2; row=2; e=4; r=2; for s in $(seq 1 5); do
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
     is still running after an hour, having solved no instances.
     </li>
    </ul>
   </li>
  </ul>


  \bug DONE (Corrected dimensions and specification for each file; added
  todo on updating translation functions)
  False specification of sizes
  <ul>
   <li> The directory is "2_4_4", and a "2x4 block" is mentioned, while
   below it says "two columns, four rows". </li>
   <li> What is a "block"? This likely should be a matrix. </li>
   <li> The dimensions of a matrix is specified as first the number of rows,
   then the number of columns. So we have an inconsistency. </li>
   <li> See "Order of small scale matrix dimensions" in
   ComputerAlgebra/Cryptology/Lisp/Cryptanalysis/Rijndael/plans/Translations.hpp
   for a todo on updating the translation function parameter order to
   correctly reflect the standard ordering for matrix dimensions.</li>
  </ul>

*/
