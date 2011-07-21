// Matthew Gwynne, 15.2.2011 (Swansea)
/* Copyright 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/KeyDiscovery/008/1_1_8/20_13.hpp
  \brief Investigations into small-scale AES key discovery with 1 row, 1 column and 8-bit field elements for 20 + 1/3 round AES


  \todo Problem specification
  <ul>
   <li> We investigate the 20 + 1/3 round small-scale AES with 1 row,
   1 column, using the 8-bit field size. </li>
   <li> We denote this AES instance by aes(20,1,1,8). </li>
   <li> aes(20,1,1,8) takes a 8-bit plaintext and 8-bit key and
   outputs a 8-bit ciphertext. </li>
   <li> For the full specification of this AES instance, see
   "Problem specification" in
   Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/KeyDiscovery/008/1_1_8/general.hpp.
   </li>
   <li> The decompositions and translations are listed in "Investigating
   dimensions" in
   Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/Experimentation.hpp.
   </li>
   <li> Note that we consider the canonical CNF translation, as
   this is an example of the "hardest" representation without
   new variables. See "Hardness of boolean function representations"
   in
   Experimentation/Investigations/BooleanFunctions/plans/general.hpp. </li>
  </ul>


  \todo Using the canonical box translation
  <ul>
   <li> Translation of aes(20,1,1,8):
    <ul>
     <li> We treat S-boxes and additions as boxes. </li>
     <li> The S-box is considered as a 16x1 boolean function,
     translated using the canonical translation; see dualts_fcl in
     ComputerAlgebra/Satisfiability/Lisp/FiniteFunctions/TseitinTranslation.mac.
     </li>
     <li> Additions of arity k are considered bit-wise as (k+1)-bit to 1-bit
     boolean functions; translated using their prime implicates. </li>
     <li> The MixColumns operation is the identity. </li>
     <li> Due to limitations in the translation, clauses occur in this
     translation representing equivalence of variables in the MixColumns;
     See "Remove hard-coding of multiplication by 01 in small-scale MixColumn"
     in
     ComputerAlgebra/Cryptology/Lisp/Cryptanalysis/Rijndael/plans/Translations.hpp.
     </li>
    </ul>
   </li>
   <li> Translation of aes(20,1,1,8):
    <ul>
     <li> We treat S-boxes and additions as boxes. </li>
     <li> S-boxes are translated using the canonical translation;
     see dualts_fcl in
     ComputerAlgebra/Satisfiability/Lisp/FiniteFunctions/TseitinTranslation.mac.
     </li>
     <li> Additions are translated using their prime implicates. </li>
     <li> The MixColumns operation is translated by translating both
     the MixColumns operation and its inverse. </li>
    </ul>
   </li>
   <li> Generating simplest small-scale AES for 20+1/3 rounds:
   \verbatim
shell> ${OKlib}/Experimentation/Investigations/Cryptography/AdvancedEncryptionStandard/generate_aes_experiment 20 1 1 1 8 false aes_ts_box aes_mc_bidirectional
shell> cat ssaes_r20_c1_rw1_e8_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
11224 176232 517376 0 517376 11225 1
 length count
1 160
2 164480
3 1312
17 10240
256 40
   \endverbatim
   </li>
   <li> In this translation, we have:
    <ul>
     <li> 20 full rounds (Key Addition and SubBytes).
     </li>
     <li> 40 Sboxes:
      <ul>
       <li> 20 from SubBytes = 1 byte * 20 round; </li>
       <li> 20 from key schedule = 1 row * 1 byte * 20 round. </li>
      </ul>
     </li>
     <li> 648 additions:
      <ul>
       <li> 320 additions of arity 1:
        <ul>
         <li> 160 from forward MixColumns = 8 bits * 20 rounds; </li>
         <li> 160 from inverse MixColumns = 8 bits * 20 rounds. </li>
        </ul>
       </li>
       <li> 328 additions of arity 2:
        <ul>
         <li> 160 from key additions = 8 bits * 20 rounds; </li>
         <li> 8 from final key addition = 8 bits; </li>
         <li> 160 from the key schedule = 8 bits * 20 rounds. </li>
        </ul>
       </li>
      </ul>
     </li>
     <li> 8 bits for the constant in the key schedule. </li>
    </ul>
   </li>
   <li> The number of clauses of each length in the canonical translation of
   the S-box:
   \verbatim
maxima> ncl_list_full_dualts(8,16);
[[2,4096],[17,256],[256,1]]
   \endverbatim
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 160 = key schedule constant * 1; </li>
     <li> 2 : 164480 = 40 S-boxes * 4096 + 320 "additions" (arity 1) * 2;
     </li>
     <li> 3 : 1312 = 328 additions (arity 2) * 4; </li>
     <li> 17 : 10240 = 40 S-boxes * 256; </li>
     <li> 256 : 40 = 40 S-boxes * 1. </li>
    </ul>
   </li>
   <li> Then we run experiments for AES instances with one round, up to
   those with twenty rounds, and inspect the results for round 20.
   \verbatim
shell> ${OKlib}/Experimentation/Investigations/Cryptography/AdvancedEncryptionStandard/run_aes_experiment 20 1 1 1 8 false aes_ts_box aes_mc_bidirectional
   \endverbatim
   </li>
   <li> precosat236 solves this problem with no decisions in a fraction
   of a second:
   \verbatim
shell> cat experiment_r20_k1.cnf_precosat236
<snip>
c 0 conflicts, 0 decisions, 0 random
c 0 iterations, 0 restarts, 0 skipped
c prps: 2928753 propagations, 5.87 megaprops
c 0.5 seconds, 15 MB max, 6 MB recycled
   \endverbatim
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
shell> col=1; row=1; e=8; r=20; for s in $(seq 1 5); do
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
   r     n        c      t sat    cfs     dec  rts      r1 mem  ptime  stime
1 20 11224 175904.6 0.4589   1 366.54 4908.28 3.37 1161237  32 0.0709 0.2673
       cfl  r    k s
1 90119.44 20 10.5 3
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> col=1; row=1; e=8; r=20; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    echo "Seed ${s}; Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf | RandomShuffleDimacs-O3-DNDEBUG $s > r${r}_k${k}_s${s}.cnf;
    (time OKsolver_2002-O3-DNDEBUG) r${r}_k${k}_s${s}.cnf > oksolver_r${r}_k${k}_s${s}.result 2>&1;
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
   r     n      c      l      t sat nds  r1      r2 pls  ats h file   n2cr dmcl
1 20 11224 176248 517392 20.752   1   1 176 5601.18   0 0.65 0   NA 164832    0
   dn  dc   dl snds qnds mnds tel oats n2cs m2cs  r    k s
1 176 528 1584    0    0    0   0    0    0    0 20 10.5 3
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>


  \todo Using the 1-base box translation
  <ul>
   <li> Generating a 1-base for the S-box from
   Cryptography/AdvancedEncryptionStandard/plans/SAT2011/Representations/Sbox_8.hpp. :
   \verbatim
shell> QuineMcCluskey-n16-O3-DNDEBUG AES_Sbox_full.cnf > AES_Sbox_pi.cnf
shell> RandomShuffleDimacs-O3-DNDEBUG 103 < AES_Sbox_pi.cnf | SortByClauseLength-O3-DNDEBUG > AES_Sbox_sortedpi.cnf
shell> RUcpGen-O3-DNDEBUG AES_Sbox_sortedpi.cnf > AES_Sbox_gen.cnf
shell> RandomShuffleDimacs-O3-DNDEBUG 1 < AES_Sbox_gen.cnf | SortByClauseLengthDescending-O3-DNDEBUG | RUcpBase-O3-DNDEBUG > AES_Sbox_base.cnf
shell> cat AES_Sbox_base.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
16 4398 30108 0 30108 0 1
 length count
5 1
6 1187
7 2703
8 503
9 4
   \endverbatim
   </li>
   <li> Generating 8-bit small scale AES for 10 rounds:
   \verbatim
shell> mkdir aes_1_1_8/small
shell> cd aes_1_1_8/small
shell> oklib --maxima
oklib_load_all()$
set_hm(ss_sbox_rbase_cnfs,8,read_fcl_f("AES_Sbox_base.cnf"))$
num_rounds : 20$
num_rows : 1$
num_columns : 1$
exp : 8$
final_round_b : false$
box_tran : aes_rbase_box$
mc_tran : aes_mc_bidirectional$
oklib_monitor : true$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r10_c1_rw1_e8_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
984 178032 1209696 0 1209696 985 1
 length count
1 160
2 640
3 1312
5 40
6 47480
7 108120
8 20120
9 160
   \endverbatim
   </li>
   <li> In this translation, we have:
    <ul>
     <li> 20 full rounds (Key Addition and SubBytes).
     </li>
     <li> 40 Sboxes:
      <ul>
       <li> 20 from SubBytes = 1 byte * 20 round; </li>
       <li> 20 from key schedule = 1 row * 1 byte * 20 round. </li>
      </ul>
     </li>
     <li> 648 additions:
      <ul>
       <li> 320 additions of arity 1:
        <ul>
         <li> 160 from forward MixColumns = 8 bits * 20 rounds; </li>
         <li> 160 from inverse MixColumns = 8 bits * 20 rounds. </li>
        </ul>
       </li>
       <li> 328 additions of arity 2:
        <ul>
         <li> 160 from key additions = 8 bits * 20 rounds; </li>
         <li> 8 from final key addition = 8 bits; </li>
         <li> 160 from the key schedule = 8 bits * 20 rounds. </li>
        </ul>
       </li>
      </ul>
     </li>
     <li> 8 bits for the constant in the key schedule. </li>
    </ul>
   </li>
   <li> The number of clauses in the 1-base translation:
   \verbatim
maxima> ncl_list_fcs(ev_hm(ss_sbox_rbase_cnfs,8));
[[5,1],[6,1187],[7,2703],[8,503],[9,4]]
   \endverbatim
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 160 = key schedule constant * 1; </li>
     <li> 2 : 640 = 320 "additions" (arity 1) * 2; </li>
     <li> 3 : 1312 = 328 additions (arity 2) * 4; </li>
     <li> 5 : 40 = 40 S-boxes * 1; </li>
     <li> 6 : 47480 = 40 S-boxes * 1187; </li>
     <li> 7 : 108120 = 40 S-boxes * 2703; </li>
     <li> 8 : 20120 = 40 S-boxes * 503; </li>
     <li> 9 : 160 = 40 S-boxes * 4. </li>
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
shell> col=1; row=1; e=8; r=20; for s in $(seq 1 5); do
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
   r   n        c       t sat     cfs      dec   rts       r1 mem  ptime
1 20 984 177699.1 13.4379   1 10735.2 15258.61 43.34 643181.3  39 0.1028
    stime      cfl  r    k s
1 10.4181 145037.5 20 10.5 3
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> col=1; row=1; e=8; r=20; for s in $(seq 1 5); do
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
   r   n      c       l      t sat    nds  r1     r2 pls ats     h file n2cr
1 20 984 178048 1209712 99.389   1 193.45 176 794.48   0   0 10.59   NA  992
  dmcl  dn  dc   dl snds qnds mnds tel oats n2cs m2cs  r    k s
1    0 176 528 1584    0    0    0   0    0    0    0 20 10.5 3
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>


  \todo Using the "minimum" box translation
  <ul>
   <li> Translation of aes(10,1,1,8):
    <ul>
     <li> We treat S-boxes and additions as boxes. </li>
     <li> The S-box is considered as a 16x1 boolean function,
     translated using the minimum translation; see ss_sbox_cnfs in
     ComputerAlgebra/Cryptology/Lisp/Cryptanalysis/Rijndael/data/SmallScaleSboxCNF.mac
     </li>
     <li> Additions of arity k are considered bit-wise as (k+1)-bit to 1-bit
     boolean functions; translated using their prime implicates. </li>
     <li> The MixColumns operation is the identity. </li>
     <li> Due to limitations in the translation, clauses occur in this
     translation representing equivalence of variables in the MixColumns;
     See "Remove hard-coding of multiplication by 01 in small-scale MixColumn"
     in
     ComputerAlgebra/Cryptology/Lisp/Cryptanalysis/Rijndael/plans/Translations.hpp.
     </li>
    </ul>
   </li>
   <li> Generating 8-bit small-scale AES for 10 rounds:
   \verbatim
shell> mkdir aes_1_1_8/small
shell> cd aes_1_1_8/small
shell> oklib --maxima
oklib_load_all()$
num_rounds : 20$
num_rows : 1$
num_columns : 1$
exp : 8$
final_round_b : false$
box_tran : aes_small_box$
mc_tran : aes_mc_bidirectional$
oklib_monitor : true$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r20_c1_rw1_e8_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
984 13872 82936 0 82936 985 1
 length count
1 160
2 640
3 1312
6 5720
7 5080
8 960
   \endverbatim
   </li>
   <li> In this translation, we have:
    <ul>
     <li> 20 full rounds (Key Addition and SubBytes).
     </li>
     <li> 40 Sboxes:
      <ul>
       <li> 20 from SubBytes = 1 byte * 20 round; </li>
       <li> 20 from key schedule = 1 row * 1 byte * 20 round. </li>
      </ul>
     </li>
     <li> 648 additions:
      <ul>
       <li> 320 additions of arity 1:
        <ul>
         <li> 160 from forward MixColumns = 8 bits * 20 rounds; </li>
         <li> 160 from inverse MixColumns = 8 bits * 20 rounds. </li>
        </ul>
       </li>
       <li> 328 additions of arity 2:
        <ul>
         <li> 160 from key additions = 8 bits * 20 rounds; </li>
         <li> 8 from final key addition = 8 bits; </li>
         <li> 160 from the key schedule = 8 bits * 20 rounds. </li>
        </ul>
       </li>
      </ul>
     </li>
     <li> 8 bits for the constant in the key schedule. </li>
    </ul>
   </li>
   <li> The number of clauses in the minimum translation:
   \verbatim
maxima> ncl_list_fcs(ev_hm(ss_sbox_cnfs,8));
[[6,143],[7,127],[8,24]]
   \endverbatim
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 160 = key schedule constant * 1; </li>
     <li> 2 : 640 = 320 "additions" (arity 1) * 2; </li>
     <li> 3 : 1312 = 328 additions (arity 2) * 4; </li>
     <li> 6 : 5720 = 40 S-boxes * 143; </li>
     <li> 7 : 5080 = 40 S-boxes * 127; </li>
     <li> 8 : 960 = 40 S-boxes * 24. </li>
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
shell> col=1; row=1; e=8; r=20; for s in $(seq 1 5); do
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
   r   n        c      t sat      cfs     dec     rts       r1   mem  ptime
1 20 984 13538.52 9.7633   1 787405.2 1200715 1560.89 10201845 24.97 0.0035
   stime      cfl  r    k s
1 0.0444 10385760 20 10.5 3
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> col=1; row=1; e=8; r=20; for s in $(seq 1 1); do
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
   r   n     c     l     t sat     nds  r1       r2 pls ats     h file n2cr
1 20 984 13888 82952 6.355   1 2106.83 176 12402.31   0   0 26.83   NA  992
  dmcl  dn  dc   dl snds qnds mnds tel oats n2cs m2cs  r    k s
1    0 176 528 1584 0.45    0 0.64   0    0    0    0 20 10.5 3
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>

*/
