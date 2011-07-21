// Matthew Gwynne, 20.5.2011 (Swansea)
/* Copyright 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/KeyDiscovery/032/2_2_8/1_13.hpp
  \brief Investigations into small scale AES key discovery for 1 + 1/3 round AES with a 2x2 plaintext matrix and 8-bit field elements

  \todo Problem specification
  <ul>
   <li> We investigate the 1 + 1/3 round small-scale AES with 2 row,
   2 column, using the 8-bit field size. </li>
   <li> We denote this AES instance by aes(1,2,2,8). </li>
   <li> aes(1,2,2,8) takes a 32-bit plaintext and 32-bit key and
   outputs a 32-bit ciphertext. </li>
   <li> For the full specification of this AES instance, see
   "Problem specification" in
   Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/KeyDiscovery/016/2_2_4/general.hpp.
   </li>
   <li> Note that we consider the canonical CNF translation, as
   this is an example of the "hardest" representation without
   new variables. See "Hardness of boolean function representations"
   in
   Experimentation/Investigations/BooleanFunctions/plans/general.hpp. </li>
  </ul>


  \todo Using the canonical box translation
  <ul>
   <li> Translation of aes(1,2,2,8):
    <ul>
     <li> The MixColumns operation is decomposed into its field
     multiplications (02 and 03) and addition operations. </li>
     <li> The MixColumns operation is translated by translating both
     the MixColumns operation and its inverse (it is self-inverse). </li>
     <li> We treat S-boxes, field multiplications and additions as boxes.
     </li>
     <li> The S-box and field multiplications are considered as a 16x1
     boolean functions, translated using the canonical translation;
     see dualts_fcl in
     ComputerAlgebra/Satisfiability/Lisp/FiniteFunctions/TseitinTranslation.mac.
     </li>
     <li> Additions of arity k are considered bit-wise as (k+1)-bit to 1-bit
     boolean functions; translated using their prime implicates. </li>
    </ul>
   </li>
   <li> Generating small scale AES for 1 + 1/3 rounds:
   \verbatim
shell> mkdir aes_2_2_8/canon
shell> cd aes_2_2_8/canon
shell> oklib --maxima
oklib_load_all()$
num_rounds : 1$
num_rows : 2$
num_columns : 2$
exp : 8$
final_round_b : false$
box_tran : aes_ts_box$
mc_tran : aes_mc_bidirectional$
oklib_monitor : true$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r1_c1_rw2_e8_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
3264 52532 154472 0 154472 3265 1
 length count
1 8
2 49152
3 288
17 3072
256 12
   \endverbatim
   </li>
   <li> In this translation, we have:
    <ul>
     <li> 1 full round (Key Addition, SubBytes, and MixColumns operation).
     </li>
     <li> 4 Sboxes:
      <ul>
       <li> 2 from SubBytes = 2 byte * 1 round; </li>
       <li> 2 from key schedule = 2 row * 1 byte * 1 round. </li>
      </ul>
     </li>
     <li> 4 multiplications by 02: 2 rows * 1 multiplication * 1 columns *
     1 round * 2 directions (forward + inverse). </li>
     <li> 4 multiplications by 03: 2 rows * 1 multiplication * 1 columns *
     1 round * 2 directions (forward + inverse). </li>
     <li> 72 additions:
      <ul>
       <li> 16 from key additions = 16 bits * 1 round; </li>
       <li> 16 from final key addition = 16 bits; </li>
       <li> 8 from the key schedule = 1 rows * 8 bits * 1 round. </li>
       <li> 16 from forward MixColumns = 2 rows * 1 column * 8 bits *
       1 round; </li>
       <li> 16 from inverse MixColumns = 2 rows * 1 column * 8 bits * 1
       round. </li>
      </ul>
     </li>
     <li> 8 bits for the constant in the key schedule. </li>
    </ul>
   </li>
   <li> Note that as this variant has only one column, the key schedule
   applies Sbox(K_i) + C rather than Sbox(K_i) + K_j + C where K_i and
   K_j are key words from the previous round key. </li>
   <li> The Sboxes and multiplications use the canonical translation,
   which has the following number of clauses of each length:
   \verbatim
maxima> ncl_list_full_dualts(16,256);
[[2,4096],[17,256],[256,1]]
   \endverbatim
   </li>
   <li> This instances has 12 boxes = 4 S-boxes + 8 multiplications.
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 8 = key schedule constant * 1; </li>
     <li> 2 : 49152 = 12 boxes * 4096; </li>
     <li> 3 : 288 = 72 additions (arity 2) * 4; </li>
     <li> 17 : 3072 = 12 boxes * 256; </li>
     <li> 256 : 12 = 12 boxes * 1. </li>
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
shell> col=2; row=2; e=8; r=1; for s in $(seq 1 5); do
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
  r    n        c        t sat      cfs      dec    rts       r1    mem  ptime
1 1 6008 96357.73 25.79468   1 76229.92 269362.6 217.86 89469530 137.09 0.0494
   stime      cfl r    k s
1 0.0999 21795723 1 10.5 3
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> col=2; row=2; e=8; r=1; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    echo "Seed ${s}; Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf | RandomShuffleDimacs-O3-DNDEBUG $s > r${r}_k${k}_s${s}.cnf;
    (time OKsolver_2002-O3-DNDEBUG r${r}_k${k}_s${s}.cnf) > oksolver_r${r}_k${k}_s${s}.result 2>&1;
  done;
done;
shell> echo "n  c  l  t  sat  nds  r1  r2  pls  ats h file n2cr  dmcl dn  dc  dl snds qnds mnds  tel  oats  n2cs  m2cs r k s" > oksolver_results; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    cat oksolver_r${r}_k${k}_s${s}.result | awk -f extract_bash_time_oksolver.awk | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractOKsolver.awk | awk " { print \$0 \"  $r  $k $s\" }";
  done;
done >> oksolver_results;
     \endverbatim
     where extract_bash_time_oksolver.awk is (as OKsolver_2002 reports the wrong time in this instance):
     \verbatim
/^c running_time\(sec\)/ { }
/^real/  { split($2,a,"m"); split(a[2],b,"s"); print "c running_time(sec)                     " (a[1] * 60) + b[1]; }
$0 !~ /^(c running_time\(sec\)|real)/ { print }
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("oksolver_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r    n     c      l        t sat   nds r1       r2 pls  ats    h file  n2cr
1 1 6008 96510 283752 1903.331   1 192.2 72 270831.2   0 0.02 9.52   NA 90240
  dmcl dn  dc  dl snds qnds mnds tel oats n2cs m2cs r    k s
1    0 72 232 744    0    0    0   0    0    0    0 1 10.5 3
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>


  \todo Using the "minimum" box translation
  <ul>
   <li> Translation of aes(1,2,2,8):
    <ul>
     <li> The MixColumns operation is decomposed into its field
     multiplications (02 and 03) and addition operations. </li>
     <li> The MixColumns operation is translated by translating both
     the MixColumns operation and its inverse (it is self-inverse). </li>
     <li> We treat S-boxes and additions as boxes. </li>
     <li> The S-box and field multiplications are considered as a 8x1
     boolean function, translated using "minimum" representations;
     see
     Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/Representations/Sbox_8.hpp,
     Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/Representations/Mul_2_8.hpp
     and
     Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/Representations/Mul_3_8.hpp
     </li>
     <li> Additions of arity k are considered bit-wise as (k+1)-bit to 1-bit
     boolean functions; translated using their prime implicates. </li>
    </ul>
   </li>
   <li> The CNFs for the Sbox and multiplications:
   \verbatim
/* Multiplication by 02: */
maxima> FieldMul2CNF : [{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16},{{-9,2},{-2,9},{-10,3},{-3,10},{-11,4},{-4,11},{-12,-5,-1},{-12,1,5},{-5,1,12},{-1,5,12},{-13,-6,-1},{-1,6,13},{-14,7},{-7,14},{-15,1,8},{-8,1,15},{-16,-15,-8},{-16,8,15},{-13,6,16},{-6,13,16}}]$
set_hm(ss_field_cnfs,[8,2], FieldMul2CNF));
/* Multiplication by 03: */
maxima> FieldMul3CNF :
 [[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16],
  [{-9,-2,-1},{-2,1,9},{-10,2,3},{-10,-9,-3,1},{-10,-3,-1,9},{-3,2,10},{-9,1,3,10},{-1,3,9,10},{-11,-4,-3},{-11,3,4},{-4,3,11},{-3,4,11},{-12,-5,-4,1},{-12,-4,-1,5},{-5,1,4,12},{-1,4,5,12},{-13,-5,-1,6},{-13,1,5,6},{-13,-12,-6,4},{-13,-6,-4,12},{-6,-5,-1,13},{-6,1,5,13},
   {-12,4,6,13},{-4,6,12,13},{-14,-7,-6},{-14,6,7},{-7,6,14},{-6,7,14},{-16,-8,-1},{-16,1,8},{-16,-15,-7},{-16,7,15},{-8,1,16},{-1,8,16},{-15,7,16},{-7,15,16}]]$
set_hm(ss_field_cnfs,[8,2], FieldMul3CNF));
/* Sbox: */
maxima> output_rijnsbox_fullcnf_stdname();
shell> QuineMcCluskeySubsumptionHypergraph-n16-O3-DNDEBUG AES_Sbox_full.cnf > AES_Sbox_shg.cnf
shell> cat AES_Sbox_shg.cnf | MinOnes2WeightedMaxSAT-O3-DNDEBUG > AES_Sbox_shg.wcnf
shell> ubcsat-okl  -alg gsat -w -runs 100 -cutoff 40000000 -wtarget 294 -solve 1 -seed 3213901809 -i AES_Sbox_shg.wcnf -r model AES_Sbox_s294.ass;
shell> cat  AES_Sbox_full.cnf_primes | FilterDimacs AES_Sbox_s294.ass > AES_Sbox_s294.cnf
maxima> SboxMinCNF : read_fcl_f("AES_Sbox_s294.cnf");
maxima> set_hm(ss_sbox_cnfs,8, SboxMinCNF));
   \endverbatim
   </li>
   <li> Generating small scale AES for 1 + 1/3 rounds:
   \verbatim
shell> mkdir aes_1_1_8/canon
shell> cd aes_1_1_8/canon
shell> oklib --maxima
oklib_load_all()$
num_rounds : 1$
num_rows : 2$
num_columns : 2$
exp : 8$
final_round_b : false$
box_tran : aes_small_box$
oklib_monitor : true$
mc_tran : aes_mc_bidirectional$
output_ss_fcl_std(rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r1_c2_rw2_e8_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
3264 52532 154472 0 154472 3265 1
 length count
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
192 1696 9332 0 9332 193 1
 length count
1 8
2 32
3 416
4 64
6 572
7 508
8 96
   \endverbatim
   </li>
   <li> In this translation, we have:
    <ul>
     <li> 1 full round (Key Addition, SubBytes, and MixColumns operation).
     </li>
     <li> 4 Sboxes:
      <ul>
       <li> 2 from SubBytes = 2 byte * 1 round; </li>
       <li> 2 from key schedule = 2 row * 1 byte * 1 round. </li>
      </ul>
     </li>
     <li> 4 multiplications by 02: 2 rows * 1 multiplication * 1 columns
     * 1 round * 2 directions (forward + inverse). </li>
     <li> 4 multiplications by 03: 2 rows * 1 multiplication * 1 columns
     * 1 round * 2 directions (forward + inverse). </li>
     <li> 72 additions:
      <ul>
       <li> 16 from key additions = 16 bits * 1 round; </li>
       <li> 16 from final key addition = 16 bits; </li>
       <li> 8 from the key schedule = 1 rows * 8 bits * 1 round. </li>
       <li> 16 from forward MixColumns = 2 rows * 1 column * 8 bits *
       1 round; </li>
       <li> 16 from inverse MixColumns = 2 rows * 1 column * 8 bits * 1
       round. </li>
      </ul>
     </li>
     <li> 8 bits for the constant in the key schedule. </li>
    </ul>
   </li>
   <li> Note that as this variant has only one column, the key schedule
   applies Sbox(K_i) + C rather than Sbox(K_i) + K_j + C where K_i and
   K_j are key words from the previous round key. </li>
   <li> The Sboxes and multiplications use the "minimum" translations,
   which have the following number of clauses of each length:
   \verbatim
maxima> ncl_list_fcs(ev_hm(ss_sbox_cnfs,8));
[[6,143],[7,127],[8,24]]
maxima> ncl_list_fcs(ev_hm(ss_field_cnfs,[8,2]))
[[2,8],[3,12]]
maxima> ncl_list_fcs(ev_hm(ss_field_cnfs,[8,3]))
[[3,20],[4,16]]
   \endverbatim
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 8 = key schedule constant * 1; </li>
     <li> 2 : 32 = 4 multiplications by 02 * 8; </li>
     <li> 3 : 416 = 4 multiplications by 02 * 12 + 4 multiplications by 03 * 20
     +  72 additions (arity 2) * 4; </li>
     <li> 4 : 64 = 4 multiplications by 03 * 16; </li>
     <li> 6 : 572 = 4 S-boxes * 143; </li>
     <li> 7 : 508 = 4 S-boxes * 127; </li>
     <li> 8 : 96 = 4 S-boxes * 24. </li>
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
shell> col=2; row=2; e=8; r=1; for s in $(seq 1 5); do
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
  r   n       c        t sat      cfs      dec    rts      r1 mem ptime stime
1 1 376 2798.21 2.169589   1 151967.5 169391.9 383.45 5241233   8     0  0.01
      cfl r    k s
1 2309915 1 10.5 3
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> col=2; row=2; e=8; r=1; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    echo "Seed ${s}; Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf | RandomShuffleDimacs-O3-DNDEBUG $s > r${r}_k${k}_s${s}.cnf;
    (time OKsolver_2002-O3-DNDEBUG r${r}_k${k}_s${s}.cnf) > oksolver_r${r}_k${k}_s${s}.result 2>&1;
  done;
done;
shell> echo "n  c  l  t  sat  nds  r1  r2  pls  ats h file n2cr  dmcl dn  dc  dl snds qnds mnds  tel  oats  n2cs  m2cs r k s" > oksolver_results; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    cat oksolver_r${r}_k${k}_s${s}.result | awk -f extract_bash_time_oksolver.awk | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractOKsolver.awk | awk " { print \$0 \"  $r  $k $s\" }";
  done;
done >> oksolver_results;
     \endverbatim
     where extract_bash_time_oksolver.awk is (as OKsolver_2002 reports the wrong time in this instance):
     \verbatim
/^c running_time\(sec\)/ { }
/^real/  { split($2,a,"m"); split(a[2],b,"s"); print "c running_time(sec)                     " (a[1] * 60) + b[1]; }
$0 !~ /^(c running_time\(sec\)|real)/ { print }
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("oksolver_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r   n    c     l        t sat     nds r1       r2 pls  ats     h file n2cr
1 1 376 2956 15194 35.38703   1 94287.2 72 163528.6   0 0.41 24.94   NA  192
  dmcl dn  dc  dl   snds qnds   mnds tel oats n2cs m2cs r    k s
1    0 72 232 744 314.09    0 196.78   0    0    0    0 1 10.5 3
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>


  \todo Using the 1-base box translation
  <ul>
   <li> Translation of aes(1,2,2,8):
    <ul>
     <li> The MixColumns operation is decomposed into its field
     multiplications (02 and 03) and addition operations. </li>
     <li> The MixColumns operation is translated by translating both
     the MixColumns operation and its inverse (it is self-inverse). </li>
     <li> We treat S-boxes and additions as boxes. </li>
     <li> The S-box and field multiplications are considered as a 16x1
     boolean function, translated using 1-bases;
     see
     Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/Representations/Sbox_8.hpp,
     Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/Representations/Mul_2_8.hpp
     and
     Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/Representations/Mul_3_8.hpp.
     </li>
     <li> Additions of arity k are considered bit-wise as (k+1)-bit to 1-bit
     boolean functions; translated using their prime implicates. </li>
    </ul>
   </li>
   <li> Generating a 1-base for the S-box from
   Cryptography/AdvancedEncryptionStandard/plans/SAT2011/Representations/Sbox_8.hpp. :
   \verbatim
maxima> output_rijnsbox_fullcnf_stdname();
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
   <li> Generating a 1-base for the multiplication by 02 and 03 from
   Cryptography/AdvancedEncryptionStandard/plans/SAT2011/Representations/Sbox_8.hpp. :
   \verbatim
maxima> output_rijn_mult_fullcnf_stdname(2);
shell> QuineMcCluskey-n16-O3-DNDEBUG AES_byte_field_mul_full_2.cnf > AES_byte_field_mul_2_pi.cnf
shell> RandomShuffleDimacs-O3-DNDEBUG 1 < AES_byte_field_mul_2_pi.cnf | SortByClauseLength-O3-DNDEBUG > AES_byte_field_mul_2_sortedpi.cnf
shell> RUcpGen-O3-DNDEBUG AES_byte_field_mul_2_sortedpi.cnf > AES_byte_field_mul_2_gen.cnf
shell> RandomShuffleDimacs-O3-DNDEBUG 1 < AES_byte_field_mul_2_gen.cnf | SortByClauseLengthDescending-O3-DNDEBUG | RUcpBase-O3-DNDEBUG > AES_byte_field_mul_2_base.cnf
shell> cat AES_byte_field_mul_2_base.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
16 22 56 0 56 0 1
 length count
2 10
3 12
maxima> output_rijn_mult_fullcnf_stdname(3);
shell> QuineMcCluskey-n16-O3-DNDEBUG AES_byte_field_mul_full_3.cnf > AES_byte_field_mul_3_pi.cnf
shell> RandomShuffleDimacs-O3-DNDEBUG 1 < AES_byte_field_mul_3_pi.cnf | SortByClauseLength-O3-DNDEBUG > AES_byte_field_mul_3_sortedpi.cnf
shell> RUcpGen-O3-DNDEBUG AES_byte_field_mul_3_sortedpi.cnf > AES_byte_field_mul_3_gen.cnf
shell> RandomShuffleDimacs-O3-DNDEBUG 1 < AES_byte_field_mul_3_gen.cnf | SortByClauseLengthDescending-O3-DNDEBUG | RUcpBase-O3-DNDEBUG > AES_byte_field_mul_3_base.cnf
shell> cat AES_byte_field_mul_3_base.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
16 80 328 0 328 0 1
 length count
3 24
4 24
5 32
   \endverbatim
   </li>
   <li> Translating the AES cipher treating Sboxes and field multiplications
   as whole boxes and translating these boxes using 1-bases.
   </li>
   <li> Generating small scale AES for 1 + 1/3 rounds:
   \verbatim
shell> mkdir aes_1_1_8/canon
shell> cd aes_1_1_8/canon
shell> oklib --maxima
oklib_load_all()$
num_rounds : 1$
num_rows : 2$
num_columns : 2$
exp : 8$
final_round_b : false$
box_tran : aes_rbase_box$
oklib_monitor : true$
mc_tran : aes_mc_bidirectional$
set_hm(ss_sbox_rbase_cnfs,8,read_fcl_f("AES_Sbox_base.cnf"))$
set_hm(ss_field_rbase_cnfs,[8,2],read_fcl_f("AES_byte_field_mul_2_base.cnf"))$
set_hm(ss_field_rbase_cnfs,[8,3],read_fcl_f("AES_byte_field_mul_3_base.cnf"))$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r1_c2_rw2_e8_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
192 18296 122840 0 122840 193 1
 length count
1 8
2 40
3 432
4 96
5 132
6 4748
7 10812
8 2012
9 16
   \endverbatim
   </li>
   <li> In this translation, we have:
    <ul>
     <li> 1 full round (Key Addition, SubBytes, and MixColumns operation).
     </li>
     <li> 4 Sboxes:
      <ul>
       <li> 2 from SubBytes = 2 byte * 1 round; </li>
       <li> 2 from key schedule = 2 row * 1 byte * 1 round. </li>
      </ul>
     </li>
     <li> 4 multiplications by 02: 2 rows * 1 multiplication * 1 columns
     * 1 round * 2 directions (forward + inverse). </li>
     <li> 4 multiplications by 03: 2 rows * 1 multiplication * 1 columns
     * 1 round * 2 directions (forward + inverse). </li>
     <li> 72 additions:
      <ul>
       <li> 32 additions of arity 3:
        <ul>
         <li> 16 from forward MixColumns = 2 rows * 1 column * 8 bits *
         1 round; </li>
         <li> 16 from inverse MixColumns = 2 rows * 1 column * 8 bits * 1
         round. </li>
        </ul>
       </li>
       <li> 40 additions of arity 2:
        <ul>
         <li> 16 from key additions = 16 bits * 1 round; </li>
         <li> 16 from final key addition = 16 bits; </li>
         <li> 8 from the key schedule = 1 rows * 8 bits * 1 round. </li>
        </ul>
       </li>
      </ul>
     </li>
     <li> 8 bits for the constant in the key schedule. </li>
    </ul>
   </li>
   <li> Note that as this variant has only one column, the key schedule
   applies Sbox(K_i) + C rather than Sbox(K_i) + K_j + C where K_i and
   K_j are key words from the previous round key. </li>
   <li> The Sboxes and multiplications use 1-base translations,
   which have the following number of clauses of each length:
   \verbatim
maxima> ncl_list_fcs(ev_hm(ss_sbox_rbase_cnfs,8));
[[5,1],[6,1187],[7,2703],[8,503],[9,4]]
maxima> ncl_list_fcs(ev_hm(ss_field_rbase_cnfs,[8,2]))
[[2,10],[3,12]]
maxima> ncl_list_fcs(ev_hm(ss_field_rbase_cnfs,[8,3]))
[[3,24],[4,24],[5,32]]
   \endverbatim
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 8 = key schedule constant * 1; </li>
     <li> 2 : 40 = 4 multiplications by 02 * 10; </li>
     <li> 3 : 432 = 4 multiplications by 02 * 12 + 4 multiplications by 03 * 24
     + 72 additions (arity 2) * 4; </li>
     <li> 4 : 96 = 4 multiplications by 03 * 24; </li>
     <li> 5 : 132 = 4 S-boxes * 1 + 4 multiplications by 03 * 32; </li>
     <li> 6 : 4748 = 4 S-boxes * 1187; </li>
     <li> 7 : 10812 = 4 S-boxes * 2703; </li>
     <li> 8 : 2012 = 4 S-boxes * 503; </li>
     <li> 9 : 16 = 4 S-boxes * 4. </li>
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
shell> col=2; row=2; e=8; r=1; for s in $(seq 1 5); do
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
  r   n        c        t sat     cfs      dec   rts      r1   mem  ptime
1 1 376 27799.44 3.990333   1 27239.7 29821.04 92.96 1758642 12.27 0.0199
   stime      cfl r    k s
1 1.2083 448487.8 1 10.5 3
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> col=1; row=2; e=8; r=1; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    echo "Seed ${s}; Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf | RandomShuffleDimacs-O3-DNDEBUG $s > r${r}_k${k}_s${s}.cnf;
    OKsolver_2002-O3-DNDEBUG r${r}_k${k}_s${s}.cnf > oksolver_r${r}_k${k}_s${s}.result 2>&1;
  done;
done;
shell> echo "n  c  l  t  sat  nds  r1  r2  pls  ats h file n2cr  dmcl dn  dc  dl snds qnds mnds  tel  oats  n2cs  m2cs r k s" > oksolver_results; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    cat oksolver_r${r}_k${k}_s${s}.result | awk -f extract_bash_time_oksolver.awk | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractOKsolver.awk | awk " { print \$0 \"  $r  $k $s\" }";
  done;
done >> oksolver_results;
     \endverbatim
where extract_bash_time_oksolver.awk is (as OKsolver_2002 reports the wrong time in this instance):
     \verbatim
/^c running_time\(sec\)/ { }
/^real/  { split($2,a,"m"); split(a[2],b,"s"); print "c running_time(sec)                     " (a[1] * 60) + b[1]; }
$0 !~ /^(c running_time\(sec\)|real)/ { print }
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("oksolver_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r   n     c      l        t sat     nds r1       r2 pls  ats     h file n2cr
1 1 376 27948 185872 54.79475   1 8048.11 72 12470.98   0 0.04 18.31   NA  208
  dmcl dn  dc  dl snds qnds mnds tel oats n2cs m2cs r    k s
1    0 72 232 744 19.4    0 0.36   0    0    0    0 1 10.5 3
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>

*/
