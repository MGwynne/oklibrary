// Matthew Gwynne, 15.2.2011 (Swansea)
/* Copyright 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/KeyDiscovery/016/2_2_4/2_13.hpp
  \brief Investigations into small-scale AES key discovery for 2 + 1/3 round AES with a 2x2 plaintext matrix and 4-bit field elements


  \todo Problem specification
  <ul>
   <li> We investigate the 2 + 1/3 round small-scale AES with 2 row,
   2 column, using the 4-bit field size. </li>
   <li> We denote this AES instance by aes(2,2,2,4). </li>
   <li> aes(2,2,2,4) takes a 16-bit plaintext and 16-bit key and
   outputs a 16-bit ciphertext. </li>
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
   <li> Translation of aes(2,2,2,4):
    <ul>
     <li> The MixColumns operation is decomposed into its field
     multiplications (02 and 03) and addition operations. </li>
     <li> The MixColumns operation is translated by translating both
     the MixColumns operation and its inverse (it is self-inverse). </li>
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
   <li> Generating small-scale AES for 2 + 1/3 rounds:
   \verbatim
shell> mkdir aes_2_2_4/canon
shell> cd aes_2_2_4/canon
shell> oklib --maxima
oklib_load_all()$
num_rounds : 2$
num_rows : 2$
num_columns : 2$
exp : 4$
final_round_b : false$
box_tran : aes_ts_box$
mc_tran : aes_mc_bidirectional$
oklib_monitor : true$
output_ss_fcl_std(rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r2_c2_rw2_e4_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG  n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
1032 6996 20200 0 20200 1033 1
 length count
1 8
2 5632
3 544
4 64
9 704
16 44
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
     <li> 16 multiplications by 02: 2 rows * 1 multiplication * 2 columns *
     2 rounds * 2 directions (forward + inverse). </li>
     <li> 16 multiplications by 03: 2 rows * 1 multiplication * 2 columns *
     2 rounds * 2 directions (forward + inverse). </li>
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
   <li> The number of clauses in the canonical translation for all
   boxes (Sbox and multiplications):
   \verbatim
maxima> ncl_list_full_dualts(8,16);
[[2,128],[9,16],[16,1]]
   \endverbatim
   </li>
   <li> This instances has 44 boxes = 12 S-boxes + 32 multiplications.
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 8 = key schedule constant * 1; </li>
     <li> 2 : 5632 = 44 boxes * 128; </li>
     <li> 3 : 544 = 136 additions (arity 2) * 4; </li>
     <li> 4 : 64 = 8 additions (arity 3) * 8; </li>
     <li> 9 : 704 = 44 boxes * 16; </li>
     <li> 16 : 44 = 44 boxes * 1. </li>
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
shell> col=2; row=2; e=4; r=2;
  for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    minisat-2.2.0 r${r}_k${k}.cnf > minisat_r${r}_k${k}.result 2>&1;
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
  r    n    c     t sat      cfs      dec   rts      r1 mem ptime stime
1 2 1032 6956 0.474   1 10837.15 12999.65 44.15 2427005  19     0 0.001
       cfl r    k
1 272529.2 2 10.5
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> col=2; row=2; e=4; r=2;
  for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    OKsolver_2002-O3-DNDEBUG r${r}_k${k}.cnf > oksolver_r${r}_k${k}.result 2>&1;
done;
shell> echo "n  c  l  t  sat  nds  r1  r2  pls  ats h file n2cr  dmcl dn  dc  dl snds qnds mnds  tel  oats  n2cs  m2cs r k" > oksolver_results;
  for k in $(seq 1 20); do
    cat oksolver_r${r}_k${k}.result | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractOKsolver.awk | awk " { print \$0 \"  $r  $k\" }";
done >> oksolver_results;
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("oksolver_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r    n    c     l     t sat    nds r1   r2 pls ats h file n2cr dmcl dn  dc
1 2 1032 7028 20232 1.415   1 163.75 40 1200   0   0 8   NA 5696    0 40 136
   dl snds qnds mnds tel oats n2cs m2cs r    k
1 456    0    0    0   0    0    0    0 2 10.5
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>


  \todo Using the 1-base box translation
  <ul>
   <li> Translation of aes(2,2,2,4):
    <ul>
     <li> The MixColumns operation is decomposed into its field
     multiplications (02 and 03) and addition operations. </li>
     <li> The MixColumns operation is translated by translating both
     the MixColumns operation and its inverse (it is self-inverse). </li>
     <li> We treat S-boxes and additions as boxes. </li>
     <li> The S-box and field multiplications are considered as a 8x1
     boolean function, translated using 1-bases; see ss_sbox_rbase_cnfs
     in
     ComputerAlgebra/Cryptology/Lisp/Cryptanalysis/Rijndael/data/SmallScaleSboxCNF.mac.
     </li>
     <li> Additions of arity k are considered bit-wise as (k+1)-bit to 1-bit
     boolean functions; translated using their prime implicates. </li>
    </ul>
   </li>
   <li> Generating small-scale AES for two rounds:
   \verbatim
shell> mkdir aes_2_2_4/1base
shell> cd aes_2_2_4/1base
shell> oklib --maxima
oklib_load_all()$
num_rounds : 2$
num_rows : 2$
num_columns : 2$
exp : 4$
final_round_b : false$
box_tran : aes_rbase_box$
mc_tran : aes_mc_bidirectional$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r2_c2_rw2_e4_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
328 1484 4712 0 4712 329 1
 length count
1 8
2 96
3 1008
4 372
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
     <li> 16 multiplications by 02: 2 rows * 1 multiplication * 2 columns *
     2 rounds * 2 directions (forward + inverse). </li>
     <li> 16 multiplications by 03: 2 rows * 1 multiplication * 2 columns *
     2 rounds * 2 directions (forward + inverse). </li>
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
   <li> The number of clauses in the 1-base translation of the Sbox and
   multiplications:
   \verbatim
maxima> ncl_list_fcs(ev_hm(ss_sbox_rbase_cnfs,4));
[[3,12],[4,15]]
maxima> ncl_list_fcs(ev_hm(ss_field_rbase_cnfs,[4,2]));
[[2,6],[3,4]]
maxima> ncl_list_fcs(ev_hm(ss_field_rbase_cnfs,[4,3]));
[[3,16],[4,8]]
   \endverbatim
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 8 = key schedule constant * 1; </li>
     <li> 2 : 96 = 16 multiplications by 02 * 6; </li>
     <li> 3 : 1008 = 12 S-boxes * 12 + 16 multiplications by 02 * 4 +
     16 multiplications by 03 * 16 + 136 additions (arity 2) * 4; </li>
     <li> 4 : 372 = 12 S-boxes * 15 + 16 multiplications by 03 * 8 +
     8 additions (arity 3) * 8. </li>
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
shell> col=2; row=2; e=4; r=2;
  for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    minisat-2.2.0 r${r}_k${k}.cnf > minisat_r${r}_k${k}.result 2>&1;
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
  r    n    c      t sat      cfs      dec   rts      r1 mem ptime  stime
1 2 1032 6956 0.4715   1 10837.15 12999.65 44.15 2427005  19     0 0.0015
       cfl r    k
1 272529.2 2 10.5
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> col=2; row=2; e=4; r=2; for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    OKsolver_2002-O3-DNDEBUG r${r}_k${k}.cnf > oksolver_r${r}_k${k}.result 2>&1;
done;
shell> echo "n  c  l  t  sat  nds  r1  r2  pls  ats h file n2cr  dmcl dn  dc  dl snds qnds mnds  tel  oats  n2cs  m2cs r k" > oksolver_results;
  for k in $(seq 1 20); do
    cat oksolver_r${r}_k${k}.result | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractOKsolver.awk | awk " { print \$0 \"  $r  $k\" }";
done >> oksolver_results;
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("oksolver_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r    n    c     l     t sat    nds r1   r2 pls ats h file n2cr dmcl dn  dc
1 2 1032 7028 20232 1.415   1 163.75 40 1200   0   0 8   NA 5696    0 40 136
   dl snds qnds mnds tel oats n2cs m2cs r    k
1 456    0    0    0   0    0    0    0 2 10.5
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>


  \todo Using the "minimum" translation
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
     boolean function, translated using the "minimum" translation;
     see ss_sbox_cnfs in
     ComputerAlgebra/Cryptology/Lisp/Cryptanalysis/Rijndael/data/SmallScaleSboxCNF.mac
     and ss_field_cnfs in
     ComputerAlgebra/Cryptology/Lisp/Cryptanalysis/Rijndael/data/SmallScaleFieldMulCNF.mac.
     </li>
     <li> Additions of arity k are considered bit-wise as (k+1)-bit to 1-bit
     boolean functions; translated using their prime implicates. </li>
    </ul>
   </li>
   <li> Generating small-scale AES for two rounds:
   \verbatim
shell> mkdir aes_2_2_4/min
shell> cd aes_2_2_4/min
shell> oklib --maxima
oklib_load_all()$
num_rounds : 2$
num_rows : 2$
num_columns : 2$
exp : 4$
final_round_b : false$
box_tran : aes_small_box$
mc_tran : aes_mc_bidirectional$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r2_c2_rw2_e4_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
328 1280 4064 0 4064 329 1
 length count
1 8
2 80
3 896
4 272
5 24
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
   <li> The number of clauses in the "minimum" translations of the Sbox and
   multiplications:
   \verbatim
maxima> ncl_list_fcs(ev_hm(ss_sbox_cnfs,4));
[[3,8],[4,12],[5,2]]
maxima> ncl_list_fcs(ev_hm(ss_field_cnfs,[4,2]));
[[2,5],[3,4]]
maxima> ncl_list_fcs(ev_hm(ss_field_cnfs,[4,3]));
[[3,12],[4,4]]
   \endverbatim
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 8 = key schedule constant * 1; </li>
     <li> 2 : 80 = 16 multiplications by 02 * 5; </li>
     <li> 3 : 896 = 12 S-boxes * 8 + 16 multiplications by 02 * 4 +
     16 multiplications by 03 * 12 + 136 additions (arity 2) * 4; </li>
     <li> 4 : 272 = 12 S-boxes * 12 + 16 multiplications by 03 * 4 +
     8 additions (arity 3) * 8; </li>
     <li> 5 : 24 = 12 S-boxes * 2. </li>
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
shell> col=2; row=2; e=4; r=2;
  for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    minisat-2.2.0 r${r}_k${k}.cnf > minisat_r${r}_k${k}.result 2>&1;
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
  r   n    c     t sat    cfs      dec rts       r1 mem ptime stime      cfl r
1 2 328 1444 0.136   1 9554.8 10209.45  39 640685.6  19     0     0 114874.9 2
     k
1 10.5
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> col=2; row=2; e=4; r=2;
  for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    OKsolver_2002-O3-DNDEBUG r${r}_k${k}.cnf > oksolver_r${r}_k${k}.result 2>&1;
done;
shell> echo "n  c  l  t  sat  nds  r1  r2  pls  ats h file n2cr  dmcl dn  dc  dl snds qnds mnds  tel  oats  n2cs  m2cs r k" > oksolver_results;
  for k in $(seq 1 20); do
    cat oksolver_r${r}_k${k}.result | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractOKsolver.awk | awk " { print \$0 \"  $r  $k\" }";
done >> oksolver_results;
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("oksolver_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r   n    c    l     t sat    nds r1      r2 pls  ats     h file n2cr dmcl dn
1 2 328 1516 4744 0.555   1 3646.8 40 6366.65   0 0.15 15.45   NA  160    0 40
   dc  dl snds qnds mnds tel oats n2cs m2cs r    k
1 136 456    0    0 0.15   0    0    0    0 2 10.5
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
shell> col=2; row=2; e=4; r=2;
  for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    minisat-2.2.0 r${r}_k${k}.cnf > minisat_r${r}_k${k}.result 2>&1;
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
  r   n     c     t sat  cfs     dec   rts     r1 mem ptime stime      cfl r
1 2 328 11136 0.276   1 9766 10551.6 40.05 811010  20 5e-04 0.057 122955.9 2
     k
1 10.5
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> col=2; row=2; e=4; r=2; 
  for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    OKsolver_2002-O3-DNDEBUG r${r}_k${k}.cnf > oksolver_r${r}_k${k}.result 2>&1;
done;
done;
shell> echo "n  c  l  t  sat  nds  r1  r2  pls  ats h file n2cr  dmcl dn  dc  dl snds qnds mnds  tel  oats  n2cs  m2cs r k" > oksolver_results;
  for k in $(seq 1 20); do
    cat oksolver_r${r}_k${k}.result | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractOKsolver.awk | awk " { print \$0 \"  $r  $k\" }";
done >> oksolver_results;
     \endverbatim
     is still running after an hour, having solved no instances.
     </li>
    </ul>
   </li>
  </ul>

*/
