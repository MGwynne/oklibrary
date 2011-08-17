// Matthew Gwynne, 18.2.2011 (Swansea)
/* Copyright 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/KeyDiscovery/004/1_1_4/20_13.hpp
  \brief Investigations into small-scale AES key discovery with 1 row, 1 column and 4-bit field elements for 20+1/3 round AES


  \todo Overview
  <ul>
   <li> We investigate the 20 + 1/3 round small-scale AES with
   1 row, 1 column, using the 4-bit field size. </li>
   <li> We denote this AES instance by aes(20,1,1,4). </li>
   <li> aes(20,1,1,4) takes a 4-bit plaintext and 4-bit key and
   outputs a 4-bit ciphertext. </li>
   <li> For the full specification of this AES instance, see
   "Problem specification" in
   Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/KeyDiscovery/004/1_1_4/general.hpp.
   </li>
   <li> For a full list of the possible translations, see
   "Investigating dimensions" in
   Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/Experimentation.hpp.
   </li>
   <li> In this file we consider:
    <ul>
     <li> "Using the 1-base box translation". </li>
     <li> "Using the canonical box translation". </li>
     <li> "Using the minimum box translation". </li>
     <li> "Using the canonical CNF box translation". </li>
    </ul>
   </li>
  </ul>


  \todo Remove linear diffusion from translation
  <ul>
   <li> Currently the AES linear diffusion operation creates equality
   clauses in the translation of this AES instance, as the translation
   does not check if the MixColumns matrix is the identity matrix. </li>
   <li> These equivalences clauses can only get in the way for the solvers
   and skew results, and therefore the translation should be updated to
   check for the identity matrix and rename variables instead. </li>
   <li> See also "Remove hard-coding of multiplication by 01 in small-scale
   MixColumn" in
   ComputerAlgebra/Cryptology/Lisp/Cryptanalysis/Rijndael/plans/Translations.hpp.
   </li>
  </ul>


  \todo Comparison of box translations
  <ul>
   <li> All translations are solved by all solvers in less than 0.5s and so
   comparing these translations on solver time is unreasonable. </li>
   <li> The canonical translation does best in terms of number of
   decisions, followed by the r_1-base, followed by the small translation.
   </li>
   <li> Comparing the translations on the number of conflicts/nodes:
   <ul>
    <li> OKsolver:
     <ul>
      <li> canonical box translation: 1; </li>
      <li> 1-base box translation: 6.61; </li>
      <li> small box translation: 16.07; </li>
      <li> canonical CNF translation: 1521.34. </li>
     </ul>
    </li>
    <li> minisat-2.2.0:
     <ul>
      <li> canonical box translation: 27.84; </li>
      <li> 1-base box translation: 96.53; </li>
      <li> small box translation: 472.35; </li>
      <li> canonical CNF translation: 3856.75. </li>
     </ul>
    </li>
   </ul>
   </li>
   <li> Note that we consider the canonical CNF translation, as
   this is an example of the "hardest" representation without
   new variables. See "Hardness of boolean function representations"
   in
   Experimentation/Investigations/BooleanFunctions/plans/general.hpp. </li>
  </ul>


  \todo Using the 1-base box translation
  <ul>
   <li> Translation of aes(20,1,1,4):
    <ul>
     <li> We treat S-boxes and additions as boxes. </li>
     <li> The S-box is considered as an 8x1 boolean function,
     translated using 1-bases; see ss_sbox_rbase_cnfs in
     ComputerAlgebra/Cryptology/Lisp/Cryptanalysis/Rijndael/data/SmallScaleSboxCNF.mac.
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
   <li> Generating simplest small-scale AES for 20 rounds:
   \verbatim
shell> mkdir aes_1_1_4/1base
shell> cd aes_1_1_4/1base
shell> oklib --maxima
oklib_load_all()$
num_rounds : 20$
num_rows : 1$
num_columns : 1$
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
   <li> In this translation, we have:
    <ul>
     <li> 20 full rounds (Key Addition, SubBytes, and MixColumns operation).
     </li>
     <li> 40 Sboxes:
      <ul>
       <li> 20 from SubBytes = 1 byte * 20 rounds; </li>
       <li> 20 from key schedule = 1 row * 1 byte * 20 rounds. </li>
      </ul>
     </li>
     <li> 324 additions:
      <ul>
       <li> 160 additions of arity 1:
        <ul>
         <li> 80 from forward MixColumns = 4 bits * 20 rounds; </li>
         <li> 80 from inverse MixColumns = 4 bits * 20 rounds. </li>
        </ul>
       </li>
       <li> 164 additions of arity 2:
        <ul>
         <li> 80 from key additions = 4 bits * 20 rounds; </li>
         <li> 4 from final key addition = 4 bits; </li>
         <li> 80 from the key schedule = 4 bits * 20 rounds. </li>
        </ul>
       </li>
      </ul>
     </li>
     <li> 80 bits for the constant in the key schedule = 4 bits * 20 rounds.
     </li>
    </ul>
   </li>
   <li> The additions are translated by their prime implicates, containing
   2^a clauses where a is the arity of the addition constraint. </li>
   <li> The S-boxes are translated by a 1-base representation. See
   Cryptography/AdvancedEncryptionStandard/plans/SAT2011/Representations/Sbox_4.hpp.
   </li>
   <li> The number of clauses for the 1-base representation of the S-box:
   \verbatim
maxima> ncl_list_fcs(ev_hm(ss_sbox_rbase_cnfs,4));
[[3,12],[4,15]]
   \endverbatim
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 80 = key schedule constant * 1; </li>
     <li> 2 : 320 = 160 "additions" (arity 1) * 2; </li>
     <li> 3 : 1136 = 40 S-boxes * 12 + 164 additions (arity 2) * 4; </li>
     <li> 4 : 600 = 20 S-boxes * 15; </li>
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
shell> col=1; row=1; e=4; r=20;
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
   r    n    c      t sat   cfs    dec rts       r1 mem ptime stime   cfl  r
1 20 1132 6616 0.0065   1 43.25 110.95 1.1 13489.55  19     0     0 675.2 20
     k
1 10.5
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> col=1; row=1; e=4; r=20;
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
   r    n    c     l t sat nds r1     r2 pls ats h file n2cr dmcl dn  dc  dl
1 20 1132 6864 19336 0   1   1 88 183.55   0 0.6 0   NA 5616    0 88 264 792
  snds qnds mnds tel oats n2cs m2cs  r    k
1    0    0    0   0    0    0    0 20 10.5
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>


  \todo Using the minimum box translation
  <ul>
   <li> Translation of aes(20,1,1,4):
    <ul>
     <li> We treat S-boxes and additions as boxes. </li>
     <li> The S-box is considered as an 8x1 boolean function,
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
   <li> Generating simplest small-scale AES for 20 rounds:
   \verbatim
shell> mkdir aes_1_1_4/min
shell> cd aes_1_1_4/min
shell> oklib --maxima
oklib_load_all()$
num_rounds : 20$
num_rows : 1$
num_columns : 1$
exp : 4$
final_round_b : false$
box_tran : aes_small_box$
mc_tran : aes_mc_bidirectional$
oklib_monitor : true$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r20_c1_rw1_e4_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
492 1936 5968 0 5968 493 1
 length count
1 80
2 320
3 976
4 480
5 80
   \endverbatim
   </li>
   <li> In this translation, we have:
    <ul>
     <li> 20 full rounds (Key Addition, SubBytes, and MixColumns operation).
     </li>
     <li> 40 Sboxes:
      <ul>
       <li> 20 from SubBytes = 1 byte * 20 rounds; </li>
       <li> 20 from key schedule = 1 row * 1 byte * 20 rounds. </li>
      </ul>
     </li>
     <li> 324 additions:
      <ul>
       <li> 160 additions of arity 1:
        <ul>
         <li> 80 from forward MixColumns = 4 bits * 20 rounds; </li>
         <li> 80 from inverse MixColumns = 4 bits * 20 rounds. </li>
        </ul>
       </li>
       <li> 164 additions of arity 2:
        <ul>
         <li> 80 from key additions = 4 bits * 20 rounds; </li>
         <li> 4 from final key addition = 4 bits; </li>
         <li> 80 from the key schedule = 4 bits * 20 rounds. </li>
        </ul>
       </li>
      </ul>
     </li>
     <li> 80 bits for the constant in the key schedule = 4 bits * 20 rounds.
     </li>
    </ul>
   </li>
   <li> The additions are translated by their prime implicates, containing
   2^a clauses where a is the arity of the addition constraint. </li>
   <li> The S-boxes are translated by a minimum representation. See
   Cryptography/AdvancedEncryptionStandard/plans/SAT2011/Representations/Sbox_4.hpp.
   </li>
   <li> The number of clauses for the minimum representation of the S-box:
   \verbatim
maxima> ncl_list_fcs(ev_hm(ss_sbox_cnfs,4));
[[3,8],[4,12],[5,2]]
   \endverbatim
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 80 = key schedule constant * 1; </li>
     <li> 2 : 320 = 160 "additions" (arity 1) * 2; </li>
     <li> 3 : 976 = 40 S-boxes * 8 + 164 additions (arity 2) * 4; </li>
     <li> 4 : 480 = 40 S-boxes * 12; </li>
     <li> 5 : 80 = 40 S-boxes * 2. </li>
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
shell> col=1; row=1; e=4; r=20;
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
   r   n    c     t sat   cfs   dec rts       r1 mem ptime stime    cfl  r    k
1 20 492 1696 5e-04   1 427.9 734.4 3.9 14451.85  19     0     0 2748.6 20 10.5
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> col=1; row=1; e=4; r=20;
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
   r   n    c    l t sat   nds r1     r2 pls ats   h file n2cr dmcl dn  dc  dl
1 20 492 1944 5976 0   1 15.85 88 221.85   0   0 4.7   NA  496    0 88 264 792
  snds qnds mnds tel oats n2cs m2cs  r    k
1    0    0    0   0    0    0    0 20 10.5
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>


  \todo Using the canonical box translation
  <ul>
   <li> Translation of aes(20,1,1,4):
    <ul>
     <li> We treat S-boxes and additions as boxes. </li>
     <li> The S-box is considered as an 8x1 boolean function,
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
   <li> Generating simplest small-scale AES for 20 rounds:
   \verbatim
shell> mkdir aes_1_1_4/canon
shell> cd aes_1_1_4/canon
shell> oklib --maxima
oklib_load_all()$
num_rounds : 20$
num_rows : 1$
num_columns : 1$
exp : 4$
final_round_b : false$
box_tran : aes_ts_box$
mc_tran : aes_mc_bidirectional$
oklib_monitor : true$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r20_c1_rw1_e4_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
1132 6856 19328 0 19328 1133 1
 length count
1 80
2 5440
3 656
9 640
16 40
   \endverbatim
   </li>
   <li> In this translation, we have:
    <ul>
     <li> 20 full rounds (Key Addition, SubBytes, and MixColumns operation).
     </li>
     <li> 40 Sboxes:
      <ul>
       <li> 20 from SubBytes = 1 byte * 20 rounds; </li>
       <li> 20 from key schedule = 1 row * 1 byte * 20 rounds. </li>
      </ul>
     </li>
     <li> 324 additions:
      <ul>
       <li> 160 additions of arity 1:
        <ul>
         <li> 80 from forward MixColumns = 4 bits * 20 rounds; </li>
         <li> 80 from inverse MixColumns = 4 bits * 20 rounds. </li>
        </ul>
       </li>
       <li> 164 additions of arity 2:
        <ul>
         <li> 80 from key additions = 4 bits * 20 rounds; </li>
         <li> 4 from final key addition = 4 bits; </li>
         <li> 80 from the key schedule = 4 bits * 20 rounds. </li>
        </ul>
       </li>
      </ul>
     </li>
     <li> 80 bits for the constant in the key schedule = 4 bits * 20 rounds.
     </li>
    </ul>
   </li>
   <li> The additions are translated by their prime implicates, containing
   2^a clauses where a is the arity of the addition constraint. </li>
   <li> The S-boxes are translated by the canonical translation. </li>
   <li> The number of clauses for the canonical representation of the S-box:
   \verbatim
maxima> ncl_list_full_dualts(8,16);
[[2,128],[9,16],[16,1]]
   \endverbatim
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 80 = key schedule constant * 1; </li>
     <li> 2 : 5440 = 40 S-boxes * 128 + 160 "additions" (arity 1) * 2; </li>
     <li> 3 : 656 = 164 additions (arity 2) * 4; </li>
     <li> 9 : 640 = 40 S-boxes * 16; </li>
     <li> 16 : 40 = 40 S-boxes * 1. </li>
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
shell> col=1; row=1; e=4; r=20;
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
   r   n    c     t sat   cfs   dec rts       r1 mem ptime stime    cfl  r    k
1 20 492 1696 5e-04   1 427.9 734.4 3.9 14451.85  19     0     0 2748.6 20 10.5
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> col=1; row=1; e=4; r=20;
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
   r   n    c    l t sat   nds r1     r2 pls ats   h file n2cr dmcl dn  dc  dl
1 20 492 1944 5976 0   1 15.85 88 221.85   0   0 4.7   NA  496    0 88 264 792
  snds qnds mnds tel oats n2cs m2cs  r    k
1    0    0    0   0    0    0    0 20 10.5
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>


  \todo Using the canonical CNF box translation
  <ul>
   <li> Translation of aes(20,1,1,4):
    <ul>
     <li> We treat S-boxes and additions as boxes. </li>
     <li> S-boxes are translated using the canonical CNF translation;
     see ss_sbox_fullcnf_fcs in
     ComputerAlgebra/Cryptology/Lisp/Cryptanalysis/Rijndael/SboxAnalysis.mac.
     </li>
     <li> Additions are translated using their prime implicates. </li>
     <li> The MixColumns operation is translated by translating both
     the MixColumns operation and its inverse. </li>
    </ul>
   </li>
   <li> Translating the AES cipher treating S-boxes and field multiplications
   as whole boxes and translating these boxes using the canonical CNF.
   </li>
   <li> Generating simplest small-scale AES for 20 rounds:
   \verbatim
shell> mkdir aes_1_1_4/full
shell> cd aes_1_1_4/full
shell> oklib --maxima
oklib_load_all()$
num_rounds : 20$
num_rows : 1$
num_columns : 1$
exp : 4$
final_round_b : false$
box_tran : aes_full_box$
mc_tran : aes_mc_bidirectional$
oklib_monitor : true$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r20_c1_rw1_e4_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
492 10656 79488 0 79488 493 1
 length count
1 80
2 320
3 656
8 9600
   \endverbatim
   </li>
   <li> In this translation, we have:
    <ul>
     <li> 20 full rounds (Key Addition, SubBytes, and MixColumns operation).
     </li>
     <li> 40 Sboxes:
      <ul>
       <li> 20 from SubBytes = 1 byte * 20 rounds; </li>
       <li> 20 from key schedule = 1 row * 1 byte * 20 rounds. </li>
      </ul>
     </li>
     <li> 324 additions:
      <ul>
       <li> 160 additions of arity 1:
        <ul>
         <li> 80 from forward MixColumns = 4 bits * 20 rounds; </li>
         <li> 80 from inverse MixColumns = 4 bits * 20 rounds. </li>
        </ul>
       </li>
       <li> 164 additions of arity 2:
        <ul>
         <li> 80 from key additions = 4 bits * 20 rounds; </li>
         <li> 4 from final key addition = 4 bits; </li>
         <li> 80 from the key schedule = 4 bits * 20 rounds. </li>
        </ul>
       </li>
      </ul>
     </li>
     <li> 80 bits for the constant in the key schedule = 4 bits * 20 rounds.
     </li>
    </ul>
   </li>
   <li> The additions are translated by their prime implicates, containing
   2^a clauses where a is the arity of the addition constraint. </li>
   <li> The S-boxes are translated by the canonical CNF:
   \verbatim
> ncl_list_fcs(ss_sbox_fullcnf_fcs(2,4,ss_polynomial_2_4));
[[8,240]]
   \endverbatim
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 80 = key schedule constant * 1; </li>
     <li> 2 : 320 = 160 "additions" (arity 1) * 2; </li>
     <li> 3 : 656 = 164 additions (arity 2) * 4; </li>
     <li> 8 : 9600 = 40 S-boxes * 240. </li>
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
shell> col=1; row=1; e=4; r=20;
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
   r   n     c     t sat   cfs    dec  rts      r1 mem ptime  stime    cfl  r
1 20 492 10416 0.053   1 154.4 189.15 1.95 6587.15  19     0 0.0465 854.15 20
     k
1 10.5
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> col=1; row=1; e=4; r=20;
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
   r   n     c     l    t sat    nds r1    r2 pls ats  h file n2cr dmcl dn  dc
1 20 492 10664 79496 0.94   1 1085.3 88 702.6   0   0 82   NA  496    0 88 264
   dl snds qnds mnds tel oats n2cs m2cs  r    k
1 792    0  9.5    0   0    0    0    0 20 10.5
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>

*/
