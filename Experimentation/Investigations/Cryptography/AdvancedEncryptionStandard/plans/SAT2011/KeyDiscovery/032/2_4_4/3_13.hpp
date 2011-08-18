// Matthew Gwynne, 13.3.2011 (Swansea)
/* Copyright 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/KeyDiscovery/032/2_4_4/3_13.hpp
  \brief Investigations into small-scale AES key discovery for 3+1/3 round AES with a 2x4 plaintext matrix and 4-bit field elements


  \todo Problem specification
  <ul>
   <li> We investigate the 3 + 1/3 round small-scale AES with 2 row,
   4 column, using the 4-bit field size. </li>
   <li> We denote this AES instance by aes(3,2,4,4). </li>
   <li> aes(3,2,4,4) takes a 32-bit plaintext and 32-bit key and
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
   <li> Over 20 plaintext-ciphertext pairs, solvers solve the instances with
   (time;conflicts):
    <ul>
     <li> minimum box translation: minisat-2.2.0 (453s; 11.9 million); </li>
     <li> 1-base box translation: minisat-2.2.0 (463s; 11.2 million); </li>
     <li> canonical box translation: minisat-2.2.0 (1666s; 11.3 million); </li>
    </ul>
   </li>
  </ul>


  \todo Using the canonical box translation
  <ul>
   <li> Translation of aes(3,2,4,4):
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
   <li> Generating small-scale AES for 1 + 1/3 round:
   \verbatim
num_rounds : 3$
num_rows : 2$
num_columns : 4$
exp : 4$
final_round_b : false$
box_tran : aes_ts_box$
seed : 1$
mc_tran : aes_mc_bidirectional$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r3_c4_rw2_e4_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
2916 19994 57660 0 57660 2917 1
 length count
1 12
2 16128
3 1616
4 96
9 2016
16 126
   \endverbatim
   </li>
 <li> In this translation, we have:
    <ul>
     <li> 3 full rounds (Key Addition, SubBytes, and MixColumns operation).
     </li>
     <li> 30 Sboxes:
      <ul>
       <li> 24 from SubBytes = 8 byte * 3 rounds; </li>
       <li> 6 from key schedule = 2 row * 1 word * 3 rounds. </li>
      </ul>
     </li>
     <li> 48 multiplications by 02: 2 rows * 1 multiplication * 4 columns *
     3 rounds * 2 directions (forward + inverse). </li>
     <li> 48 multiplications by 03: 2 rows * 1 multiplication * 4 columns *
     3 rounds * 2 directions (forward + inverse). </li>
     <li> 416 additions:
      <ul>
       <li> 404 additions of arity 2:
        <ul>
         <li> 96 from key additions = 32 bits * 3 rounds; </li>
         <li> 32 from final key addition = 32 bits; </li>
         <li> 84 from the key schedule = (32 bits - 4 bits) * 3 rounds. </li>
         <li> 96 from forward MixColumns = 2 rows * 4 column * 4 bits *
         3 rounds; </li>
         <li> 96 from inverse MixColumns = 2 rows * 4 column * 4 bits * 3
         rounds. </li>
        </ul>
       </li>
       <li> 12 additions of arity 3:
        <ul>
         <li> 12 from the key schedule = 4 bits * 3 rounds. </li>
        </ul>
       </li>
      </ul>
     </li>
     <li> 12 bits for the constant in the key schedule = 4 bits * 3 rounds.
     </li>
    </ul>
   </li>
   <li> The number of clauses of each length in the translation, computed by:
   \verbatim
maxima> ncl_list_full_dualts(8,16);
[[2,128],[9,16],[16,1]]
   \endverbatim
   </li>
   <li> This instance has 126 boxes = 30 S-boxes + 96 multiplications.
   </li>
   <li> This instance has the following number of clauses of length:
    <ul>
     <li> 1 : 12 = key schedule constant * 1; </li>
     <li> 2 : 16128 = 42 boxes * 128; </li>
     <li> 3 : 1616 = 404 additions (arity 2) * 4; </li>
     <li> 4 : 96 = 12 additions (arity 3) * 8; </li>
     <li> 9 : 2016 = 126 boxes * 16; </li>
     <li> 16 : 126 = 126 boxes * 1. </li>
    </ul>
   </li>
   <li> Then we can generate a random assignment with the plaintext and
   ciphertext, leaving the key unknown:
   \verbatim
maxima> output_ss_random_pc_pair(seed,num_rounds,num_columns,num_rows,exp,final_round_b);
   \endverbatim
   and the merging the assignment with the translation:
   \verbatim
shell> AppendDimacs-O3-DNDEBUG ssaes_r1_c4_rw2_e4_f0.cnf ssaes_pkpair_r1_c4_rw2_e4_f0_s1.cnf > r1_keyfind.cnf
   \endverbatim
   </li>
   <li> minisat-2.2.0 solves it in 65s:
   \verbatim
shell> minisat-2.2.0 experiment_r3_k1.cnf
restarts              : 36632
conflicts             : 26578774       (406788 /sec)
decisions             : 28721930       (0.00 % random) (439590 /sec)
propagations          : 12638199080    (193427808 /sec)
conflict literals     : 690572739      (62.54 % deleted)
Memory used           : 63.00 MB
CPU time              : 65.3381 s
   \endverbatim
   </li>
   <li> cryptominisat solves it in 61.4s:
   \verbatim
shell> cryptominisat experiment_r3_k1.cnf
<snip>
c restarts                 : 105
c conflicts                : 5370243     (87472.26  / sec)
c decisions                : 5741789     (0.26      % random)
c CPU time                 : 61.39       s
   \endverbatim
   </li>
   <li> glucose solves it in 65s:
   \verbatim
shell> glucose experiment_r3_k1.cnf
<snip>
c restarts              : 50
c nb ReduceDB           : 164
c conflicts             : 14316868       (219560 /sec)
c decisions             : 15063464       (1.57 % random) (231010 /sec)
c propagations          : 4612945014     (70743001 /sec)
c CPU time              : 65.2071 s
   \endverbatim
   </li>
   <li> precosat236 solves it in 1246s:
   \verbatim
shell> precosat236 experiment_r3_k1.cnf
<snip>
c 5597931 conflicts, 6207027 decisions, 1 random
c 0 iterations, 58 restarts, 8769 skipped
c 47 simplifications, 2 reductions
c prps: 1627135948 propagations, 1.31 megaprops
c 1246.0 seconds, 22 MB max, 635 MB recycled
   \endverbatim
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
shell> row=2; col=4; e=4; r=3; for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    (time minisat-2.2.0 r${r}_k${k}.cnf) > minisat_r${r}_k${k}.result 2>&1;
done;
shell> echo "n  c  t  sat  cfs dec rts r1 mem ptime stime cfl r k" > minisat_results;
  for k in $(seq 1 20); do
    cat minisat_r${r}_k${k}.result | awk -f extract_bash_time_minisat.awk | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractMinisat.awk | awk " { print \$0 \"  $r  $k\" }";
done >> minisat_results;
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("minisat_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r    n     c        t sat      cfs      dec      rts         r1  mem ptime
1 3 2916 19934 1665.785   1 11305692 12319819 16798.75 5188934612 41.4  0.01
  stime       cfl r    k
1  0.02 311244850 3 10.5
     \endverbatim
     where "extract_bash_time_minisat.awk" is:
     \verbatim
/^CPU time/ { }
/^real/  { split($2,a,"m"); split(a[2],b,"s"); print "CPU time              : " (a[1] * 60) + b[1] " s"; }
$0 !~ /^(CPU time|real)/ { print }
     \endverbatim
     </li>
     <li> Running OKsolver_2002:
     \verbatim
shell> row=2; col=4; e=4; r=3; for k in $(seq 1 20); do
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
num_rounds : 3$
num_rows : 2$
num_columns : 4$
exp : 4$
final_round_b : false$
box_tran : aes_small_box$
mc_tran : aes_mc_bidirectional$
oklib_monitor : true$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r3_c4_rw2_e4_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
900 3584 11256 0 11256 901 1
 length count
1 12
2 240
3 2624
4 648
5 60
   \endverbatim
   </li>
   <li> In this translation, we have:
    <ul>
     <li> 3 full round (Key Addition, SubBytes, and MixColumns operation).
     </li>
     <li> 30 Sboxes:
      <ul>
       <li> 24 from SubBytes = 8 byte * 3 rounds; </li>
       <li> 6 from key schedule = 2 row * 1 word * 3 rounds. </li>
      </ul>
     </li>
     <li> 48 multiplications by 02: 2 rows * 1 multiplication * 4 columns *
     3 rounds * 2 directions (forward + inverse). </li>
     <li> 48 multiplications by 03: 2 rows * 1 multiplication * 4 columns *
     3 rounds * 2 directions (forward + inverse). </li>
     <li> 416 additions:
      <ul>
       <li> 404 additions of arity 2:
        <ul>
         <li> 96 from key additions = 32 bits * 3 rounds; </li>
         <li> 32 from final key addition = 32 bits; </li>
         <li> 84 from the key schedule = (32 bits - 4 bits) * 3 round. </li>
         <li> 96 from forward MixColumns = 2 rows * 4 column * 4 bits *
         3 rounds; </li>
         <li> 96 from inverse MixColumns = 2 rows * 4 column * 4 bits * 2
         rounds. </li>
        </ul>
       </li>
       <li> 12 additions of arity 3:
        <ul>
         <li> 12 from the key schedule = 4 bits * 3 rounds. </li>
        </ul>
       </li>
      </ul>
     </li>
     <li> 12 bits for the constant in the key schedule = 4 bits * 3 rounds.
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
     <li> 1 : 12 = key schedule constant * 1; </li>
     <li> 2 : 240 = 48 multiplications by 02 * 5; </li>
     <li> 3 : 2624 = 404 additions (arity 2) * 4 + 30 S-boxes * 8 +
     48 multiplications by 02 * 4 + 48 multiplications by 03 * 12; </li>
     <li> 4 : 648 = 12 additions (arity 3) * 8 + 30 S-boxes * 12 +
     48 multiplications by 03 * 4; </li>
     <li> 5 : 60 = 30 boxes * 2; </li>
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
shell> row=2; col=4; e=4; r=3; for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    (time minisat-2.2.0 r${r}_k${k}.cnf) > minisat_r${r}_k${k}.result 2>&1;
done;
shell> echo "n  c  t  sat  cfs dec rts r1 mem ptime stime cfl r k" > minisat_results;
  for k in $(seq 1 20); do
    cat minisat_r${r}_k${k}.result | awk -f extract_bash_time_minisat.awk | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractMinisat.awk | awk " { print \$0 \"  $r  $k\" }";
done >> minisat_results;
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("minisat_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r   n    c        t sat      cfs      dec      rts         r1  mem ptime
1 3 900 3524 452.6807   1 11948584 13101473 17862.05 1399318623 12.7     0
  stime       cfl r    k
1 5e-04 242906859 3 10.5
     \endverbatim
     where "extract_bash_time_minisat.awk" is:
     \verbatim
/^CPU time/ { }
/^real/  { split($2,a,"m"); split(a[2],b,"s"); print "CPU time              : " (a[1] * 60) + b[1] " s"; }
$0 !~ /^(CPU time|real)/ { print }
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

shell> cat ssaes_r3_c4_rw2_e4_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
900 4166 13116 0 13116 901 1
 length count
1 12
2 288
3 2936
4 930
   \endverbatim
   </li>
   <li> In this translation, we have:
    <ul>
     <li> 3 full round (Key Addition, SubBytes, and MixColumns operation).
     </li>
     <li> 30 Sboxes:
      <ul>
       <li> 24 from SubBytes = 8 byte * 3 rounds; </li>
       <li> 6 from key schedule = 2 row * 1 word * 3 rounds. </li>
      </ul>
     </li>
     <li> 48 multiplications by 02: 2 rows * 1 multiplication * 4 columns *
     3 rounds * 2 directions (forward + inverse). </li>
     <li> 48 multiplications by 03: 2 rows * 1 multiplication * 4 columns *
     3 rounds * 2 directions (forward + inverse). </li>
     <li> 416 additions:
      <ul>
       <li> 404 additions of arity 2:
        <ul>
         <li> 96 from key additions = 32 bits * 3 rounds; </li>
         <li> 32 from final key addition = 32 bits; </li>
         <li> 84 from the key schedule = (32 bits - 4 bits) * 3 round. </li>
         <li> 96 from forward MixColumns = 2 rows * 4 column * 4 bits *
         3 rounds; </li>
         <li> 96 from inverse MixColumns = 2 rows * 4 column * 4 bits * 2
         rounds. </li>
        </ul>
       </li>
       <li> 12 additions of arity 3:
        <ul>
         <li> 12 from the key schedule = 4 bits * 3 rounds. </li>
        </ul>
       </li>
      </ul>
     </li>
     <li> 12 bits for the constant in the key schedule = 4 bits * 3 rounds.
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
     <li> 1 : 12 = key schedule constant * 1; </li>
     <li> 2 : 288 = 48 multiplications by 02 * 6; </li>
     <li> 3 : 2936 = 404 additions (arity 2) * 4 + 30 S-boxes * 12 +
     48 multiplications by 02 * 6 + 48 multiplications by 03 * 16; </li>
     <li> 4 : 930 = 12 additions (arity 3) * 8 + 30 S-boxes * 15 +
     48 multiplications by 03 * 8; </li>
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
shell> row=2; col=4; e=4; r=3; for k in $(seq 1 20); do
    echo "Key ${k} Round ${r}";
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c${col}_rw${row}_e${e}_f0.cnf ssaes_pcpair_r${r}_c${col}_rw${row}_e${e}_f0_s${k}.cnf > r${r}_k${k}.cnf;
    (time minisat-2.2.0 r${r}_k${k}.cnf) > minisat_r${r}_k${k}.result 2>&1;
done;
shell> echo "n  c  t  sat  cfs dec rts r1 mem ptime stime cfl r k" > minisat_results;
  for k in $(seq 1 20); do
    cat minisat_r${r}_k${k}.result | awk -f extract_bash_time_minisat.awk | awk -f $OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractMinisat.awk | awk " { print \$0 \"  $r  $k\" }";
done >> minisat_results;
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("minisat_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r   n    c        t sat      cfs      dec     rts         r1 mem ptime stime
1 3 900 4106 463.3990   1 11237887 12236955 16937.9 1278077395  14     0 0.008
        cfl r    k
1 230734677 3 10.5
     \endverbatim
     where "extract_bash_time_minisat.awk" is:
     \verbatim
/^CPU time/ { }
/^real/  { split($2,a,"m"); split(a[2],b,"s"); print "CPU time              : " (a[1] * 60) + b[1] " s"; }
$0 !~ /^(CPU time|real)/ { print }
     \endverbatim
    </ul>
   </li>
  </ul>

*/
