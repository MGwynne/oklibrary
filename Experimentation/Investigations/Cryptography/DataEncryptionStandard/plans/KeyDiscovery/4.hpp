// Matthew Gwynne, 25.5.2011 (Swansea)
/* Copyright 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Investigations/Cryptography/DataEncryptionStandard/plans/KeyDiscovery/4.hpp
  \brief On investigations into the four-round Data Encryption Standard key discovery


  \todo Overview
  <ul>
   <li> We consider the four round DES given by the encryption function
   des_encryption_gen in
   ComputerAlgebra/Cryptology/Lisp/CryptoSystems/DataEncryptionStandard/Cipher.mac.
   </li>
   <li> The translation of one round DES to SAT is given at the Maxima level by
   des_fcl_gen in
   ComputerAlgebra/Cryptology/Lisp/Cryptanalysis/DataEncryptionStandard/GeneralisedConstraintTranslation.mac.
   </li>
   <li> The DES consists of certain rewiring of the bits, additions (XOR) and
   the application of 8 S-boxes (substitution boxes) for each round. </li>
   <li> We consider the DES S-boxes as 6-bit to 4-bit boolean functions,
   given by des_sbox_bf in
   ComputerAlgebra/Cryptology/Lisp/CryptoSystems/DataEncryptionStandard/Sboxes.mac.
   </li>
   <li> We should also consider the DES S-boxes as 4 6-bit to 1-bit functions.
   See "Basic translation" in
   Investigations/Cryptography/DataEncryptionStandard/plans/general.hpp. </li>
   <li> We translate the DES by treating the additions and S-boxes as the
   boolean functions, which we consider our units of translation. </li>
   <li> The additions are translated by the set of their prime implicates.
   </li>
   <li> The S-boxes are translated using each of the following CNF
   representations:
    <ul>
     <li> canonical(+) representation, see dualts_fcl and dualtsplus_fcl in
     ComputerAlgebra/Satisfiability/Lisp/FiniteFunctions/TseitinTranslation.mac;
     </li>
     <li> 1-base translations, see
     Investigations/Cryptography/DataEncryptionStandard/plans/Sboxes/general.hpp;
     </li>
     <li> minimum translations, see
     Investigations/Cryptography/DataEncryptionStandard/plans/Sboxes/general.hpp;
     </li>
     <li> their prime implicates; </li>
     <li> their canonical CNF representations. </li>
    </ul>
   All such translations apply to both the 6-bit to 4-bit S-box functions and
   the 4 decomposed 6-bit to 1-bit functions.
   </li>
   <li> For initial experiments we use the Argosat-desgen plaintext-ciphertext
   pairs. See "Transferring the Argosat-desgen example" in
   Investigations/Cryptography/DataEncryptionStandard/plans/KeyDiscovery/KnownKeyBits.hpp.
   </li>
   <li> Using the:
    <ul>
     <li> "minimum" translation; fastest solver solves in 0.5s, all in
     less than 1600s. See "Using the 1-base translation for the S-boxes
     (6-to-4)". </li>
     <li> 1-base translation; fastest solver solves in 7s, all in
     less than 761s. See "Using the 1-base translation for the S-boxes
     (6-to-4)". </li>
     <li> canonical translation; fastest solver solves in 31s, all in less
     than 330s. See "Using the canonical translation for the S-boxes
     (6-to-4)". </li>
     <li> canonical CNF translation; fastest solver solves in 32s.
     See "Using the canonical CNF translation for the S-boxes (6-to-4)". </li>
    </ul>
   </li>
   <li> Note that we use the canonical CNF translation for the S-boxes to
   compare other representations to the "hardest" representation. </li>
  </ul>


  \todo Using the canonical translation for the S-boxes (6-to-4)
  <ul>
   <li> Translating the DES Sboxes, as 6-to-4-bit boolean functions, using the
   canonical representation. That is, each Sbox is represented with the
   canonical representation given by dualts_fcl in
   ComputerAlgebra/Satisfiability/Lisp/FiniteFunctions/TseitinTranslation.mac.
   </li>
   <li> Considering a single plaintext-ciphertext pair:
    <ul>
     <li> Generating the instance:
     \verbatim
rounds : 4$
sbox_fcl_l : create_list(dualts_fcl([listify(setn(10)), des_sbox_fulldnf_cl(i)]), i, 1, 8)$
P_hex : "038E596D4841D03B"$
K_hex : "15FBC08D31B0D521"$
C_hex : des_encryption_hex_gen(rounds, "038E596D4841D03B","15FBC08D31B0D521")$
P : des_plain2fcl_gen(hexstr2binv(P_hex),rounds)$
C : des_cipher2fcl_gen(hexstr2binv(C_hex),rounds)$
F : des2fcl_gen(sbox_fcl_l,rounds)$
Fs : standardise_fcl([F[1],append(F[2],P[2],C[2])])$
output_fcl_v(
  sconcat("DES over ",rounds," rounds; translated using the canonical translation for the S-boxes (6-to-4)."),
  Fs[1],
  sconcat("des_6t4_canon_r",rounds,".cnf"),
  Fs[2])$
print("DONE!");
     \endverbatim
     </li>
     <li> Statistics:
     \verbatim
shell> cat des_6t4_canon_r4.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
2624 23968 69504 0 69504 2625 1
 length count
1 128
2 20480
3 1280
11 2048
64 32
     \endverbatim
     </li>
     <li> S-box statistics (canonical translation):
     \verbatim
ncl_list_fcl(dualts_fcl([listify(setn(10)), des_sbox_fulldnf_cl(1)]));
[[2,640],[11,64],[64,1]]
     \endverbatim
     </li>
     <li> We have the following number of clauses of the following sizes:
      <ul>
       <li> 128 unit-clauses (setting plaintext + ciphertext); </li>
       <li> 20480 binary clauses (8 * 4 = 32 S-boxes); </li>
       <li> 1280 ternary clauses (80 * 4 = 320 binary additions); </li>
       <li> 2048 clauses of length eleven (8 * 4 = 32 S-boxes); </li>
       <li> 32 clauses of length 64 (8 * 4 = 32 S-boxes). </li>
      </ul>
     </li>
     <li> Solvers (t:time,cfs:conflicts,nds:nodes): glucose
     (t:39.31s,cfs:178662), minisat-2.2.0 (t:131s,cfs:555383), cryptominisat
     (t:195s,cfs:676495), precosat236 (t:306s,cfs:1144952),
     OKsolver_2002 (t:327s,nds:5601). </li>
     </li>
    </ul>
   </li>
   <li> Considering random 20 plaintext-ciphertext pairs and randomising
   the clause-set 5 times:
    <ul>
     <li> Generating the instances:
     \verbatim
shell> mkdir -p des_4/canon
shell> cd des_4/canon
shell> oklib --maxima
oklib_load_all()$
rounds : 4$
sbox_fcl_l : create_list(dualts_fcl([listify(setn(10)), des_sbox_fulldnf_cl(i)]), i, 1, 8)$
for seed : 1 thru 20 do block(
  print(sconcat("Generating ", rounds, "-round DES with seed ", seed)),
  set_random(make_random_state(seed)),
  P_hex : lpad(int2hex(random(2**64)),"0",16),
  K_hex : lpad(int2hex(random(2**64)),"0",16),
  C_hex : des_encryption_hex_gen(rounds, P_hex,K_hex),
  P : des_plain2fcl_gen(hexstr2binv(P_hex),rounds),
  C : des_cipher2fcl_gen(hexstr2binv(C_hex),rounds),
  F : des2fcl_gen(sbox_fcl_l,rounds),
  Fs : standardise_fcl([F[1],append(F[2],P[2],C[2])]),
  output_fcl_v(
    sconcat(rounds, "-round DES instantiated with plaintext and ciphertext generated from seed ", seed, "; translated using the canonical translation for the S-boxes (6-to-4)."),
    Fs[1],
    sconcat("des_6t4_canon_r",rounds,"_s",seed,".cnf"),
    Fs[2]))$
print("DONE!");
     \endverbatim
     </li>
     <li> Running minisat-2.2.0 on these instances:
     \verbatim
shell> r=4;
shell> for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    echo "Round ${r}; Key Seed ${k}; Random Seed ${s}...";
    cat des_6t4_canon_r${r}_s${k}.cnf | RandomShuffleDimacs-O3-DNDEBUG $s > r${r}_k${k}_s${s}.cnf;
    (time minisat-2.2.0 r${r}_k${k}_s${s}.cnf) > minisat_r${r}_k${k}_s${s}.result 2>&1;
  done;
done;
shell> echo "n  c  t  sat  cfs dec rts r1 mem ptime stime cfl r k s" > minisat_results; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    OKP=~/Work/OKlibrary/OKplatform/; cat minisat_r${r}_k${k}_s${s}.result | awk -f extract_bash_time_minisat.awk | awk -f ${OKP}/OKsystem/OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractMinisat.awk | awk " { print \$0 \"  $r  $k $s\" }";
  done;
done >> minisat_results;
     \endverbatim
     where extract_bash_time_minisat.awk is (as minisat-2.2.0 reports the wrong time):
     \verbatim
/^CPU time/ { }
/^real/  { split($2,a,"m"); split(a[2],b,"s"); print "CPU time              : " (a[1] * 60) + b[1] " s"; }
$0 !~ /^(CPU time|real)/ { print }
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("minisat_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r    n        c        t sat     cfs     dec     rts        r1   mem  ptime
1 4 2624 23616.55 416.5165   1 1454177 2607240 2732.91 488831369 77.85 0.0133
  stime       cfl r    k s
1  0.01 200745903 4 10.5 3
     \endverbatim
     </li>
     <li> Running OKsolver_2002 on these instances:
     \verbatim
shell> r=4;
shell> for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    echo "Round ${r}; Key Seed ${k}; Random Seed ${s}...";
    cat des_6t4_canon_r${r}_s${k}.cnf | RandomShuffleDimacs-O3-DNDEBUG $s > r${r}_k${k}_s${s}.cnf;
    (time OKsolver_2002-O3-DNDEBUG r${r}_k${k}_s${s}.cnf) > oksolver_r${r}_k${k}_s${s}.result 2>&1;
  done;
done;
     \endverbatim
     <li> Looking at randomising seeds 1-3 (4-5 still running):
     \verbatim
shell> echo "n  c  l  t  sat  nds  r1  r2  pls  ats h file n2cr  dmcl dn  dc  dl snds qnds mnds  tel  oats  n2cs  m2cs r k s" > oksolver_results; for s in $(seq 1 3); do
  for k in $(seq 1 20); do
    OKP=~/Work/OKlibrary/OKplatform/; cat oksolver_r${r}_k${k}_s${s}.result | awk -f ${OKP}/OKsystem/OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractOKsolver.awk | awk " { print \$0 \"  $r  $k $s\" }";
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
E = read.table("minisat_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r    n        c        t sat     cfs     dec     rts        r1   mem  ptime
1 4 2624 23616.55 416.5165   1 1454177 2607240 2732.91 488831369 77.85 0.0133
  stime       cfl r    k s
1  0.01 200745903 4 10.5 3
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>


  \todo Using the 1-base translations for the S-boxes (6-to-4)
  <ul>
   <li> Translating the DES Sboxes, as 6-to-4 bit boolean functions, using
   1-bases. </li>
   <li> Generating the 1-bases:
   \verbatim
shell> mkdir -p des_4/1base
shell> cd des_4/1base
shell> oklib --maxima
maxima> oklib_load_all()$ for i : 1 thru 8 do output_dessbox_fullcnf_stdname(i)$
shell> gen_seed[1]=7;gen_seed[2]=71;gen_seed[3]=185;gen_seed[4]=346;gen_seed[5]=67;gen_seed[6]=327;gen_seed[7]=148;gen_seed[8]=167;
shell> base_seed[1]=1;base_seed[2]=1;base_seed[3]=2;base_seed[4]=4;base_seed[5]=2;base_seed[6]=1;base_seed[7]=2;base_seed[8]=1;
shell> for i in $(seq 1 8); do
  QuineMcCluskey-n16-O3-DNDEBUG DES_Sbox_${i}_fullCNF.cnf > DES_Sbox_${i}_pi.cnf;
  RandomShuffleDimacs-O3-DNDEBUG ${gen_seed[$i]} < DES_Sbox_${i}_pi.cnf | SortByClauseLength-O3-DNDEBUG > DES_Sbox_${i}_sortedpi.cnf;
  RUcpGen-O3-DNDEBUG DES_Sbox_${i}_sortedpi.cnf > DES_Sbox_${i}_gen.cnf;
  RandomShuffleDimacs-O3-DNDEBUG ${base_seed[$i]}  < DES_Sbox_${i}_gen.cnf | SortByClauseLengthDescending-O3-DNDEBUG | RUcpBase-O3-DNDEBUG > DES_Sbox_${i}_1base.cnf;
done
   \endverbatim
   </li>
   <li> The numbers of clauses in the 1-bases are 124, 129, 138, 128, 134,
   136, 123, 152 respectively. </li>
   <li> All the 1-bases used have clauses of sizes 5 and 6, except Sbox 4
   which has clauses of size 5 and 6 as well as 2 of size 7. </li>
   <li> Considering a single plaintext-ciphertext pair:
    <ul>
     <li> Generating the instance:
     \verbatim
des_4/canon> oklib --maxima
rounds : 4$
sbox_fcl_l : create_list(read_fcl_f(sconcat("DES_Sbox_",i,"_1base.cnf")), i, 1, 8)$
P_hex : "038E596D4841D03B"$
K_hex : "15FBC08D31B0D521"$
C_hex : des_encryption_hex_gen(rounds, "038E596D4841D03B","15FBC08D31B0D521")$
P : des_plain2fcl_gen(hexstr2binv(P_hex),rounds)$
C : des_cipher2fcl_gen(hexstr2binv(C_hex),rounds)$
F : des2fcl_gen(sbox_fcl_l,rounds)$
Fs : standardise_fcl([F[1],append(F[2],P[2],C[2])])$
output_fcl_v(
  sconcat("DES over ",rounds," rounds; translated using 1-base translations for the S-boxes (6-to-4)."),
  Fs[1],
  sconcat("des_6t4_1base_r",rounds,".cnf"),
  Fs[2])$
print("DONE!");
     \endverbatim
     </li>
     <li> Statistics:
     \verbatim
shell> cat des_6t4_1base_r4.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
576 5664 27076 0 27076 577 1
 length count
1 128
3 1280
5 2432
6 1820
7 4
     \endverbatim
     </li>
     <li> S-box statistics (1-base translations):
     \verbatim
for F in sbox_fcl_l do print(ncl_list_fcl(F));
[[5,84],[6,39],[7,1]]
[[5,75],[6,54]]
[[5,76],[6,62]]
[[5,69],[6,59]]
[[5,78],[6,56]]
[[5,83],[6,53]]
[[5,75],[6,48]]
[[5,68],[6,84]]
     \endverbatim
     </li>
     <li> We have the following number of clauses of the following sizes:
      <ul>
       <li> 128 unit-clauses (setting plaintext + ciphertext); </li>
       <li> 1280 ternary clauses (80 * 4 = 32 binary additions); </li>
       <li> 2432 clauses of length five (8 * 4 = 32 S-boxes); </li>
       <li> 1820 clauses of length six (8 * 4 = 32 S-boxes); </li>
       <li> 4 clauses of length seven (1 * 4 = 4 S-boxes). </li>
      </ul>
     </li>
     <li> Solvers (t:time,cfs:conflicts,nds:nodes): cryptominisat
     (t:7.52s,cfs:124339), precosat236 (t:15s,cfs:276563), minisat-2.2.0
     (t:18s,cfs:613128), precosat-570.1 (t:18.4s,cfs:252715), glucose
     (t:60s,cfs:437112), OKsolver_2002 (t:761s,nds:1361497). </li>
    </ul>
   </li>
   <li> Considering random 20 plaintext-ciphertext pairs and randomising
   the clause-set 5 times:
    <ul>
     <li> Generating the instances:
     \verbatim
shell> mkdir -p des_4/1base
shell> cd des_4/1base
shell> oklib --maxima
oklib_load_all()$
rounds : 4$
sbox_fcl_l : create_list(read_fcl_f(sconcat("DES_Sbox_",i,"_1base.cnf")), i, 1, 8)$
for seed : 1 thru 20 do block(
  print(sconcat("Generating ", rounds, "-round DES with seed ", seed)),
  set_random(make_random_state(seed)),
  P_hex : lpad(int2hex(random(2**64)),"0",16),
  K_hex : lpad(int2hex(random(2**64)),"0",16),
  C_hex : des_encryption_hex_gen(rounds, P_hex,K_hex),
  P : des_plain2fcl_gen(hexstr2binv(P_hex),rounds),
  C : des_cipher2fcl_gen(hexstr2binv(C_hex),rounds),
  F : des2fcl_gen(sbox_fcl_l,rounds),
  Fs : standardise_fcl([F[1],append(F[2],P[2],C[2])]),
  output_fcl_v(
  sconcat(rounds, "-round DES instantiated with plaintext and ciphertext generated from seed ", seed, "; translated using the 1-base translation for the S-boxes (6-to-4)."),
    Fs[1],
    sconcat("des_6t4_1base_r",rounds,"_s",seed,".cnf"),
    Fs[2]))$
print("DONE!");
     \endverbatim
     </li>
     <li> Running minisat-2.2.0 on these instances:
     \verbatim
shell> r=4;
shell> for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    echo "Round ${r}; Key Seed ${k}; Random Seed ${s}...";
    cat des_6t4_1base_r${r}_s${k}.cnf | RandomShuffleDimacs-O3-DNDEBUG $s > r${r}_k${k}_s${s}.cnf;
    (time minisat-2.2.0 r${r}_k${k}_s${s}.cnf) > minisat_r${r}_k${k}_s${s}.result 2>&1;
  done;
done;
shell> echo "n  c  t  sat  cfs dec rts r1 mem ptime stime cfl r k s" > minisat_results; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    OKP=~/Work/OKlibrary/OKplatform/; cat minisat_r${r}_k${k}_s${s}.result | awk -f extract_bash_time_minisat.awk | awk -f ${OKP}/OKsystem/OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractMinisat.awk | awk " { print \$0 \"  $r  $k $s\" }";
  done;
done >> minisat_results;
     \endverbatim
     where extract_bash_time_minisat.awk is (as minisat-2.2.0 reports the wrong time):
     \verbatim
/^CPU time/ { }
/^real/  { split($2,a,"m"); split(a[2],b,"s"); print "CPU time              : " (a[1] * 60) + b[1] " s"; }
$0 !~ /^(CPU time|real)/ { print }
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("minisat_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r   n       c       t sat     cfs     dec     rts       r1   mem ptime  stime
1 4 576 5313.23 42.7119   1 1266362 1431265 2404.62 93211178 20.39     0 0.0049
       cfl r    k s
1 24220285 4 10.5 3
     \endverbatim
     </li>
     <li> Running OKsolver_2002 on these instances:
     \verbatim
shell> r=4;
shell> for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    echo "Round ${r}; Key Seed ${k}; Random Seed ${s}...";
    cat des_6t4_1base_r${r}_s${k}.cnf | RandomShuffleDimacs-O3-DNDEBUG $s > r${r}_k${k}_s${s}.cnf;
    (time OKsolver_2002-O3-DNDEBUG r${r}_k${k}_s${s}.cnf) > oksolver_r${r}_k${k}_s${s}.result 2>&1;
  done;
done;
     \endverbatim
     <li> Looking at randomising seeds 1-3 (4-5 still running):
     \verbatim
shell> echo "n  c  l  t  sat  nds  r1  r2  pls  ats h file n2cr  dmcl dn  dc  dl snds qnds mnds  tel  oats  n2cs  m2cs r k s" > oksolver_results; for s in $(seq 1 3); do
  for k in $(seq 1 20); do
    OKP=~/Work/OKlibrary/OKplatform/; cat oksolver_r${r}_k${k}_s${s}.result | awk -f extract_bash_time_oksolver.awk | awk -f ${OKP}/OKsystem/OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractOKsolver.awk | awk " { print \$0 \"  $r  $k $s\" }";
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
  r   n    c     l        t sat     nds  r1      r2 pls ats    h file n2cr dmcl
1 4 568 5664 27076 1971.334   1 3320624 128 8818236   0 0.1 34.8   NA  448    0
   dn  dc   dl     snds qnds     mnds tel oats n2cs m2cs r    k s
1 128 576 1920 1238.183    0 3169.317   0    0    0    0 4 10.5 2
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>


  \todo Using the "minimum" translation for the S-boxes (6-to-4)
  <ul>
   <li> Translating the DES Sboxes, as 6-to-4 bit boolean functions, using the
   "minimum" (inf-based) representations. </li>
   <li> Generating the "minimum" CNFs for the Sboxes:
   \verbatim
shell> mkdir -p des_4/min
shell> cd des_4/min
shell> oklib --maxima
maxima> oklib_load_all()$ for i : 1 thru 8 do output_dessbox_fullcnf_stdname(i)$
shell> for i in $(seq 1 8); do
  QuineMcCluskeySubsumptionHypergraph-n16-O3-DNDEBUG DES_Sbox_${i}_fullCNF.cnf > DES_Sbox_${i}_shg.cnf;
  cat DES_Sbox_${i}_shg.cnf | MinOnes2WeightedMaxSAT-O3-DNDEBUG > DES_Sbox_${i}_shg.wcnf;
done
shell> ubcsat-okl  -alg gsat -w -runs 100 -cutoff 400000 -wtarget 67 -solve 1 -seed 2444475534 -i DES_Sbox_1_shg.wcnf -r model DES_Sbox_1.ass;
shell> ubcsat-okl  -alg gsat -w -runs 100 -cutoff 400000 -wtarget 67 -solve 1 -seed 2521057446 -i DES_Sbox_2_shg.wcnf -r model DES_Sbox_2.ass;
shell> ubcsat-okl  -alg gsat -w -runs 100 -cutoff 400000 -wtarget 68 -solve 1 -seed 3544367510 -i DES_Sbox_3_shg.wcnf -r model DES_Sbox_3.ass;
shell> ubcsat-okl  -alg gsat -w -runs 100 -cutoff 400000 -wtarget 69 -solve 1 -seed 3808694681 -i DES_Sbox_4_shg.wcnf -r model DES_Sbox_4.ass;
shell> ubcsat-okl  -alg gsat -w -runs 100 -cutoff 400000 -wtarget 67 -solve 1 -seed 1876503362 -i DES_Sbox_5_shg.wcnf -r model DES_Sbox_5.ass;
shell> ubcsat-okl  -alg gsat -w -runs 100 -cutoff 400000 -wtarget 66 -solve 1 -seed 68018538 -i DES_Sbox_6_shg.wcnf -r model DES_Sbox_6.ass;
shell> ubcsat-okl  -alg gsat -w -runs 100 -cutoff 400000 -wtarget 67 -solve 1 -seed 1856244582 -i DES_Sbox_7_shg.wcnf -r model DES_Sbox_7.ass;
shell> ubcsat-okl  -alg gsat -w -runs 100 -cutoff 400000 -wtarget 69 -solve 1 -seed 4223500633 -i DES_Sbox_8_shg.wcnf -r model DES_Sbox_8.ass;
shell> for i in $(seq 1 8); do
  cat DES_Sbox_${i}_fullCNF.cnf_primes | FilterDimacs DES_Sbox_${i}.ass > DES_Sbox_${i}_min.cnf;
done
   \endverbatim
   </li>
   <li> The numbers of clauses in the CNFs are 67, 67, 68, 69, 67, 66, 67, and
   69 respectively. </li>
   <li> Considering 1 plaintext-ciphertext pair:
    <ul>
     <li> Generating the instance:
     \verbatim
rounds : 4$
sbox_fcl_l : create_list(read_fcl_f(sconcat("DES_Sbox_",i,"_min.cnf")), i, 1, 8)$
P_hex : "038E596D4841D03B"$
K_hex : "15FBC08D31B0D521"$
C_hex : des_encryption_hex_gen(rounds, "038E596D4841D03B","15FBC08D31B0D521")$
P : des_plain2fcl_gen(hexstr2binv(P_hex),rounds)$
C : des_cipher2fcl_gen(hexstr2binv(C_hex),rounds)$
F : des2fcl_gen(sbox_fcl_l,rounds)$
Fs : standardise_fcl([F[1],append(F[2],P[2],C[2])])$
output_fcl_v(
  sconcat("DES over ",rounds," rounds; translated using minimum translations for the S-boxes (6-to-4)."),
  Fs[1],
  sconcat("des_6t4_min_r",rounds,".cnf"),
  Fs[2])$
print("DONE!");
     \endverbatim
     </li>
     <li> Statistics:
     \verbatim
shell> cat des_6t4_min_r4.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
576 3568 16048 0 16048 577 1
 length count
1 128
3 1280
5 928
6 1184
7 48
     \endverbatim
     </li>
     <li> S-box statistics ("minimum" translation):
     \verbatim
for F in sbox_fcl_l do print(ncl_list_fcl(F));

[[5,30],[6,35],[7,2]]
[[5,33],[6,33],[7,1]]
[[5,28],[6,38],[7,2]]
[[5,29],[6,38],[7,2]]
[[5,29],[6,36],[7,2]]
[[5,28],[6,38]]
[[5,29],[6,37],[7,1]]
[[5,26],[6,41],[7,2]]
     \endverbatim
     </li>
     <li> We have the following number of clauses of the following sizes:
      <ul>
       <li> 128 unit-clauses (setting plaintext + ciphertext); </li>
       <li> 1280 ternary clauses (80 * 4 = 320 binary additions); </li>
       <li> 928 clauses of length five (8 * 4 = 32 S-boxes); </li>
       <li> 1184 clauses of length six (8 * 4 = 32 S-boxes); </li>
       <li> 48 clauses of length seven (7 * 4 = 28 S-boxes). </li>
      </ul>
     </li>
     <li> Solvers (t:time,cfs:conflicts,nds:nodes): precosat-570.1
     (t:0.5s,cfs:20603), minisat-2.2.0 (t:9s, cfs:479829), precosat236
     (t:10.1s,cfs:242455), cryptominisat (t:30s,cfs:372190), OKsolver_2002
     (t:1600s,nds:5797). </li>
    </ul>
   </li>
   <li> Considering 20 plaintext-ciphertext pairs, randomising each in 5
   different ways:
    <ul>
     <li> Generating the instances:
     \verbatim
des_4/min> oklib --maxima
oklib_load_all()$
rounds : 4$
sbox_fcl_l : create_list(read_fcl_f(sconcat("DES_Sbox_",i,"_min.cnf")), i, 1, 8)$
for seed : 1 thru 20 do block(
  print(sconcat("Generating ", rounds, "-round DES with seed ", seed)),
  set_random(make_random_state(seed)),
  P_hex : lpad(int2hex(random(2**64)),"0",16),
  K_hex : lpad(int2hex(random(2**64)),"0",16),
  C_hex : des_encryption_hex_gen(rounds, P_hex,K_hex),
  P : des_plain2fcl_gen(hexstr2binv(P_hex),rounds),
  C : des_cipher2fcl_gen(hexstr2binv(C_hex),rounds),
  F : des2fcl_gen(sbox_fcl_l,rounds),
  Fs : standardise_fcl([F[1],append(F[2],P[2],C[2])]),
  output_fcl_v(
  sconcat(rounds, "-round DES instantiated with plaintext and ciphertext generated from seed ", seed, "; translated using the minimum translation for the S-boxes (6-to-4)."),
    Fs[1],
    sconcat("des_6t4_min_r",rounds,"_s",seed,".cnf"),
    Fs[2]))$
print("DONE!");
     \endverbatim
     </li>
     <li> Running minisat-2.2.0 on these instances:
     \verbatim
shell> r=4;
shell> for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    echo "Round ${r}; Key Seed ${k}; Random Seed ${s}...";
    cat des_6t4_min_r${r}_s${k}.cnf | RandomShuffleDimacs-O3-DNDEBUG $s > r${r}_k${k}_s${s}.cnf;
    (time minisat-2.2.0 r${r}_k${k}_s${s}.cnf) > minisat_r${r}_k${k}_s${s}.result 2>&1;
  done;
done;
shell> echo "n  c  t  sat  cfs dec rts r1 mem ptime stime cfl r k s" > minisat_results; for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    OKP=~/Work/OKlibrary/OKplatform/; cat minisat_r${r}_k${k}_s${s}.result | awk -f extract_bash_time_minisat.awk | awk -f ${OKP}/OKsystem/OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractMinisat.awk | awk " { print \$0 \"  $r  $k $s\" }";
  done;
done >> minisat_results;
     \endverbatim
     where extract_bash_time_minisat.awk is (as minisat-2.2.0 reports the wrong time):
     \verbatim
/^CPU time/ { }
/^real/  { split($2,a,"m"); split(a[2],b,"s"); print "CPU time              : " (a[1] * 60) + b[1] " s"; }
$0 !~ /^(CPU time|real)/ { print }
     \endverbatim
     yields:
     \verbatim
shell> oklib --R
E = read.table("minisat_results", header=TRUE)
EM = aggregate(E, by=list(r=E$r), FUN=mean)
EM
  r   n       c       t sat     cfs     dec     rts        r1   mem ptime stime
1 4 576 3216.35 48.1668   1 2095952 2560479 3758.17 129184335 19.53     0 5e-04
       cfl r    k s
1 38584572 4 10.5 3
     \endverbatim
     </li>
     <li> Running OKsolver_2002 on these instances:
     \verbatim
shell> r=4;
shell> for s in $(seq 1 5); do
  for k in $(seq 1 20); do
    echo "Round ${r}; Key Seed ${k}; Random Seed ${s}...";
    cat des_6t4_min_r${r}_s${k}.cnf | RandomShuffleDimacs-O3-DNDEBUG $s > r${r}_k${k}_s${s}.cnf;
    (time OKsolver_2002-O3-DNDEBUG r${r}_k${k}_s${s}.cnf) > oksolver_r${r}_k${k}_s${s}.result 2>&1;
  done;
done;
shell> echo "n  c  l  t  sat  nds  r1  r2  pls  ats h file n2cr  dmcl dn  dc  dl snds qnds mnds  tel  oats  n2cs  m2cs r k s" > oksolver_results; for s in $(seq 1 3); do
  for k in $(seq 1 20); do
    OKP=~/Work/OKlibrary/OKplatform/; cat oksolver_r${r}_k${k}_s${s}.result | awk -f extract_bash_time_oksolver.awk | awk -f ${OKP}/OKsystem/OKlib/Experimentation/ExperimentSystem/SolverMonitoring/ExtractOKsolver.awk | awk " { print \$0 \"  $r  $k $s\" }";
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
  r   n    c     l        t sat     nds  r1       r2 pls        ats        h
1 4 568 3568 16048 1599.375   1 5487761 128 14852411   0 0.06666667 37.96667
  file n2cr dmcl  dn  dc   dl     snds qnds  mnds tel oats n2cs m2cs r    k s
1   NA  448    0 128 576 1920 6657.167    0 11729   0  3.9    0    0 4 10.5 2
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>

*/
