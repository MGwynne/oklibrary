// Matthew Gwynne, 17.11.2011 (Swansea)
/* Copyright 2011, 2012 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Investigations/Cryptography/AdvancedEncryptionStandard/plans/KeyDiscovery/012/1_3_4/general.hpp
  \brief Investigations into small-scale AES key discovery with 1 row, 3 column and 4-bit field elements


  \todo Problem specification
  <ul>
  <li> We consider the small-scale AES with 1 row, 3 columns, using the 4-bit
   field size for rounds 1 to 20. </li>
   <li> We denote this AES instance by aes(r,1,3,4) for r in 1,...,20. </li>
   <li> Thus aes(r,1,3,4) has 1*3*4=12-bit plaintext/key/ciphertext. </li>
   <li> As a reminder, aes(r,1,3,4) applies the following operations (up to
   variable-permutations):
    <ol>
     <li> Key schedule applies the following operations r+1 times:
      <ul>
       <li> r * 1 = r S-boxes (first column).
       <li> r * 1 * 4 * 2 = 8*r additions of arity 2 (last two columns). </li>
       <li> r * 1 * 4 = 4*r additions of arity 3 (first column). </li>
      </ul>
     generating r+1 12-bit round keys. </li>
     <li> Application of the following operation (the "round") r times:
      <ol>
       <li> Addition of 12-bit round key. </li>
       <li> Application of 3 4x4-bit Sbox operations. </li>
       <li> Mixcolumn is just the identity, namely application of
       3 (1*4)x(1*4)=4x4-bit Mixcolumn operations, given by the 1x1 matrix (1)
       over the half-byte field. </li>
      </ol>
     </li>
     <li> Addition of round key r+1. </li>
     <li> The result of the last round key addition is the ciphertext. </li>
    </ol>
   </li>
   <li> Round key 0 is the input key. </li>
   <li> The S-box is a permutation from {0,1}^4 to {0,1}^4 which we consider
   as either:
    <ul>
     <li> a 8x1 boolean function; see ss_sbox_bf in
     Cryptology/Lisp/CryptoSystems/Rijndael/AdvancedEncryptionStandard.mac.
     </li>
     <li> 4 4x1 boolean functions (not implemented yet). </li>
    </ul>
   </li>
   <li> The decompositions and translations are listed in "Investigating
   dimensions" in
   Cryptography/AdvancedEncryptionStandard/plans/Experimentation.hpp.
   </li>
   <li> The plaintext and ciphertext variables are then set, and the
   SAT solver is run on this instance to deduce the key variables. </li>
  </ul>


  \todo Instance characteristics
  <ul>
   <li> In this instance, we have:
    <ul>
     <li> r full rounds (Key Addition, SubBytes; MixColumns is the identity).
     </li>
     <li> 4*r Sboxes:
      <ul>
       <li> 3*r from SubBytes = 3 columns * r rounds; </li>
       <li> r from key schedule = 1 column * r round. </li>
      </ul>
     </li>
     <li> 52*r + 12 additions:
      <ul>
       <li> 24*r additions of arity 1 (equivalence clauses):
        <ul>
         <li> 12*r from forward MixColumns = 12 bits * r rounds; </li>
         <li> 12*r from inverse MixColumns = 12 bits * r rounds. </li>
        </ul>
       </li>
       <li> 20*r + 12 additions of arity 2:
        <ul>
         <li> 12*r from key additions = 12 bits * r round; </li>
         <li> 12 from final key addition = 12 bits; </li>
         <li> 8*r from the key schedule = 4 bits * 2 column * r rounds. </li>
        </ul>
       </li>
       <li> 4*r additions of arity 3:
        <ul>
         <li> 4*r from the key schedule = 4 bits * 1 column * r rounds. </li>
        </ul>
       </li>
      </ul>
     </li>
     <li> 4*r bits from the key schedule constant = 4 bits * r rounds. </li>
    </ul>
   </li>
   <li> S-box statistics:
   \verbatim
# Canonical
statistics_fcs(dualts_fcl(ss_sbox_fulldnf_fcl(2,4,ss_polynomial(2,4))));
  [24,145,416,16,2]
# 1-base
statistics_fcs(ev_hm(ss_sbox_rbase_cnfs,4));
  [8,27,96,4,3]
# minimum
statistics_fcs(ev_hm(ss_sbox_cnfs,4));
  [8,22,82,5,3]
   \endverbatim
   For details of the generation, see "Translations" below. </li>
   <li> Calculating the statistics:
    <ul>
     <li> The clause-set has:
     \verbatim
n : nvar_ss_gen(r,3,1,4,matrix([1]),s_n - 8,[], false, aes_mc_bidirectional);
  r*(s_n-4)+3*r*(s_n-8)+52*r+36
expand(simplify_t(n));
  4*r*s_n+24*r+36
factorout(expand(simplify_t(n)), s_n);
  4*r*(s_n+6)+36
     \endverbatim
     variables, where s_n is the number of variables in the S-box
     representation for each S-box. </li>
     <li> Each clause-set has:
      <ul>
       <li> 4*r*(s_c+41) + 48 clauses:
       \verbatim
c : 4*r*s_c + 24*r*2 + (20*r+12)*4 + 4*r*8 + 4*r;
expand(simplify_t(c));
  4*r*s_c+164*r+48
factorout(expand(simplify_t(c)), s_c);
  4*r*(s_c+41)+48
       \endverbatim
       clauses, where s_c is the number of clauses in the S-box
       representation. </li>
      </ul>
     </li>
     <li> Instantiating for the 1-base translation, where now
     s_n=24; s_c=145:
     \verbatim
expand(ev(n, s_n:24));
120*r+36
expand(ev(c, s_c:145));
744*r+48
     \endverbatim
     Checking:
     \verbatim
> ExtendedDimacsStatistics-O3-DNDEBUG < ssaes_r20_c3_rw1_e4_f0.cnf
     pn      pc      n    nmi       c        l     n0   n0mi      c0       l0  cmts
   2436   14928   2436   2436   14928    42784     NA     NA   14928    42784  2437

> ev(n, s_n:24, r:20);
  2436
> ev(c, s:145,r:20);
  14928
     \endverbatim
     </li>
     <li> Instantiating for the 1-base translation, where now
     s_n=8; s_c=27:
     \verbatim
expand(ev(n, s_n:8));
56*r+36
expand(ev(c, s_c:27));
272*r+48
     \endverbatim
     Checking:
     \verbatim
> ExtendedDimacsStatistics-O3-DNDEBUG < ssaes_r20_c3_rw1_e4_f0.cnf
     pn      pc      n    nmi       c        l     n0   n0mi      c0       l0  cmts
   1156    5488   1156   1156    5488    17184     NA     NA    5488    17184  1157

> ev(n, s_n:8, r:20);
  1156
> ev(c, s_c:27,r:20);
  5488
     \endverbatim
     </li>
     <li> Instantiating for the minimum translation, where now
     s_n=8; s_c=22:
     \verbatim
expand(ev(n, s_n:8));
56*r+36
expand(ev(c, s_c:22));
252*r+48
     \endverbatim
     Checking:
     \verbatim
> ExtendedDimacsStatistics-O3-DNDEBUG < ssaes_r20_c3_rw1_e4_f0.cnf
     pn      pc      n    nmi       c        l     n0   n0mi      c0       l0  cmts
   1156    5088   1156   1156    5088    16064     NA     NA    5088    16064  1157

> ev(n, s_n:8, r:20);
  1156
> ev(c, s_c:22,r:20);
  5088
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>


  \todo Translations
  <ul>
   <li> The following translations are considered in this %plans %file:
    <ul>
     <li> The canonical box translation. </li>
     <li> The minimum box translation. </li>
     <li> The 1-base translation. </li>
    </ul>
   </li>
   <li> For a full list of the possible translations, see
   "Investigating dimensions" in
   Cryptography/AdvancedEncryptionStandard/plans/Experimentation.hpp.
   </li>
   <li> Generating instances for rounds 1-20 for a 20 random keys with each
   of the translations:
    <ul>
     <li> The canonical box translation:
     \verbatim
shell> mkdir ssaes_r1-20_c3_rw1_e4_f0_k1-20_aes_canon_box_aes_mc_bidirectional
shell> cd ssaes_r1-20_c3_rw1_e4_f0_k1-20_aes_canon_box_aes_mc_bidirectional
shell> oklib --maxima
num_rows : 1$
num_columns : 3$
exp : 4$
final_round_b : false$
box_tran : aes_ts_box$
seed : 1$
mc_tran : aes_mc_bidirectional$
for num_rounds : 1 thru 20 do (
  output_ss_fcl_std(
    num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran),
  for seed : 1 thru 20 do (
    output_ss_random_pc_pair(
      seed,num_rounds,num_columns,num_rows,exp,final_round_b)))$
exit();
shell> for r in $(seq 1 20); do
  for s in $(seq 1 20) do
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c3_rw1_e4_f0.cnf ssaes_pcpair_r${r}_c3_rw1_e4_f0_s${s}.cnf > r${r}_k${s}.cnf;
  done
done
     \endverbatim
     </li>
     <li> The minimum box translation:
     \verbatim
shell> mkdir ssaes_r1-20_c3_rw1_e4_f0_k1-20_aes_min_box_aes_mc_bidirectional
shell> cd ssaes_r1-20_c3_rw1_e4_f0_k1-20_aes_min_box_aes_mc_bidirectional
shell> oklib --maxima
num_rows : 1$
num_columns : 3$
exp : 4$
final_round_b : false$
box_tran : aes_small_box$
seed : 1$
mc_tran : aes_mc_bidirectional$
for num_rounds : 1 thru 20 do (
  output_ss_fcl_std(
    num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran),
  for seed : 1 thru 20 do (
    output_ss_random_pc_pair(
      seed,num_rounds,num_columns,num_rows,exp,final_round_b)))$
exit();
shell> for r in $(seq 1 20); do
  for s in $(seq 1 20) do
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c3_rw1_e4_f0.cnf ssaes_pcpair_r${r}_c3_rw1_e4_f0_s${s}.cnf > r${r}_k${s}.cnf;
  done
done
     \endverbatim
     </li>
     <li> The 1-base box translation:
     \verbatim
shell> mkdir ssaes_r1-20_c3_rw1_e4_f0_k1-20_aes_1base_box_aes_mc_bidirectional
shell> cd ssaes_r1-20_c3_rw1_e4_f0_k1-20_aes_1base_box_aes_mc_bidirectional
shell> oklib --maxima
num_rows : 1$
num_columns : 3$
exp : 4$
final_round_b : false$
box_tran : aes_rbase_box$
seed : 1$
mc_tran : aes_mc_bidirectional$
for num_rounds : 1 thru 20 do (
  output_ss_fcl_std(
    num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran),
  for seed : 1 thru 20 do (
    output_ss_random_pc_pair(
      seed,num_rounds,num_columns,num_rows,exp,final_round_b)))$
exit();
shell> for r in $(seq 1 20); do
  for s in $(seq 1 20) do
    AppendDimacs-O3-DNDEBUG ssaes_r${r}_c3_rw1_e4_f0.cnf ssaes_pcpair_r${r}_c3_rw1_e4_f0_s${s}.cnf > r${r}_k${s}.cnf;
  done
done
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>


  \todo Analysing the data
  <ul>
   <li> Overview on all parameters:
    <ol>
     <li> n, c, l: strict linear dependency on r:
     \verbatim
n = 116 * r + 12  (canonical)
n = 52 * r + 12   (1-base)
n = 52 * r + 12   (minimum)
c = 724 * r       (canonical)
c = 252 * r       (1-base)
c = 232 * r       (minimum)
l = 2048 * r - 48 (canonical)
l = 768 * r - 48  (1-base)
l = 712 * r - 48  (minimum)
     \endverbatim
     </li>
     <li> t ~ r: linear relationship with increasing variance:
     \verbatim
t = 0.0228277 * r - 0.0271841 (canonical, Mult R^2=0.3386, R^2 avg over s=0.9197)
t = 0.0111033 * r - 0.0072123 (1-base, Mult R^2=0.3223, R^2 avg over s=0.8502)
t = 0.0143109 * r - 0.0269359 (min, Mult R^2=0.3732, R^2 avg over s=0.8912)
     \endverbatim
     </li>
     <li> sat: constant 1. </li>
     <li> t ~ r1 XXX </li>
     <li> dec ~ cfs XXX </li>
     <li> rts XXX </li>
     <li> r1 ~ r XXX </li>
     <li> mem: seems to be two-valued </li>
     <li> ptime, stime: seems to be implementation-dependent paramters without
     deeper meaning. </li>
     <li> cfl ~ cfs XXX </li>
     <li> r: the independent variable, varies from 1 to 20. </li>
     <li> For every r-values, 1 <= s <= 20 are the data points. </li>
    </ol>
   </li>
   <li> minisat-2.2.0:
    <ul>
     \verbatim
> git clone git://github.com/MGwynne/Experimental-data.git

> E_canon = read.table("Experimental-data/AES/1_3_4/ssaes_r1-20_c3_rw1_e4_f0_k1-20_aes_canon_box_aes_mc_bidirectional/MinisatStatistics",header=TRUE)
> E_1base = read.table("Experimental-data/AES/1_3_4/ssaes_r1-20_c3_rw1_e4_f0_k1-20_aes_1base_box_aes_mc_bidirectional/MinisatStatistics",header=TRUE)
> E_min = read.table("Experimental-data/AES/1_3_4/ssaes_r1-20_c3_rw1_e4_f0_k1-20_aes_min_box_aes_mc_bidirectional/MinisatStatistics",header=TRUE)

# Removing constant, and implementation dependent variables
> excluded_columns=c("sat", "stime", "ptime", "s")
> E_canon = E_canon[,!(names(E_canon) %in% excluded_columns)]
> E_1base = E_1base[,!(names(E_1base) %in% excluded_columns)]
> E_min = E_min[,!(names(E_min) %in% excluded_columns)]

# Values averaged per round:
> E_canon_mean = aggregate(E_canon, by=list(r=E_canon$r), FUN=mean)
> E_1base_mean = aggregate(E_1base, by=list(r=E_1base$r), FUN=mean)
> E_min_mean = aggregate(E_min, by=list(r=E_min$r), FUN=mean)
     \endverbatim
     </li>
     <li> Canonical translation:
      <ul>
       <li> n, c and l vs r: strict linear relationship:
       \verbatim
> plot(E_canon$r, E_canon$n)
> m = lm(E_canon$n ~ E_canon$r)
> short_summary_lm(m)
              Estimate Std. Error    t value  Pr(>|t|)
(Intercept) 1.2000e+01 2.8822e-13 4.1635e+13 < 2.2e-16 ***
E_canon$r   1.1600e+02 2.4060e-14 4.8213e+15 < 2.2e-16 ***
R-squared:     1
# Yielding the (exact) model: n = 116 * r + 12
> plot(E_canon$r, E_canon$c)
> m = lm(E_canon$c ~ E_canon$r)
> short_summary_lm(m)
              Estimate Std. Error    t value  Pr(>|t|)
(Intercept) 2.9104e-12 4.1913e-13 6.9439e+00 1.561e-11 ***
E_canon$r   7.2400e+02 3.4988e-14 2.0693e+16 < 2.2e-16 ***
R-squared:     1
# Yielding the (exact) model: c = 724 * r
> plot(E_canon$r, E_canon$l)
> m = lm(E_canon$l ~ E_canon$r)
> short_summary_lm(m)
               Estimate  Std. Error     t value  Pr(>|t|)
(Intercept) -4.8000e+01  6.5367e-12 -7.3431e+12 < 2.2e-16 ***
E_canon$r    2.0480e+03  5.4567e-13  3.7532e+15 < 2.2e-16 ***
R-squared:     1
# Yielding the (exact) model: l = 2048 * r - 48
       \endverbatim
       </li>
       <li> rounds vs time: linear function with increasing variance;
       filling a triangle in the bottom left.
       \verbatim
> plot(E_canon$r, E_canon$t)
> points(E_canon_mean$r, E_canon_mean$t, pch=1, cex=3)
> m = lm(E_canon$t ~ E_canon$r)
> lines(E_canon$r, predict(m))
> short_summary_lm(m)
              Estimate Std. Error t value Pr(>|t|)
(Intercept) -0.0271841  0.0191574  -1.419   0.1567
E_canon$r    0.0228277  0.0015992  14.274   <2e-16 ***
R-squared: 0.3386
> mm = lm(E_canon_mean$t ~ E_canon_mean$r)
> short_summary_lm(mm)
                 Estimate Std. Error t value  Pr(>|t|)
(Intercept)    -0.0271841  0.0190428 -1.4275    0.1705
E_canon_mean$r  0.0228277  0.0015897 14.3602 2.667e-11 ***
R-squared: 0.9197
       \endverbatim
       So we have t = 0.0228277 * r - 0.0271841 as predictor for t,
       with a high variance increasing with the number of rounds. </li>
       </li>
       <li> rounds vs r1: linear function with increasing variance;
       filling a triangle in the bottom left.
       \verbatim
> plot(E_canon$r, E_canon$r1)
> points(E_canon_mean$r, E_canon_mean$r1, pch=3, cex=2)
> m = lm(E_canon$r1 ~ E_canon$r)
> lines(E_canon$r, predict(m))
> summary(m)
            Estimate Std. Error t value Pr(>|t|)
(Intercept)  -292840     129202  -2.267    0.024 *
E_canon$r     158358      10786  14.682   <2e-16 ***
Residual standard error: 1244000 on 398 degrees of freedom
Multiple R-squared: 0.3513,     Adjusted R-squared: 0.3497
F-statistic: 215.6 on 1 and 398 DF,  p-value: < 2.2e-16
> mm = lm(E_canon_mean$r1 ~ E_canon_mean$r); summary(mm)$r.squared
[1] 0.9247276
       \endverbatim
       So we have r1 = 158358 * r - 292840 as predictor for r1. </li>
       <li> r1 vs time: (strong) linear relationship:
       \verbatim
> plot(E_canon$r1, E_canon$t)
> points(E_canon_mean$r1, E_canon_mean$t, pch=3, cex=2)
> m = lm(E_canon$t ~ E_canon$r1)
> lines(E_canon$r1, predict(m))
> summary(m)
             Estimate Std. Error t value Pr(>|t|)
(Intercept) 1.169e-02  8.894e-04   13.15   <2e-16 ***
E_canon$r1  1.466e-07  4.314e-10  339.76   <2e-16 ***

Residual standard error: 0.01329 on 398 degrees of freedom
Multiple R-squared: 0.9966,	Adjusted R-squared: 0.9966
F-statistic: 1.154e+05 on 1 and 398 DF,  p-value: < 2.2e-16
> mm = lm(E_canon_mean$t ~ E_canon_mean$r1); summary(mm)$r.squared
[1] 0.9977728
       \endverbatim
       So we have r1 = 1.466e-07 * r1 - 1.169e-02 as predictor for t. </li>
       </li>
       <li> r1 vs conflicts: looks like a "cone" from the origin
       \verbatim
> plot(E_canon$r1, E_canon$cfs)
> points(E_canon_mean$r1, E_canon_mean$cfs, pch=3, cex=2)
> m = lm(E_canon$cfs ~ E_canon$r1)
> lines(E_canon$r1, predict(m))
> summary(m)
             Estimate Std. Error t value Pr(>|t|)
(Intercept) 7.995e+02  6.990e+01   11.44   <2e-16 ***
E_canon$r1  1.112e-03  3.391e-05   32.79   <2e-16 ***

Residual standard error: 1045 on 398 degrees of freedom
Multiple R-squared: 0.7298,	Adjusted R-squared: 0.7291
F-statistic:  1075 on 1 and 398 DF,  p-value: < 2.2e-16
> mm = lm(E_canon_mean$cfs ~ E_canon_mean$r1); summary(mm)$r.squared
[1] 0.5396627

> plot(E_canon_mean$r1, E_canon_mean$cfs)
       \endverbatim
       </li>
      </ul>
     </li>
     <li> 1-base translation:
      <ul>
       <li> n, c and l vs r: strict linear relationship:
       \verbatim
> plot(E_1base$r, E_1base$n)
> m = lm(E_1base$n ~ E_1base$r)
> short_summary_lm(m)
              Estimate Std. Error    t value  Pr(>|t|)
(Intercept) 1.2000e+01 8.5093e-14 1.4102e+14 < 2.2e-16 ***
E_1base$r   5.2000e+01 7.1034e-15 7.3204e+15 < 2.2e-16 ***
R-squared:     1
# Yielding the (exact) model: n = 52 * r + 12
> plot(E_1base$r, E_1base$c)
> m = lm(E_1base$c ~ E_1base$r)
> short_summary_lm(m)
              Estimate Std. Error    t value  Pr(>|t|)
(Intercept) 2.1828e-12 2.3790e-13 9.1753e+00 < 2.2e-16 ***
E_1base$r   2.5200e+02 1.9859e-14 1.2689e+16 < 2.2e-16 ***
R-squared:     1
# Yielding the (exact) model: c = 252 * r
> plot(E_1base$r, E_1base$l)
> m = lm(E_1base$l ~ E_1base$r)
> short_summary_lm(m)
               Estimate  Std. Error     t value  Pr(>|t|)
(Intercept) -4.8000e+01  2.3445e-12 -2.0473e+13 < 2.2e-16 ***
E_1base$r    7.6800e+02  1.9572e-13  3.9240e+15 < 2.2e-16 ***
R-squared:     1
# Yielding the (exact) model: l = 768 * r - 48
       \endverbatim
       </li>
       <li> rounds vs time: linear function with increasing variance;
       filling a triangle in the bottom left.
       \verbatim
> plot(E_1base$r, E_1base$t)
> points(E_1base_mean$r, E_1base_mean$t, pch=1, cex=3)
> m = lm(E_1base$t ~ E_1base$r)
> lines(E_1base$r, predict(m))
> short_summary_lm(m)
             Estimate Std. Error t value Pr(>|t|)
(Intercept) -0.007212   0.009667  -0.746    0.456
E_1base$r    0.011103   0.000807  13.759   <2e-16 ***
R-squared: 0.3223
> mm = lm(E_1base_mean$t ~ E_1base_mean$r)
> short_summary_lm(mm)
                 Estimate Std. Error t value  Pr(>|t|)
(Intercept)    -0.0072123  0.0131592 -0.5481    0.5904
E_1base_mean$r  0.0111033  0.0010985 10.1077 7.572e-09 ***
R-squared: 0.8502
       \endverbatim
       So we have t = 0.0111033 * r - 0.0072123 as predictor for t,
       with a high variance increasing with the number of rounds. </li>
       <li> rounds vs r1: linear function with increasing variance;
       filling a triangle in the bottom left.
       \verbatim
> plot(E_1base$r, E_1base$r1)
> points(E_1base_mean$r, E_1base_mean$r1, pch=3, cex=2)
> m = lm(E_1base$r1 ~ E_1base$r)
> lines(E_1base$r, predict(m))
> summary(m)
            Estimate Std. Error t value Pr(>|t|)
(Intercept)   -70937      52596  -1.349    0.178
E_1base$r      61206       4391  13.940   <2e-16 ***
Residual standard error: 506300 on 398 degrees of freedom
Multiple R-squared: 0.3281,     Adjusted R-squared: 0.3264
F-statistic: 194.3 on 1 and 398 DF,  p-value: < 2.2e-16
> mm = lm(E_1base_mean$r1 ~ E_1base_mean$r); summary(mm)$r.squared
[1] 0.8596205
       \endverbatim
       So we have r1 = 61206 * r - 70937 as predictor for r1. </li>
       <li> r1 vs time: (strong) linear relationship:
       \verbatim
> plot(E_1base$r1, E_1base$t)
> points(E_1base_mean$r1, E_1base_mean$t, pch=3, cex=2)
> m = lm(E_1base$t ~ E_1base$r1)
> lines(E_1base$r1, predict(m))
> summary(m)
             Estimate Std. Error t value Pr(>|t|)
(Intercept) 4.814e-03  2.958e-04   16.27   <2e-16 ***
E_1base$r1  1.829e-07  3.520e-10  519.61   <2e-16 ***
Residual standard error: 0.004337 on 398 degrees of freedom
Multiple R-squared: 0.9985,     Adjusted R-squared: 0.9985
F-statistic: 2.7e+05 on 1 and 398 DF,  p-value: < 2.2e-16
> mm = lm(E_1base_mean$t ~ E_1base_mean$r1); summary(mm)$r.squared
[1] 0.998752
       \endverbatim
       So we have r1 = 1.829e-07 * r1 - 4.814e-03 as predictor for t. </li>
       </li>
       <li> r1 vs conflicts: looks like a "cone" from the origin
       \verbatim
> plot(E_1base$r1, E_1base$cfs)
> points(E_1base_mean$r1, E_1base_mean$cfs, pch=3, cex=2)
> m = lm(E_1base$cfs ~ E_1base$r1)
> lines(E_1base$r1, predict(m))
> summary(m)
             Estimate Std. Error t value Pr(>|t|)
(Intercept) 6.181e+02  7.219e+01   8.562 2.46e-16 ***
E_1base$r1  3.081e-03  8.589e-05  35.869  < 2e-16 ***
Residual standard error: 1058 on 398 degrees of freedom
Multiple R-squared: 0.7637,     Adjusted R-squared: 0.7631
F-statistic:  1287 on 1 and 398 DF,  p-value: < 2.2e-16
> mm = lm(E_1base_mean$cfs ~ E_1base_mean$r1); summary(mm)$r.squared
[1] 0.6081624

> plot(E_1base_mean$r1, E_1base_mean$cfs)
       \endverbatim
       </li>
      </ul>
     </li>
     <li> minimum translation:
      <ul>
       <li> n, c and l vs r: strict linear relationship:
       \verbatim
> plot(E_min$r, E_min$n)
> m = lm(E_min$n ~ E_min$r)
> short_summary_lm(m)
              Estimate Std. Error    t value  Pr(>|t|)
(Intercept) 1.2000e+01 8.5093e-14 1.4102e+14 < 2.2e-16 ***
E_min$r     5.2000e+01 7.1034e-15 7.3204e+15 < 2.2e-16 ***
R-squared:     1
# Yielding the (exact) model: n = 52 * r + 12
> plot(E_min$r, E_min$c)
> m = lm(E_min$c ~ E_min$r)
> short_summary_lm(m)
              Estimate Std. Error    t value  Pr(>|t|)
(Intercept) 1.5280e-11 6.7494e-13 2.2638e+01 < 2.2e-16 ***
E_min$r     2.3200e+02 5.6343e-14 4.1176e+15 < 2.2e-16 ***
R-squared:     1
# Yielding the (exact) model: c = 232 * r
> plot(E_min$r, E_min$l)
> m = lm(E_min$l ~ E_min$r)
> short_summary_lm(m)
               Estimate  Std. Error     t value  Pr(>|t|)
(Intercept) -4.8000e+01  1.1405e-12 -4.2086e+13 < 2.2e-16 ***
E_min$r      7.1200e+02  9.5208e-14  7.4783e+15 < 2.2e-16 ***
R-squared:     1
# Yielding the (exact) model: l = 712 * r - 48
       \endverbatim
       </li>
       <li> rounds vs time: linear function with increasing variance;
       filling a triangle in the bottom left.
       \verbatim
> plot(E_min$r, E_min$t)
> points(E_min_mean$r, E_min_mean$t, pch=1, cex=3)
> m = lm(E_min$t ~ E_min$r)
> lines(E_min$r, predict(m))
> short_summary_lm(m)
              Estimate Std. Error t value Pr(>|t|)
(Intercept) -0.0269359  0.0111358 -2.4188  0.01602 *
E_min$r      0.0143109  0.0009296 15.3946  < 2e-16 ***
R-squared: 0.3732
> mm = lm(E_min_mean$t ~ E_min_mean$r)
> short_summary_lm(mm)
               Estimate Std. Error t value  Pr(>|t|)
(Intercept)  -0.0269359  0.0141215 -1.9074   0.07255 .
E_min_mean$r  0.0143109  0.0011788 12.1397 4.187e-10 ***
R-squared: 0.8912
       \endverbatim
       So we have t = 0.0143109 * r - 0.0269359 as predictor for t,
       with a high variance increasing with the number of rounds. </li>
       </li>
       <li> rounds vs r1: (very weak) linear relationship forming a
       triangle in the bottom left.
       \verbatim
# Upper bounding linear function
> E_min_max = aggregate(E_min, by=list(r=E_min$r), FUN=max)
> m = lm(E_min_max$r1 ~ E_min_max$r)
> summary(m)
            Estimate Std. Error t value Pr(>|t|)
(Intercept)  -120616     143265  -0.842    0.411
E_min_max$r   161304      11960  13.487 7.53e-11 ***
Residual standard error: 308400 on 18 degrees of freedom
Multiple R-squared:  0.91,	Adjusted R-squared: 0.905
F-statistic: 181.9 on 1 and 18 DF,  p-value: 7.526e-11

# Removing a lot of the variance due to the difference between keys
# yields a reasonable linear relationship on the average time per round
> E_min_mean = aggregate(E_min, by=list(r=E_min$r), FUN=mean)
> m = lm(E_min_mean$r1 ~ E_min_mean$r)
             Estimate Std. Error t value Pr(>|t|)
(Intercept)   -115238      68114  -1.692    0.108
E_min_mean$r    65442       5686  11.509 9.85e-10 ***
Residual standard error: 146600 on 18 degrees of freedom
Multiple R-squared: 0.8804,	Adjusted R-squared: 0.8737
F-statistic: 132.5 on 1 and 18 DF,  p-value: 9.854e-10
       \endverbatim
       </li>
       <li> r1 vs time: (strong) linear relationship:
       \verbatim
> m = lm(E_min$t ~ E_min$r1)
> summary(m)
             Estimate Std. Error t value Pr(>|t|)
(Intercept) 5.009e-03  5.473e-04   9.152   <2e-16 ***
E_min$r1    2.069e-07  6.312e-10 327.761   <2e-16 ***

Residual standard error: 0.008227 on 398 degrees of freedom
Multiple R-squared: 0.9963,	Adjusted R-squared: 0.9963
       \endverbatim
       </li>
       <li> r1 vs conflicts (strong) sub-linear relationship:
       \verbatim
> m = lm(log(E_min$cfs+1) ~ log(E_min$r1+1))
> summary(m)
                   Estimate Std. Error t value Pr(>|t|)
(Intercept)       -1.432645   0.073707  -19.44   <2e-16 ***
log(E_min$r1 + 1)  0.736170   0.005998  122.73   <2e-16 ***

Residual standard error: 0.2747 on 398 degrees of freedom
Multiple R-squared: 0.9743,	Adjusted R-squared: 0.9742
F-statistic: 1.506e+04 on 1 and 398 DF,  p-value: < 2.2e-16
       \endverbatim
       </li>
      </ul>
     </li>
    </ul>
   </li>
  </ul>


  \todo Comparison of run-times for the three translations
  <ul>
   <li> minisat-2.2.0:
    <ul>
     <li> Reading in experimental data:
     \verbatim
> git clone git://github.com/MGwynne/Experimental-data.git

> E_canon = read.table("Experimental-data/AES/1_3_4/ssaes_r1-20_c3_rw1_e4_f0_k1-20_aes_canon_box_aes_mc_bidirectional/MinisatStatistics",header=TRUE)
> E_1base = read.table("Experimental-data/AES/1_3_4/ssaes_r1-20_c3_rw1_e4_f0_k1-20_aes_1base_box_aes_mc_bidirectional/MinisatStatistics",header=TRUE)
> E_min = read.table("Experimental-data/AES/1_3_4/ssaes_r1-20_c3_rw1_e4_f0_k1-20_aes_min_box_aes_mc_bidirectional/MinisatStatistics",header=TRUE)

# Values averaged per round:
> E_canon_mean = aggregate(E_canon, by=list(r=E_canon$r), FUN=mean)
> E_1base_mean = aggregate(E_1base, by=list(r=E_1base$r), FUN=mean)
> E_min_mean = aggregate(E_min, by=list(r=E_min$r), FUN=mean)
     \endverbatim
     </li>
     <li> Comparing the (individual) run-times for the three translations:
      <ul>
       <li> Comparing the canonical and minimum translation:
        <ol>
	 <li> Time:
         \verbatim
> plot(E_canon$r, E_canon$t - E_min$t, , ylim=c(-max(abs(E_canon$t - E_min$t)), max(abs(E_canon$t - E_min$t))))
> m = lm(E_canon$t - E_min$t ~ E_canon$r)
> lines(E_canon$r, predict(m))
> summary(m)
              Estimate Std. Error t value Pr(>|t|)
(Intercept) -0.0002482  0.0202706  -0.012     0.99
E_canon$r    0.0085169  0.0016922   5.033 7.32e-07 ***
Residual standard error: 0.1951 on 398 degrees of freedom
Multiple R-squared: 0.05984,    Adjusted R-squared: 0.05748
F-statistic: 25.33 on 1 and 398 DF,  p-value: 7.323e-07
> mm = lm(E_canon_mean$t - E_min_mean$t ~ E_canon_mean$r)
> summary(mm)$r.squared
[1] 0.7233898
> points(E_canon_mean$r,E_canon_mean$t - E_min_mean$t, pch=1, cex=3)
         \endverbatim
	 </li>
	 <li> r1:
         \verbatim
> plot(E_canon$r, E_canon$r1 - E_min$r1, ylim=c(-max(abs(E_canon$r1 - E_min$r1)), max(abs(E_canon$r1 - E_min$r1))))
> m = lm(E_canon$r1 - E_min$r1 ~ E_canon$r)
> lines(E_canon$r, predict(m))
> summary(m)
            Estimate Std. Error t value Pr(>|t|)
(Intercept)  -177602     131064  -1.355    0.176
E_canon$r      92916      10941   8.492 4.07e-16 ***
Residual standard error: 1262000 on 398 degrees of freedom
Multiple R-squared: 0.1534,     Adjusted R-squared: 0.1513
F-statistic: 72.12 on 1 and 398 DF,  p-value: 4.073e-16
> mm = lm(E_canon_mean$r1 - E_min_mean$r1 ~ E_canon_mean$r)
> summary(mm)$r.squared
[1] 0.8788695
> points(E_canon_mean$r,E_canon_mean$r1 - E_min_mean$r1, pch=1, cex=3)
         \endverbatim
         </li>
         <li> cfs:
         \verbatim
> plot(E_canon$r, E_canon$cfs - E_min$cfs, ylim=c(-max(abs(E_canon$cfs - E_min$cfs)), max(abs(E_canon$cfs - E_min$cfs))))
> m = lm(E_canon$cfs - E_min$cfs ~ E_canon$r)
> lines(E_canon$r, predict(m))
> summary(m)
            Estimate Std. Error t value Pr(>|t|)
(Intercept)   567.49     286.36   1.982   0.0482 *
E_canon$r    -165.61      23.91  -6.928 1.73e-11 ***
Residual standard error: 2757 on 398 degrees of freedom
Multiple R-squared: 0.1076,     Adjusted R-squared: 0.1054
F-statistic:    48 on 1 and 398 DF,  p-value: 1.727e-11
> mm = lm(E_canon_mean$cfs - E_min_mean$cfs ~ E_canon_mean$r); summary(mm)$r.squared
[1] 0.6867762
> points(E_canon_mean$r,E_canon_mean$cfs - E_min_mean$cfs, pch=1, cex=3)
         \endverbatim
         </li>
        </ol>
       </li>
       <li> Comparing the 1-base and minimum:
       \verbatim
> plot(E_1base$r, E_1base$t - E_min$t, ylim=c(-max(abs(E_1base$t - E_min$t)), max(abs(E_1base$t - E_min$t))))
> m = lm(E_1base$t - E_min$t ~ E_1base$r)
> lines(E_1base$r, predict(m))
> summary(m)
(Intercept)  0.019724   0.012769   1.545  0.12324
E_1base$r   -0.003208   0.001066  -3.009  0.00279 **
Residual standard error: 0.1229 on 398 degrees of freedom
Multiple R-squared: 0.02224,    Adjusted R-squared: 0.01979
F-statistic: 9.054 on 1 and 398 DF,  p-value: 0.002787
> mm = lm(E_1base_mean$t - E_min_mean$t ~ E_1base_mean$r); summary(mm)$r.squared
[1] 0.2207844


> plot(E_1base$r, E_1base$r1 - E_min$r1, ylim=c(-max(abs(E_1base$r1 - E_min$r1)), max(abs(E_1base$r1 - E_min$r1))))
> m = lm(E_1base$r1 - E_min$r1 ~ E_1base$r)
> lines(E_1base$r, predict(m))
> summary(m)
(Intercept)    44300      65963   0.672    0.502
E_1base$r      -4236       5506  -0.769    0.442
Residual standard error: 635000 on 398 degrees of freedom
Multiple R-squared: 0.001485,   Adjusted R-squared: -0.001024
F-statistic: 0.5918 on 1 and 398 DF,  p-value: 0.4422
> mm = lm(E_1base_mean$r1 - E_min_mean$r1 ~ E_1base_mean$r); summary(mm)$r.squared
[1] 0.02052002

> plot(E_1base$r, E_1base$cfs - E_min$cfs, ylim=c(-max(abs(E_1base$cfs - E_min$cfs)), max(abs(E_1base$cfs - E_min$cfs))))
> m = lm(E_1base$cfs - E_min$cfs ~ E_1base$r)
> lines(E_1base$r, predict(m))
> summary(m)
(Intercept)   558.57     285.90   1.954   0.0514
E_1base$r    -159.34      23.87  -6.676 8.25e-11 ***
Residual standard error: 2752 on 398 degrees of freedom
Multiple R-squared: 0.1007,     Adjusted R-squared: 0.09845
F-statistic: 44.57 on 1 and 398 DF,  p-value: 8.254e-11
> mm = lm(E_1base_mean$cfs - E_min_mean$cfs ~ E_1base_mean$r); summary(mm)$r.squared
[1] 0.5608833
       \endverbatim
       </li>
       <li> Comparing the 1-base and minimum:
       \verbatim
> plot(E_1base$r, E_1base$t - E_canon$t, ylim=c(-max(abs(E_1base$t - E_canon$t)), max(abs(E_1base$t - E_canon$t))))
> m = lm(E_1base$t - E_canon$t ~ E_1base$r)
> lines(E_1base$r, predict(m))
> summary(m)
             Estimate Std. Error t value Pr(>|t|)
(Intercept)  0.019972   0.019726   1.012    0.312
E_1base$r   -0.011724   0.001647  -7.120 5.08e-12 ***
Residual standard error: 0.1899 on 398 degrees of freedom
Multiple R-squared: 0.113,      Adjusted R-squared: 0.1108
F-statistic: 50.69 on 1 and 398 DF,  p-value: 5.08e-12
> mm = lm(E_1base_mean$t - E_canon_mean$t ~ E_canon_mean$r); summary(mm)$r.squared
[1] 0.6872132

> plot(E_1base$r, E_1base$r1 - E_canon$r1, ylim=c(-max(abs(E_1base$r1 - E_canon$r1)), max(abs(E_1base$r1 - E_canon$r1))))
> m = lm(E_1base$r1 - E_canon$r1 ~ E_1base$r)
> lines(E_1base$r, predict(m))
> summary(m)
            Estimate Std. Error t value Pr(>|t|)
(Intercept)   221902     130185   1.705   0.0891 .
E_1base$r     -97152      10868  -8.940   <2e-16 ***
Residual standard error: 1253000 on 398 degrees of freedom
Multiple R-squared: 0.1672,     Adjusted R-squared: 0.1651
F-statistic: 79.92 on 1 and 398 DF,  p-value: < 2.2e-16
> mm = lm(E_1base_mean$r1 - E_canon_mean$r1 ~ E_canon_mean$r); summary(mm)$r.squared
[1] 0.7871271


> plot(E_1base$r, E_1base$cfs - E_canon$cfs, ylim=c(-max(abs(E_1base$cfs - E_canon$cfs)), max(abs(E_1base$cfs - E_canon$cfs))))
> m = lm(E_1base$cfs - E_canon$cfs ~ E_1base$r)
> lines(E_1base$r, predict(m))
> summary(m)
            Estimate Std. Error t value Pr(>|t|)
(Intercept)   -8.912    251.938  -0.035    0.972
E_1base$r      6.271     21.031   0.298    0.766
Residual standard error: 2425 on 398 degrees of freedom
Multiple R-squared: 0.0002234,  Adjusted R-squared: -0.002289
F-statistic: 0.08892 on 1 and 398 DF,  p-value: 0.7657
> mm = lm(E_1base_mean$cfs - E_canon_mean$cfs ~ E_canon_mean$r); summary(mm)$r.squared
[1] 0.002643576
       \endverbatim
       </li>
      </ul>
     </li>
    </ul>
   </li>
  </ul>


  \todo Minisat-2.2.0
  <ul>
   <li> Solving the key discovery problem over rounds 1 to 20. </li>
   <li> The environment for all of these experiments is:
   \verbatim
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 23
model name	: Intel(R) Core(TM)2 Duo CPU     E8400  @ 3.00GHz
cpu MHz		: 2003.000
cache size	: 6144 KB
bogomips	: 5999.94

processor	: 1
vendor_id	: GenuineIntel
cpu family	: 6
model		: 23
model name	: Intel(R) Core(TM)2 Duo CPU     E8400  @ 3.00GHz
cpu MHz		: 2003.000
cache size	: 6144 KB
bogomips	: 5999.64
address sizes	: 36 bits physical, 48 bits virtual
             total       used       free     shared    buffers     cached
Mem:          3947       3363        583          0        165       3077
   \endverbatim
   </li>
   <li> The canonical box translation:
    <ul>
     <li> The data:
     \verbatim
shell> r_max=20; s_max=5000;
shell> for r in $(seq 1 ${r_max}); do for s in $(seq 1 ${s_max}); do RunMinisat r${r}_k${s}.cnf; done; done
shell> (ExtractMinisat header-only |  awk " { print \$0 \" r s\"}"; for r in $(seq 1 ${r_max}); do for s in $(seq 1 ${s_max}); do
    cat ExperimentMinisat_r${r}_k${s}cnf_*/Statistics | tail -n 1 | awk " { print \$0 \" ${r} ${s}\"}";
  done;
done) > MinisatStatistics
shell> oklib --R
R> E = read.table("MinisatStatistics", header=TRUE)
R> aggregate(E, by=list(r=E$r), FUN=mean)
 r    n     c     l           t       cfs       dec     rts           r1        cfl
 1  128   724  2000 0.001714851    9.6620   17.9842  1.0000     580.8164    60.8848
 2  244  1448  4048 0.005310922  136.2558  179.0542  1.8132   11059.7788  1951.9632
 3  360  2172  6096 0.013412875  589.2922  755.5184  4.7504   44106.7312  8399.7434
 4  476  2896  8144 0.056125769 2427.5876 3004.9056 13.7882  232566.9866 45201.8218
 5  592  3620 10192 0.093324322 2166.1512 2485.8716 12.6348  499074.2818 44888.5274
 6  708  4344 12240 0.121380846 2367.8182 2730.6476 13.5466  695770.3570 46812.0854
 7  824  5068 14288 0.144844891 2537.4450 2929.7844 14.2698  862526.5380 45730.4996
 8  940  5792 16336 0.173685905 2793.8526 3223.5978 15.3584 1051323.9708 48758.0272
 9 1056  6516 18384 0.192543428 2770.4374 3194.2486 15.1986 1191376.8612 46912.5372
10 1172  7240 20432 0.212637779 2776.3278 3211.0058 15.1994 1330393.8994 46976.2800
11 1288  7964 22480 0.229672784 2717.8800 3130.9544 14.9580 1454783.5706 45897.7590
12 1404  8688 24528 0.254079681 2751.4800 3182.4828 15.1300 1625304.8030 46384.5044
13 1520  9412 26576 0.275816171 2761.0856 3188.2470 15.1674 1785505.2208 45984.1052
14 1636 10136 28624 0.292813789 2764.8900 3178.8502 15.2316 1940283.5768 42679.6064
15 1752 10860 30672 0.320477384 2846.9046 3268.4632 15.5838 2119659.8186 45370.1550
16 1868 11584 32720 0.330626839 2721.3424 3127.2188 15.0342 2204883.6194 43332.2112
17 1984 12308 34768 0.356421922 2739.6872 3137.8350 15.1046 2411890.3160 43167.8400
18 2100 13032 36816 0.382137415 2812.9192 3231.6404 15.4006 2582191.3248 45121.6630
19 2216 13756 38864 0.400623184 2821.6118 3248.2956 15.4298 2710239.5174 45229.8642
20 2332 14480 40912 0.431657473 2927.5514 3391.1398 15.7922 2887636.0340 47893.6852
     \endverbatim
     </li>
    </ul>
   </li>
   <li> The "minimum" box translation:
    <ul>
     <li> The data:
     \verbatim
shell> r_max=20; s_max=5000;
shell> for r in $(seq 1 ${r_max}); do for s in $(seq 1 ${s_max}); do RunMinisat r${r}_k${s}.cnf; done; done
shell> (ExtractMinisat header-only |  awk " { print \$0 \" r s\"}"; for r in $(seq 1 ${r_max}); do for s in $(seq 1 ${s_max}); do
    cat ExperimentMinisat_r${r}_k${s}cnf_*/Statistics | tail -n 1 | awk " { print \$0 \" ${r} ${s}\"}";
  done;
done) > MinisatStatistics
shell> oklib --R
R> E = read.table("MinisatStatistics", header=TRUE)
R> aggregate(E, by=list(r=E$r), FUN=mean)
 r    n    c     l           t       cfs       dec     rts           r1        cfl
 1   64  232   664 0.001070232   14.0248   19.1068  1.0000     293.2758    53.7914
 2  116  464  1376 0.002557242  146.0434  163.5488  1.8884    4934.2322  1013.4466
 3  168  696  2088 0.009440481  881.8998  992.5432  6.3120   31012.5752  7291.1932
 4  220  928  2800 0.026376094 2325.5392 2577.8366 13.0560  112758.6750 22217.2894
 5  272 1160  3512 0.048504134 2576.3772 2859.8044 14.0790  234276.7970 29849.2366
 6  324 1392  4224 0.065723319 3022.1352 3410.3350 15.9582  321484.9308 34255.2064
 7  376 1624  4936 0.076303298 3105.1848 3539.3898 16.3138  374136.7616 34832.3944
 8  428 1856  5648 0.092317667 3387.9744 3922.5488 17.5070  448673.4138 38039.5404
 9  480 2088  6360 0.101019548 3392.3770 3978.6082 17.5516  491490.0892 37768.8416
10  532 2320  7072 0.112618379 3510.9318 4213.6252 18.1934  538628.3310 39249.4476
11  584 2552  7784 0.124018845 3636.8154 4447.3132 18.6996  592558.5392 40793.9894
12  636 2784  8496 0.137712370 3836.9176 4752.8894 19.5730  656638.4360 43141.2800
13  688 3016  9208 0.149305801 4019.4104 5117.3816 20.3024  706971.6146 45599.6104
14  740 3248  9920 0.166107652 4282.5722 5559.0916 21.4454  775229.3576 49128.9538
15  792 3480 10632 0.177769077 4440.7568 5836.1232 22.0588  824135.8872 51191.2706
16  844 3712 11344 0.197220122 4861.4238 6473.2960 23.7832  906477.6336 56131.5462
17  896 3944 12056 0.214749256 5146.3752 6928.0306 24.8722  983458.5828 60437.9974
18  948 4176 12768 0.231643884 5413.4056 7373.8464 25.9022 1054425.5506 63866.8024
19 1000 4408 13480 0.247624255 5759.7484 8010.1198 27.3120 1120220.9396 68477.1612
20 1052 4640 14192 0.267402052 6104.0708 8511.6910 28.6250 1197680.5836 73567.2786
     \endverbatim
     </li>
    </ul>
   </li>
   <li> The 1-base box translation:
    <ul>
     <li> The data:
     \verbatim
shell> r_max=20; s_max=5000;
shell> for r in $(seq 1 ${r_max}); do for s in $(seq 1 ${s_max}); do RunMinisat r${r}_k${s}.cnf; done; done
shell> (ExtractMinisat header-only |  awk " { print \$0 \" r s\"}"; for r in $(seq 1 ${r_max}); do for s in $(seq 1 ${s_max}); do
    cat ExperimentMinisat_r${r}_k${s}cnf_*/Statistics | tail -n 1 | awk " { print \$0 \" ${r} ${s}\"}";
  done;
done) > MinisatStatistics
shell> oklib --R
R> E = read.table("MinisatStatistics", header=TRUE)
R> aggregate(E, by=list(r=E$r), FUN=mean)
 r    n    c     l           t       cfs       dec     rts           r1        cfl
 1   64  252   720 0.001042045   11.4232   16.0914  1.0000     289.3598    40.0822
 2  116  504  1488 0.002444439  124.5410  137.7208  1.7348    4461.3792   875.1974
 3  168  756  2256 0.006926061  526.4488  578.0386  4.3808   21108.9450  4165.8018
 4  220 1008  3024 0.021692411 1767.7824 1943.9376 10.6592   88582.9910 16514.8640
 5  272 1260  3792 0.045123248 2189.1096 2406.6092 12.5716  216494.2226 26708.5480
 6  324 1512  4560 0.060651071 2553.7336 2858.4154 14.0864  299520.6852 30520.0622
 7  376 1764  5328 0.074245617 2724.2428 3063.8020 14.7512  371442.7210 32172.3694
 8  428 2016  6096 0.089152354 2915.9180 3285.6822 15.5270  452167.8292 34074.0596
 9  480 2268  6864 0.099106639 2893.6372 3267.3224 15.4932  505336.5214 33841.0956
10  532 2520  7632 0.107022635 2818.4310 3190.9598 15.2168  548560.9996 33070.6954
11  584 2772  8400 0.116655180 2802.6284 3175.0258 15.1258  603956.4388 32872.9664
12  636 3024  9168 0.126150323 2790.9882 3161.9816 15.1026  657245.5288 32774.2238
13  688 3276  9936 0.135061974 2753.4974 3126.2918 14.9604  707519.0370 32372.0376
14  740 3528 10704 0.143954624 2718.6530 3096.2852 14.8430  757481.4892 31889.8674
15  792 3780 11472 0.154266854 2726.8592 3102.6428 14.9090  816101.3738 31944.9208
16  844 4032 12240 0.161963682 2669.7362 3044.8086 14.7508  869258.6482 30711.2306
17  896 4284 13008 0.178497964 2684.7054 3038.6192 14.8192  981726.6584 30945.6232
18  948 4536 13776 0.188807001 2754.5634 3136.1468 15.1474 1027851.3072 32066.8498
19 1000 4788 14544 0.194174181 2741.0686 3138.6022 15.0672 1043137.5356 32131.2224
20 1052 5040 15312 0.204566399 2766.1018 3168.7010 15.0972 1100981.2522 32365.6258
     \endverbatim
     </li>
     <li> Total times and conflicts over 20 rounds and keys:
     \verbatim
1_3_4> oklib --R
R> E_canon = read.table(Sys.glob("ssaes_r1-20_c*_aes_canon_box*/MinisatStatistics")[1], header=TRUE)
R> E_1base = read.table(Sys.glob("ssaes_r1-20_c*_aes_1base_box*/MinisatStatistics")[1], header=TRUE)
R> E_min = read.table(Sys.glob("ssaes_r1-20_c*_aes_min_box*/MinisatStatistics")[1], header=TRUE)
R> options(width=1000)
R> sum(E_canon$t); sum(E_1base$t); sum(E_min$t)
[1] 85.00288
[1] 43.74914
[1] 49.3313
R> sum(E_canon$cfs); sum(E_1base$cfs); sum(E_min$cfs)
[1] 928968
[1] 951743
[1] 1397543
     \endverbatim
     </li>
    </ul>
   </li>
  </ul>

*/
