// Oliver Kullmann, 23.5.2009 (Swansea)
/* Copyright 2009, 2010 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Experimentation/Investigations/RamseyTheory/GreenTaoProblems/plans/GreenTao_3-3-4-k.hpp
  \brief On investigations into Green-Tao numbers greentao_3(3,4,k)

  Aloamo-translations are generated by output_greentao_stdname([3,4,k],n) at
  Maxima-level, and by "GTSat 3 4 k n" at C++ level.

  Standard nested translations are generated by
  output_greentao_standnest_stdname([3,4,k],n) resp.
  output_greentao_standnest_strong_stdname([3,4,k],n).
  

  \todo greentao_3(3,4,4) > 1662
  <ul>
   <li> Creating problems via output_greentao_stdname([3,4,4],n). </li>
   <li> n=500 trivially satisfiable (adaptnovelty+). </li>
   <li> n=600 trivially satisfiable. </li>
   <li> n=700 trivially satisfiable. </li>
   <li> n=900 trivially satisfiable. </li>
   <li> n=1000 trivially satisfiable. </li>
   <li> n=1100 still easy to solve (cutoff=100*10^3). </li>
   <li> n=1200 still easy to solve (cutoff=10^6). </li>
   <li> n=1300 rather easy to solve (cutoff=10^6). </li>
   <li> n=1400: one solution in 10 runs with cutoff=10^6. </li>
   <li> n=1500: only min=3 for 10 runs with cutoff=10*10^6; cutoff=100*10^6
   found a solution in the third run (osteps=39412430, seed=1928236138). </li>
   <li> n=1512: one run in 10 with cutoff=100*10^6 found a solution
   (osteps=37551993, seed=4046775428). While another 100 runs with this
   cutoff actually found no solution. </li>
   <li> n=1518
    <ol>
     <li> 9 runs with cutoff=100*10^6 yield only a minimum of 2. </li>
     <li> cutoff=500*10^6: run 18 found a solution (osteps=309459026,
     seed=3122222825). </li>
    </ol>
   </li>
   <li> n=1525
    <ol>
     <li> 10 runs with cutoff=100*10^6 yield only min=2. </li>
     <li> cutoff=500*10^6: run 16 yields a solution (msteps=375313903,
     seed=2274305602). </li>
    </ol>
   </li>
   <li> n=1531: cutoff=5*10^8 yields a solution (seed=1692755539) in
   run 12. </li>
   <li> n=1532
    <ol>
     <li> cutoff=5*10^8 yields in 10 runs only once min=1. </li>
     <li> cutoff=10^9 yields in run 15 a solution (seed=1453937791). </li>
    </ol>
   </li>
   <li> n=1534
    <ol>
     <li> cutoff=5*10^8 yields in 23 runs only 4 times min=1. </li>
     <li> cutoff=10^9 yields in run 6 a solution (seed=1913394293). </li>
    </ol>
   </li>
   <li> n=1535
    <ol>
     <li> cutoff=10^9 yields in 9 runs only min=2. </li>
     <li> cutoff=2*10^9 yields in run 18 a solution (seed=238771004,
     osteps=47373687). </li>
    </ol>
   </li>
   <li> n=1537
    <ol>
     <li> 16 runs with cutoff=5*10^8 only yield min=1 twice. </li>
     <li> cutoff=10^9 yields in 12 runs min=1 twice, so a cutoff of
     2*10^9 would be needed. </li>
     <li> cutoff=10^8, 1000 runs: In run 213 a solution was found
     (seed=2884500780, osteps=42486702). </li>
    </ol>
   </li>
   <li> n=1538
    <ol>
     <li> cutoff=10^9: 2 solutions found with 214 runs (seed=1006777768,
     osteps=507922529). </li>
    </ol>
   </li>
   <li> n=1539
    <ol>
     <li> cutoff=10^9: one solution found in 34 runs (seed=2866671762,
     osteps=167931793). </li>
    </ol>
   </li>
   <li> n=1540: cutoff=10^9 found two solutions in 164 runs (seed=163883519,
   osteps=337015990). </li>
   <li> n=1541
    <ol>
     <li> cutoff=10^9 (adaptnovelty+):
     \verbatim
> E = read_ubcsat("GreenTao_3-3-4-4_1541.cnf_OUT")
 1  2  3  5
 2 13  1  1
17
> summary(E$osteps)
     Min.   1st Qu.    Median      Mean   3rd Qu.      Max.
204200000 287600000 469700000 496300000 700700000 900400000
     \endverbatim
     </li>
     <li> Further 51 runs found one solution (seed=1306721667,
     osteps=428867613). </li>
    </ol>
   </li>
   <li> n=1542: cutoff=10^9 (adaptnovelty+): one solution found in 148
   runs (seed=1219495006, osteps=466488791). </li>
   <li> n=1543: cutoff=10^9: in 474 runs one solution was found
   (seed=2142163637, osteps=918202991). It seems we need to double the
   cutoff. </li>
   <li> n=1544: cutoff=2*10^9
   \verbatim
  1   2   3
 41 137   6
184
  0   1   2   3   4
  1  63 261  22   1
348
   \endverbatim
   (seed=2955200386, osteps=664563809). </li>
   <li> n=1545:
    <ol>
     <li> aloamo, adaptnovelty+, cutoff=2*10^9:
     \verbatim
 1  2  3
13 35  4
52
 1  2  3
28 87  8
123
     \endverbatim
     </li>
     <li> Weak standard nested, rnovelty+, cutoff=10^7: found a solution
     in the first run (seed=1652015207, osteps=1816932). </li>
    </ol>
   </li>
   </li>
   <li> n=1550
    <ol>
     <li> Looks (at first sight) unsatisfiable: 10 runs with
     cutoff=10^8 yield min=3 (twice; so cutoff=10^9 would be needed). </li>
     <li> cutoff=5*10^8: 13 runs only yield min=2, so a cutoff of 2.5*10^9
     would be needed. </li>
     <li> cutoff=10^8, 1000 runs yields
     \verbatim
> E = read_ubcsat("GreenTao_3-3-4-4_1550.cnf_OUT")
  1   2   3   4   5   6   7   8   9
  1  17  75 123 166 241 232 133  12
1000
     \endverbatim
     so perhaps 100 * 1000 runs would be needed to find a solution. </li>
     <li> cutoff = 10^9 yields
     \verbatim
 1  2  3  4  5  6
 5 46 35  6  6  2
100
     \endverbatim
     <li> Weak standard nested, rnovelty+, cutoff=10^7:
     \verbatim
> E=read_ubcsat("GreenTao_N_3-3-4-4_1550.cnf_OUT1")
  0   1   2   3
243 212  42   3
500
> summary(E$osteps[E$min==0])
   Min. 1st Qu.  Median    Mean 3rd Qu.    Max.
 599300 3286000 4930000 5318000 7516000 9961000
     \endverbatim
     </li>
    </ol>
   </li>
   <li> n=1600: Weak standard nested, rnovelty+, cutoff=10^7 found a solution
   in run 21 (seed=2913780691, osteps=8089572). </li>
   <li> n=1650:
    <ol>
     <li> Weak standard nested, rnovelty+, cutoff=10^7:
     \verbatim
 2  3  4  5  6  7  8  9 10 11 12 13 14 15 16
 3  3 20 29 56 68 86 77 50 50 26 12  9 10  1
500
     \endverbatim
     </li>
     <li> cutoff=2*10^7:
     \verbatim
 0  2  3  4  5  6  7  8  9 10 11 12 13
 1  1 14 41 57 84 68 51 32 11  5  3  1
369
     \endverbatim
     (seed=3892552022, osteps=16215921). </li>
     <li> Best local search algorithm from Ubcsat-suite:
     \verbatim
E = run_ubcsat("GreenTao_N_3-3-4-4_1650.cnf", runs=200,cutoff=1000000)
     \endverbatim
     evaluated by plot(E$alg,E$best):
     \verbatim
> table(E$best[E$alg=="rnoveltyp"])
 6  7  8  9 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32
 1  1  2  3  8  3  4  9 11  8 14 12 18 17 12 13  8 12  9  3  6  7  6  4  5  1
33 37
 2  1
> table(E$best[E$alg=="rnovelty"])
 8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33
 1  1  5  4  6 11  6  9  7 12  7 13 15 10 11 14 14  9  6  8 11  3  4  7  1  1
34 35 40
 2  1  1
> table(E$best[E$alg=="walksat_tabu"])
12 15 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39
 1  1  1  2  1  1  6  4 13 13 19 17 14 14 19 19 13  9  7  9  6  6  1  3  1
     \endverbatim
     confirming that rnovelty+ seems best here. </li>
    </ol>
   </li>
   <li> n=1660: weak standard nested translation, rnovelty+ with
   cutoff=16*10^7 found in 157 runs one solution (seed=3193141014,
   osteps=87677992), while with cutoff=32*10^7 in 39 runs only min=2 was
   reached. </li>
   <li> n=1661: weak standard nested translation, rnovelty+
    <ol>
     <li> cutoff=32*10^7:
     \verbatim
 2  3  4  5
12 40 40  7
99
 1  2  3  4  5  6
 1 17 62 48 10  2
140
     \endverbatim
     </li>
     <li> cutoff=64*10^7
     \verbatim
 1  2  3  4
 2 12 23  7
48
     \endverbatim
     In further 15 runs one solution was found (seed=3028693870,
     osteps=187092298). </li>
    </ol>
   </li>
   <li> n=1662: weak standard nested translation, rnovelty+, cutoff=64*10^7
   found a solution in 38 runs (seed=1319314469, seed=298802296). </li>
   <li> n=1663: weak standard nested translation, rnovelty+
    <ol>
     <li> cutoff=64*10^7
     \verbatim
  1   2   3   4   5
  9  63 131  50   5
258
  1   2   3   4   5
  4  61 150  74   2
291
     \endverbatim
     </li>
     <li> cutoff=10^9
     \verbatim
 1  2  3  4
 3 19 20  1
43
     \endverbatim
     </li>
    </ol>
   </li>
   <li> n=1665: weak standard nested translation, rnovelty+
    <ol>
     <li> cutoff=16*10^7:
     \verbatim
 2  3  4  5  6  7  8
 1  9 32 22  5  1  1
71
 1  2  3  4  5  6  7
 1  5 24 33 23  4  1
91
     \endverbatim
     </li>
     <li> cutoff=32*10^7:
     \verbatim
 1  2  3  4  5  6
 3 24 68 51 17  2
165
     \endverbatim
     </li>
    </ol>
   </li>
   <li> n=1670
    <ol>
     <li> Weak standard nested, rnovelty+, cutoff=2*10^7:
     \verbatim
 1  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17
 1  3  8 17 37 50 69 69 91 51 42 35 12 10  4  1
500
     \endverbatim
     </li>
     <li> rnovelty+, cutoff=4*10^7:
     \verbatim
 3  4  5  6  7  8  9 10 11 14
 2  4 17 21 35 26 14 12  7  1
139
     \endverbatim
     </li>
     <li> rnovelty, cutoff=4*10^7:
     \verbatim
  2   3   4   5   6   7   8   9  10  11  12  13  14  15
  2   4  23  37  82 117  98  77  34  19   3   2   1   1
500
     \endverbatim
     </li>
     <li> rnovelty+, cutoff=8*10^7:
     \verbatim
  2   3   4   5   6   7   8   9  10
  6  21  36 121 137 108  47  21   3
500
     \endverbatim
     </li>
     <li> rnovelty, cutoff=8*10^7:
     \verbatim
 3  4  5  6  7  8  9 10 11
 5 15 29 45 21 16  7  2  1
141
     \endverbatim
     So rnovelty+ seems better. </li>
     <li> rnovelty+, cutoff=16*10^7:
     \verbatim
  2   3   4   5   6   7   8
  7  46 131 146 118  41   9
498
  1   2   3   4   5   6   7   8
  3   6  30 126 125  73  34   4
401
     \endverbatim
     </li>
     <li> rnovelty+, cutoff=32*10^7:
     \verbatim
 1  2  3  4  5  6  7
 2 10 21 55 45  8  1
142
     \endverbatim
     </li>
     <li> adaptnovelty+, cutoff=16*10^7:
     \verbatim
 5  7  8  9 10 11 13
 2  5  3  7  5  6  1
29
     \endverbatim
     Looks inappropriate. </li>
    </ol>
   </li>
  </ul>


  \todo greentao_3(3,4,5) > 8300
  <ul>
   <li> n=1000 trivial for adaptnovelty+. </li>
   <li> n=2000 trivial for adaptnovelty+ (70% success with cutoff=10^4). </li>
   <li> n=2200 trivial for adaptnovelty+ (70% success with cutoff=10^4). </li>
   <li> n=3000 trivial for adaptnovelty+ (90% success with cutoff=10^5). </li>
   <li> n=4000 simple for adaptnovelty+ (100% success with cutoff=10^6). </li>
   <li> n=5000 simple for adaptnovelty+ (40% success with cutoff=10^6). </li>
   <li> n=6000 simple for adaptnovelty+ (100% success with cutoff=10^7). </li>
   <li> n=7000
    <ol>
     <li> cutoff=10^7 yields min=4 in 10 runs. </li>
     <li> cutoff=10^8: 100% success. </li>
    </ol>
   </li>
   <li> n=7250: cutoff=10^8 found a solution in run 2 (seed=2722596453,
   osteps=65636246). </li>
   <li> n=7375: cutoff=10^8 found one solution in 20 runs (seed=161549167,
   osteps=73817861). </li>
   <li> n=7438: cutoff=10^8 found two solutions in 77 runs (seed=3688103311,
   osteps=67497802). </li>
   <li> n=7479: cutoff=10^8 finds a solution (seed=1752281516,
   osteps=79570476). </li>
   <li> n=7490:  cutoff=10^8 finds one solution in 40 runs (seed=1381313198,
   osteps=32116058). </li>
   <li> n=7500:
    <ol>
     <li> cutoff=10^8:
     \verbatim
> ubcsat-okl -alg adaptnovelty+ -runs 100 -cutoff 100000000 -i GreenTao_3-3-4-5_7500.cnf | tee GreenTao_3-3-4-5_7500.cnf_OUT
> E=read_ubcsat("GreenTao_3-3-4-5_7500.cnf_OUT")
 2  4  5  7  8  9 10 12 13 14 16 18 19
 1  5  3  2  3  1  1  1  1  1  2  1  2
24
> summary(E$osteps)
    Min.  1st Qu.   Median     Mean  3rd Qu.     Max.
20480000 65180000 73430000 70900000 84870000 98250000
     \endverbatim
     </li>
     <li> In further 110 runs one solution was found (seed=173131959,
     cutoff=85955523). </li>
     <li> Let's increase the cutoff to 2*10^8. </li>
    </ol>
   </li>
   <li> n=7600, cutoff=2*10^8 (adaptnovelty+): in 249 runs one solution was
   found (seed=3054809508, osteps=165824921). It seems one should double
   the cutoff. </li>
   <li> n=7650
    <ol>
     <li> cutoff=4*10^8 (adaptnovelty+, aloamo):
     \verbatim
 2  5  6  7  8  9 10 11 12 14 15
 1  2  4  2  1  3  4  2  2  3  2
26
 2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17
 1  4  8  1  7  4 10  9 15 18 11  2  4  1  2  3
100
     \endverbatim
     </li>
     <li> Weak standard nested translation, rnovelty+, cutoff=10^6 finds a
     solution in the first run (seed=1527646207, osteps=920073). </li>
    </ol>
   </li>
   <li> n=7700
    <ol>
     <li> aloamo, cutoff=4*10^8 (adaptnovelty+):
     \verbatim
 3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 21
 1  1  2  3  6  5  4  9 12 12 13 10  3  5  5  7  1  1
100
 5  6  7  8  9 10 11 12 13 14 15 16 17 19
 1  3  4  8  9 12 10 10 10 14  4  9  5  1
100
 3  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21
 1  1  2  2  3 10 13  7 10  8 12  6 12  3  2  3  2  3
100
     \endverbatim
     </li>
     <li> Weak standard nested translation, rnovelty+, cutoff=2*10^6:
     \verbatim
 1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 18 23 26
 5  2 18 18 19 21 23 29 22 10 11  8  5  2  7  1  1  1
203
     \endverbatim
     while with cutoff=4*10^6 two solutions were found in 7 runs
     (seed=1076160763, osteps=3425039). </li>
    </ol>
   </li>
   <li> n=7750, weak standard nested translation, rnovelty+, cutoff=4*10^6:
   In 92 runs 5 solutions were found (seed=3051660126, osteps=2154632). </li>
   <li> n=7900, weak standard nested translation, rnovelty+, cutoff=8*10^6:
   In 60 runs one solution was found (seed=2495938585, osteps=4986167). </li>
   <li> n=8000
    <ol>
     <li> cutoff=10^8, aloamo:
     \verbatim
> ubcsat-okl -alg adaptnovelty+ -runs 100 -cutoff 100000000 -i GreenTao_3-3-4-5_8000.cnf | tee GreenTao_3-3-4-5_8000.cnf_OUT
> E=read_ubcsat("GreenTao_3-3-4-5_8000.cnf_OUT")
24 26 27 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 51 53
 1  3  1  1  3  5  3  1  5  2  4  4  1  4  1  5  3  5  2  2  3  5  1  4  2  1
58
 1
73
> summary(E$osteps)
    Min.  1st Qu.   Median     Mean  3rd Qu.     Max.
15540000 37710000 68590000 64060000 84820000 99420000
     \endverbatim
     looks unsatisfiable (although one might try cutoff=2*10^8). </li>
     <li> 
     <li> Weak standard nested translation, rnovelty+, cutoff=16*10^6 find in
     6 runs one solution (seed=3908229136, osteps=11449398). </li>
    </ol>
   </li>
   <li> n=8100, weak standard nested translation, rnovelty+
    <ol>
     <li> cutoff=16*10^6: found in 91 runs no solution. </li>
     <li> cutoff=32*10^6: found in 39 runs two solutions (seed=2882427028,
     osteps=23392210). </li>
    </ol>
   </li>
   <li> n=8200, weak standard nested translation, rnovelty+
    <ol>
     <li> cutoff=32*10^6:
     \verbatim
 3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 19 20 24
 2  1  6  1  7  9  7  5  2  9 10  1  2  2  3  2  1  1
71
     \endverbatim
     Using cutoff=64*10^6, in run 10 a solution was found (seed=2296183965,
     cutoff=20180202). </li>
    </ol>
   </li>
   <li> n=8250, weak standard nested translation, rnovelty, cutoff=2*10^8 </li>
   <li> n=8300, weak standard nested translation, rnovelty+
    <ol>
     <li> cutoff=32*10^6:
     \verbatim
 5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30
 1  1  1  1  1  2  3  6  3  2  1  6  3  5  5  4  1  1  3  5  1  1  1  2  2  1
31 33
 1  3
67
 7  8  9 10 11 12 13 14 15 16 17 19 20 21 22 23 25 27 28 29 32
 1  1  2  5  1  1  3  3  5  5  5  2  3  1  2  1  2  1  1  2  1
48
 5  9 10 11 12 13 14 15 16 17 18 19 20 22 23 24 26 27 28 29 32
 1  2  3  3  3  3  1  1  2  4  6  3  2  2  1  1  1  1  2  1  2
45
     \endverbatim
     </li>
     <li> cutoff=64*10^6:
     \verbatim
 5  6  7  8  9 10 11 12 13 14 15 16 17 19 21 26 32
 3  1  5  4  4  3  5  4  1  6  3  4  1  3  1  1  1
50
 3  5  6  8  9 10 11 12 14 15 16 17 20 22
 1  1  1  1  2  2  3  3  2  1  1  1  3  2
24
 2  3  5  6  7  8 10 11 12 13 14 15 17 18 19
 1  1  2  1  7  3  3  8  1  1  4  4  2  1  2
41
     \endverbatim
     </li>
     <li> cutoff=128*10^6:
     \verbatim
 2  3  4  5  6  7  8  9 11 13 14 15 17 18
 1  4  3  5  2  9  4  4  1  3  2  2  2  1
43
     \endverbatim
     </li>
     <li> cutoff=2*10^8
     \verbatim
 3 4 5 6 8 9 12
 2 2 3 1 2 2  1
13
 2  3  4  5  6  7  8  9 12
 1  2  4  3  4  1  4  3  1
23
     \endverbatim
     </li>
     <li> walksat-tabu-nonull using cutoff=128*10^6 reaches in 5 runs only
     a min=72, while in 6 runs with cutoff=256*10^6 only min=80 was reached.
     </li>
     <li> Finding best algorithm from Ubcsat:
     \verbatim
> E = run_ubcsat("GreenTao_N_3-3-4-5_8300.cnf",runs=100,cutoff=1000000)
> plot(E$alg,E$best)
> eval_ubcsat_dataframe(E)
     \endverbatim
     rnovelty and rnovelty+ seem clearly best. </li>
     <li> cutoff=2*10^8, rnovelty 
     \verbatim
 1  2  3  4  5  6  7  8  9 10 11 12 15
 2  3  5  7  3  5 13  8  3  1  2  2  1
55
 1  2  3  4  5  6  7  8  9 10 11 12
 2  3  6  5  8 12  3  7  4  1  2  2
55
     \endverbatim
     So rnovelty seems better than rnovelty+. </li>
     <li> cutoff=4*10^8, rnovelty: in run 68 a solution was found
     (seed=4131142001, osteps=350760305). </li>
    </ol>
   </li>
   <li> n=8350, weak standard nested translation, rnovelty
    <ol>
     <li> cutoff=10^9:
     \verbatim
 1  2  3  4  5  6  7  8  9
 2  6 17 18 17  8  3  1  1
73
     \endverbatim
     </li>
    </ol>
   </li>
  </ul>
  
*/

