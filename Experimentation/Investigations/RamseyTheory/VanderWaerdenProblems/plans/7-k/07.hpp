// Oliver Kullmann, 12.3.2011 (Swansea)
/* Copyright 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Experimentation/Investigations/RamseyTheory/VanderWaerdenProblems/plans/7-k/07.hpp
  \brief On investigations into vdw_2(7,7)


  \todo Best complete solver for palindromic problems


  \todo Best local-search solver for palindromic problems
  <ul>
   <li> Best ubcsat-algorithm:
   \verbatim
> PdVanderWaerdenCNF-O3-DNDEBUG 7 7 1548

> E=run_ubcsat("VanDerWaerden_pd_2-7-7_1548.cnf",runs=100,cutoff=10000000)

   \endverbatim
   </li>
  </ul>


  \todo vdw_2^pd(7,7) >= (1544,1547)
  <ul>
   <li> Certificates:
    <ol>
     <li> n=1543:
     \verbatim
1,6,8,9,12,13,15,16,19,21,
22,23,24,26,27,28,31,33,35,37,
42,45,46,47,48,50,51,52,54,55,
57,58,59,63,65,66,67,68,69,73,
75,80,85,86,93,98,99,100,101,102,
104,105,107,108,109,110,111,114,115,116,
118,124,126,127,128,129,130,131,135,136,
138,139,140,141,143,144,148,149,150,152,
153,155,161,163,164,165,167,168,169,170,
171,172,174,175,177,178,179,180,181,186,
193,194,199,204,206,210,212,213,214,216,
221,224,225,227,228,229,231,232,233,234,
237,242,246,248,251,252,253,255,258,260,
261,264,266,268,271,272,274,279,280,281,
284,286,289,290,295,298,300,301,303,304,
305,307,308,311,316,318,319,320,322,326,
328,332,333,338,339,346,351,352,353,354,
355,357,358,360,361,362,363,364,365,367,
368,369,371,376,377,379,380,382,383,384,
387,388,389,391,392,393,394,396,397,398,
401,402,403,404,405,406,408,414,416,417,
418,421,422,423,424,425,427,428,430,431,
432,433,434,439,442,446,447,452,457,459,
463,464,465,466,467,469,473,474,475,477,
478,480,481,482,484,485,486,487,490,495,
499,501,504,505,506,508,511,513,514,517,
521,524,525,527,530,532,533,534,537,539,
543,548,551,552,553,554,556,557,558,560,
561,564,569,571,572,573,575,579,581,586,
591,592,596,599,604,605,606,607,608,610,
611,613,614,615,616,617,620,621,622,624,
629,630,632,633,635,636,637,641,642,644,
645,646,647,649,650,651,654,655,656,657,
658,659,661,667,669,670,671,674,675,676,
677,678,680,681,683,685,686,687,692,695,
699,700,705,706,710,712,716,717,718,719,
720,722,726,727,730,731,733,734,735,737,
738,740,743,748,750,752,754,757,758,759,
761,764,766,767,770,772
     \endverbatim
     </li>
     <li> n=1546:
     \verbatim
4,5,6,8,10,12,13,14,18,22,
26,27,28,29,31,32,33,34,35,37,
41,48,51,53,57,58,59,60,62,63,
64,65,66,67,70,71,72,73,76,77,
78,80,82,83,84,90,92,93,94,95,
97,98,101,105,110,111,113,114,115,116,
120,122,124,125,129,130,131,132,134,137,
138,140,141,142,144,145,148,150,151,153,
157,158,160,162,166,167,168,169,171,172,
174,177,181,184,187,188,189,190,192,198,
199,200,202,204,205,206,209,211,212,215,
216,217,219,220,222,223,224,225,231,234,
241,245,247,248,249,250,251,253,256,260,
261,265,270,274,275,282,284,285,286,287,
288,290,294,301,304,306,310,311,312,313,
315,316,318,319,320,323,324,326,329,330,
331,333,335,336,337,343,345,346,347,351,
354,358,361,363,364,366,367,368,369,373,
375,377,378,382,383,384,385,387,390,391,
393,394,395,397,398,401,403,404,405,406,
410,411,413,415,416,419,420,421,422,424,
425,427,430,434,437,441,442,443,445,449,
451,452,453,455,457,458,459,462,464,465,
468,469,470,471,472,473,475,476,477,478,
482,484,487,494,498,500,501,502,503,506,
509,513,514,515,518,523,527,528,532,535,
537,538,539,540,541,543,547,554,557,559,
563,564,565,566,568,569,570,571,572,573,
576,577,578,579,581,582,583,584,586,588,
589,590,596,598,599,600,604,607,611,616,
617,619,620,621,622,624,626,628,630,631,
635,637,638,640,643,644,646,647,648,650,
651,654,656,657,658,659,663,664,666,668,
669,672,673,674,675,677,678,680,683,687,
690,693,694,695,696,698,704,705,706,708,
710,711,712,715,716,717,718,721,722,723,
724,725,726,728,729,730,731,737,740,747,
751,753,754,755,756,757,759,766,767,771
     \endverbatim
    </ol>
   </li>
   <li> "RunPdVdWk1k2 7 7 adaptg2wsat 100 6000000" yields
   \verbatim
Break point 1: 660
Break point 2: 839
   \endverbatim
   using at most ?? runs.
   </li>
  </ul>
   <li> "RunPdVdWk1k2 7 7 adaptg2wsat 100 20000000" yields
   \verbatim
Break point 1: 1544
Break point 2: 1547
   \endverbatim
   using at most ?? runs.
   </li>

*/
