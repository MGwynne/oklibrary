// Oliver Kullmann, 17.5.2008 (Swansea)
/* Copyright 2008 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file ComputerAlgebra/Satisfiability/Lisp/MinimalUnsatisfiability/plans/uhit_def.hpp
  \brief Plans regarding the catalogue of unsatisfiable non-singular hitting clause-sets


  \todo Connections to other modules
  <ul>
   <li> See ComputerAlgebra/Satisfiability/Lisp/ConflictCombinatorics/plans/HittingClauseSets.hpp
   </li>
  </ul>


  \todo Tests
  <ul>
   <li> Write tests for all functions.
    <ol>
     <li> uhit_def : DONE </li>
     <li> uhit_n : started </li>
     <li> apply_uhit </li>
     <li> collect_uhit_n </li>
     <li> classify_candidates_uhit_def </li>
    </ol>
   </li>
  </ul>


  \todo New entries
  <ul>
   <li> For n=5 add deficiencies delta = 14, ..., 27. </li>
   <li> It seems unlikely that we can get all for n=5. Nevertheless
   we should get a could variety, and for that we need a version of
   all_unsinghitting which starts from a different (random) path. </li>
  </ul>


  \todo ExternalSources for larger data-sets
  <ul>
   <li> Larger data-sets should be made available as uhit_def*.mac
   data-sets under ExternalSources, loadable on demand. </li>
   <li> Process n=5,6,7. </li>
   <li> For n=5 add deficiencies delta = 5,6,7,8,9,10,11. </li>
  </ul>

*/

