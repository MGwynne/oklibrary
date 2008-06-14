// Oliver Kullmann, 19.2.2008 (Swansea)
/* Copyright 2008 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file ComputerAlgebra/Satisfiability/Lisp/MinimalUnsatisfiability/plans/general.hpp
  \brief Plans for Maxima-components regarding minimally unsatisfiable clause-sets


  \todo Create milestones


  \todo Create tests


  \todo Connections to other modules
  <ul>
   <li> In
   ComputerAlgebra/Satisfiability/Lisp/ConflictCombinatorics/HittingClauseSets.mac
   we have 2 generators for elements of SMUSAT(1). </li>
   <li> Further generators in
   ComputerAlgebra/Satisfiability/Lisp/Generators/Generators.mac. </li>
   <li> See Experimentation/Investigations/plans/general.hpp. </li>
  </ul>


  \todo Overview on generators for MUSAT
  <ul>
   <li> We need an overview on all possibilities to create elements of
   MUSAT. </li>
   <li> In ComputerAlgebra/Satisfiability/Lisp/Generators/Generators.mac
   we have, besides the hitting clause-sets:
    <ol>
     <li> weak_ph(n+1,n) </li>
     <li> usat_musat(FF) for unsatisfiable FF </li>
     <li> sat_musat(FF) for satisfiable FF </li>
    </ol>
   </li>
  </ul>


  \todo Maximal min-var-degrees
  <ul>
   <li> The general quest here is for example which show that the bound
   max_min_var_degree_def is sharp. </li>
   <li> See Experimentation/Investigations/plans/MaximiseMinVarDegrees.hpp
   for the general investigation. </li>
   <li> Perhaps the considerations regarding hitting clause-sets should go
   to a module regarding hitting clause-sets ?
    <ol>
     <li> The smallest deficiency where we do not have an example is 6. </li>
     <li> See "derived_hitting_cs_pred_isoelim" in
     ComputerAlgebra/Satisfiability/Lisp/ConflictCombinatorics/plans/HittingClauseSets.hpp
     for how to find examples. </li>
    </ol>
   </li>
  </ul>


  \todo Singular extensions
  <ul>
   <li> Transfer SingExt, ISingExt from Orthogonal.mup (see
   ComputerAlgebra/Mupad/plans/general.hpp). </li>
   <li> We want three types of extensions:
    <ol>
     <li> the non-degenerated extensions, characteristic for singular
     DP-reductions on MU; </li>
     <li> the saturated extensions, characteristic for singular
     DP-reductions on SMU; </li>
     <li> the hitting extensions, characteristic for singular
     DP-reductions on UHIT. </li>
    </ol>
   </li>
   <li> We should have systematic versions, which try to generator
   all isomorphism types for a given number of steps. </li>
   <li> And we should have simple randomised versions (as with the current
   Mupad-code). </li>
   <li> The first questions concern the characterisation of MU(delta=2),
   SMU(delta=2) and UHIT(delta=2) (always looking at all clause-sets, not
   just the non-singular one). </li>
  </ul>

*/

