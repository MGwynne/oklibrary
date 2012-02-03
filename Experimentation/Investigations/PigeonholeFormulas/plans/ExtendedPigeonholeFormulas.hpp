// Matthew Gwynne, 3.2.2012 (Swansea)
/* Copyright 2012 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Experimentation/Investigations/PigeonholeFormulas/plans/ExtendedPigeonholeFormulas.hpp
  \brief Investigations regarding extended pigeonhole clause-sets


  \todo Links
  <ul>
   <li> The Maxima implementation of the extended pigeonhole formulas from
   [Cook, 1976] are available as weak_php_unsat_ext_fcs in
   ComputerAlgebra/Satisfiability/Lisp/Generators/Pigeonhole.mac. </li>
   <li> The resolution proof for weak_php_unsat_ext_fcs is available
   as php_ext_resl in Satisfiability/Lisp/Resolution/Proofs.mac. </li>
   <li> Investigations on the standard pigeonhole formulas are
   available in Investigations/PigeonholeFormulas/plans/general.hpp. </li>
  </ul>

  \todo Statistics on the performance of SAT solvers
  <ul>
   <li> We need statistics on the running of SAT solvers on solvers,
   as in Investigations/PigeonholeFormulas/plans/general.hpp. </li>
  </ul>


  \todo Basic statistics
  <ul>
   <li> Implemented formulas:
   \verbatim
for n : 0 thru 10 do block(print(n,nvar_weak_php_unsat_ext(n),ncl_weak_php_unsat_ext(n)));

0 0 1
1 2 3
2 8 17
3 20 54
4 40 125
5 70 241
6 112 413
7 168 652
8 240 969
9 330 1375
10 440 1881
   \endverbatim
   </li>
  </ul>


  \todo Prime implicates
  <ul>
   <li> The number and the structure of prime implicates for satisfiable ephp
   is needed. </li>
  </ul>


  \todo Hardness of (extended-)pigeon-hole formulas
  <ul>
   <li> Discussion and generators for Cook's extended pigeon-hole formulas
   are available in
   "Extended Resolution clauses for the Pigeon Hole Principle" in
   ComputerAlgebra/Satisfiability/Lisp/Generators/plans/general.hpp. </li>
   <li> We know that:
    <ul>
     <li> weak_php(n+1,n) has hardness n from [Kullmann 1999]. </li>
     <li> Cook's extension, weak_php_unsat_ext_fcs(n), has at most
     hardness n (as weak_php(n+1,n) is a subset). </li>
    </ul>
   </li>
   <li> Cook's extension, weak_php_unsat_ext_fcs(m), has a polynomial size
   resolution proof. </li>
   <li> We conjecture that Cook's extension has exactly hardness n
   (see below for a rough proof sketch). </li>
   <li> The hardness of weak_php(m+1,m) vs weak_php_unsat_ext_fcs(m):
   \verbatim
maxima> for m : 0 while true do
  print([hardness_wpi_cs(weak_php_fcs(m+1,m)[2],{{}}),
         hardness_wpi_cs(weak_php_unsat_ext_fcs(m)[2],{{}})])$
[0,0]
[1,1]
[2,2]
[3,3]
[4,4]
   \endverbatim
   </li>
   <li> A (rough) proof sketch that hardness
   weak_php_unsat_ext_uni_fcs(n) >= n, and hence
   weak_php_unsat_ext_fcs(n) >= n:
    <ul>
     <li> By Lemma 3.17 of [Kullmann 1999], it suffices to show that
     for any variable v of weak_php_unsat_ext_uni_fcs(n) and truth value b in {0,1}
     the hardness of <v->b> * weak_php_unsat_ext_uni_fcs(n) is at least that
     of weak_php_unsat_ext_fcs(n-1). </li>
     <li> The variables of weak_php_unsat_ext_uni_fcs(n) are php_ext_var(l,i,j) for
     1 <= l <= n, 1 <= i <= l+1, 1 <= j <= l. </li>
     <li> Consider the assignment <php_ext_var(l,i,j) -> b> for some
     allowed l,i, and j.  </li>
     <li> If b = 1 then construct the partial assignment phi such that
      <ul>
       <li> phi(php_ext_var(l,i',j)) = 0 for all  1 <= i' <= l+1, i' != i. </li>
       <li> phi(php_ext_var(l,i,j')) = 0 for all  1 <= j' <= l, j' != j. </li>
      </ul>
     </li>
     <li> Otherwise if b = 0 then choose some 1 <= i'' <= l+1 such that
     i'' != i and then construct phi in the following way:
      <ul>
       <li> phi(php_ext_var(l,i',j)) = 0 for all  1 <= i' <= l+1, i' != i''. </li>
       <li> phi(php_ext_var(l,i'',j')) = 0 for all  1 <= j' <= l, j' != j. </li>
      </ul>
      In other words, w.l.o.g., we can assume that there is some
      php_ext_var(l,i,j) such that phi(php_ext_var(l,i,j)) = true.
     </li>
     <li> Construct phi * weak_php_unsat_ext_uni_fcs(n), and apply
     unit-clause propagation, and equivalence propagation; the result is
     a clause-set isomorphic to weak_php_unsat_ext_uni_fcs(n-1). </li>
     <li> Application of a partial assignment to a clause-set can not
     produce a harder clause-set (so neither can unit-clause propagation). </li>
     <li> Equivalence propagation also doesn't yield a harder clause-set.
     </li>
     <li> Therefore, we have that weak_php_unsat_ext_uni_fcs(n) has hardness
     >= n. </li>
    </ul>
   </li>
   <li> Checking that for weak_php_unsat_ext_uni_fcs(n), and assignment
   <php_ext_var(l,i,j) -> true>, the clause-set constructed after applying
    <ul>
     <li> the appropriate partial assignment, </li>
     <li> unit-clause propagation (giving the assignment directly), and </li>
     <li> applying equivalence propagation (applying the substitution of
     variables directly) </li>
    </ul>
   yields a clause-set isomorphic to weak_php_unsat_ext_uni_fcs(n-1):
   \verbatim
/* Checking proof of hardness(weak_php_unsat_ext_uni_fcs(n)) = n: */
check_hardness_n_weak_php_unsat_ext_uni_fcs(n,is,js) := block(
    [F,F_nm1, phi,l_stop,merge_vars_sm,renaming_sm],
  if n = 0 then return(true),
  if n = 1 then return(true), /* Here weak_php_unsat_ext_fcs(n) = weak_php_fcs(n) */
  /* Calculate level at which unit-clause propagation stops: */
  l_stop : max(is-1,js),
  /* Construct partial assignment, including assignment given by applying UCP: */
  phi : delete(und, create_list(
    if i = is and j = js then php_ext_var(l,i,j)
    else if i = is or j = js then -php_ext_var(l,i,j)
    else und,
    l, l_stop, n, i, 1, l+1, j, 1, l)),
  /* When unit-clause propagation stops, we are left with equivalence clauses,
     which we now construct a substitution to remove: */
  if is = l_stop + 1 then
    merge_vars :
      create_list([php_ext_var(l_stop-1,i,js),php_ext_var(l_stop,i,l_stop)],
                   i, 1, l_stop)
  else if js = l_stop then
    merge_vars :
      create_list([php_ext_var(l_stop-1,is,j),php_ext_var(l_stop,l_stop+1,j)],
                   j, 1, l_stop-1),
  merge_vars : append(merge_vars,
    delete(und,create_list(
      if i # is and j # js then
        [php_ext_var(l_stop-1,i,j),php_ext_var(l_stop,i,j)]
      else und,
      i, 1, l_stop, j, 1, l_stop-1))),
  /* Apply all and check it's equal to the level below: */
  F : weak_php_unsat_ext_uni_fcs(n),
  F : apply_pa_fcs(setify(phi),F),
  F : subset(substitute_cl(F[2], sm2hm(merge_vars)), lambda([C], not(clashp(C,C)))),
  F_nm1 : weak_php_unsat_ext_uni_fcs(n-1),
  is_isomorphic_fcs(cs2fcs(F),F_nm1)
)$

 /* Checking for instantiated values: */
for n : 1 thru 5 do print("Proposition holds for n =", n, "?", stable_unique(create_list(check_hardness_n_weak_php_unsat_ext_uni_fcs(n,i,j), i, 1, n+1, j,1,n))[1])$

Proposition holds for n = 1 ? true
Proposition holds for n = 2 ? true
Proposition holds for n = 3 ? true
Proposition holds for n = 4 ? true
Proposition holds for n = 5 ? true
   \endverbatim
   Note that check_hardness_n_weak_php_unsat_ext_uni_fcs doesn't take
   l as an argument as unit-clause-propagation will force that
   php_ext_var(l',i,j) = true for all l' such that i <= l+1 and j <= j,
   and so l' would be a superfluous argument. </li>
  </ul>


*/
