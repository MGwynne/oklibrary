// Oliver Kullmann, 28.1.2008 (Swansea)
/* Copyright 2008, 2009, 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file ComputerAlgebra/Satisfiability/Lisp/Resolution/plans/general.hpp
  \brief Plans for Maxima-components regarding the resolution calculus


  \todo Write tests


  \todo Write docus


  \todo See ProofSystems/Resolution/plans/Search.hpp.


  \todo Resolution trees
  <ul>
   <li> Function splitting2resolution_tree in
   ComputerAlgebra/Satisfiability/Lisp/Backtracking/SplittingTrees.mac
   transforms splitting trees into resolution trees. </li>
   <li> There is also a function for outputting resolution trees; this
   function should move here. </li>
   <li> We need to make this concept explicit. </li>
   <li> A "resolution tree" ("reslrt"; for the boolean case) is a rooted binary
   tree labelled with clauses such that each inner node-label is the resolvent
   of the labels of the two children. </li>
   <li> We can represent such a labelled rooted binary tree in Maxima using
   our notion of a labelled rooted tree, given in
   ComputerAlgebra/Trees/Lisp/Basics.mac. </li>
   <li> When translating a resldg (see below) into a reslrt, then we loose
   the vertex labels. In order to represent them, one needed rooted trees
   where the labels are pairs, the clause and the original label. </li>
   <li> Such "labelled resolution trees" ("resllrt", for 2 labels) should also
   be useful. </li>
   <li> We will also have collections (at least sets) of resolution trees; one
   might introduce the notion of a "resolution forest". </li>
  </ul>


  \todo Resolution proofs
  <ul>
   <li> The natural format for a resolution proof is a non-empty list,
   where each entry is either a clause (an "axiom") or a pair consisting
   of a clause (the "resolvent") and a pair of (smaller) indices (the
   indices of the "parent clauses"). </li>
   <li> Resolution proofs as digraphs:
    <ul>
     <li> The graph notions are defined in
     ComputerAlgebra/Graphs/Lisp/Basic.mac. </li>
     <li> A "resolution proof as directed graph" ("resdg") is a dg [V,E]
     such that
      <ul>
       <li> V is a set of clauses </li>
       <li> For every edge [C,D] in E, there is another edge [C,D']
       such that D and D' resolve to C. </li>
      </ul>
      We have that:
      <ul>
       <li> every resolvent points to its two parent clauses; </li>
       <li> every sink node in the graph is an axiom; </li>
       <li> all vertices have out-degree 0 or >= 2 (not 1). </li>
      </ul>
     </li>
     <li> A "resolution proof as labelled directed graph" ("resldg") is a
     labelled dg [[V,E],f] such that:
      <ul>
       <li> f maps V to clauses </li>
       <li> for every edge [u,v] in E, there is another edge [u,v'] such that
       f(v) and f(v') resolve to f(u) </li>
       <li> every node has out-degree 0 or 2. </li>
      </ul>
     </li>
     <li> The notion of "(vertex-)labelled graph" needs to be made explicit
     and implemented at the Maxima level, as discussed in "Representing edge
     and vertex labellings" in ComputerAlgebra/Graphs/Lisp/plans/Basic.hpp.
     </li>
    </ul>
   </li>
   <li> We need a correctness-checker for each different form. </li>
   <li> We need functions to translate between each of the different
   forms of resolution proofs. </li>
   <li> We also need functions to check various properties of the proof
   structures. For example:
    <ul>
     <li> Is a proof tree-like? </li>
     <li> Is a proof regular? </li>
     <li> Is the proof repetition-free? </li>
    </ul>
   </li>
   <li> Some or all of the relevant properties of resolution proofs will be
   implementable directly using existing functions on the underlying
   representations. </li>
   <li> Likely at first, we implement just the functions for lists
   and digraphs, as the notions for the underlying datastructures
   are already developed in the library. </li>
   <li> Naming conventions:
    <ul>
     <li> We need abbreviations for the following notions:
      <ul>
       <li> resolution proof as a list; </li>
       <li> resolution proof as a digraph; </li>
       <li> resolution proof as a labelled digraph; </li>
       <li> (tree-)resolution proof as a rooted tree (discussed
       in "Resolution trees" above). </li>
      </ul>
     </li>
     <li> We use "resl","reslrt", "resdg", "resldg". </li>
     <li> DONE (irrelevant: if one would read it as this word, it wouldn't
     make sense)
     It *is* unfortunate that "rest" is a word, as this might
     create confusion. </li>
    </ul>
   </li>
   <li> We should also investigate the existing file-formats for resolution
   proofs, and we should provide input- and output-facilities. </li>
   <li> The above can easily be generalised to non-boolean clause-sets.
   </li>
   <li> DONE (discussed separately w.r.t labelled digraphs)
   This linear format is in 1-1 correspondence to the representation
   via labelled dag's; we need a representation of labelled graphs,
   digraphs and labelled digraphs. </li>
  </ul>


  \todo Bounded resolution
  <ul>
   <li> Implement the different forms of bounded resolution. </li>
   <li> In this way we can determine the width of a clause-set. </li>
  </ul>


  \todo Read-once resolution proofs
  <ul>
   <li> Write a checker whether a resolution proof is read-once. </li>
   <li> Implement the translation of "has read-once refutation" into SAT. </li>
  </ul>


  \todo Create milestones : DONE

*/

