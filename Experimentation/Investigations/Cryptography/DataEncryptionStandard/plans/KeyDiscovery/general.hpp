// Matthew Gwynne, 25.5.2011 (Swansea)
/* Copyright 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Investigations/Cryptography/DataEncryptionStandard/plans/KeyDiscovery/general.hpp
  \brief On investigations into the Data Encryption Standard key discovery


  \todo Overview
  <ul>
   <li> Solving the key discovery problem for:
    <ul>
     <li> 1-round DES, see
     Cryptography/DataEncryptionStandard/plans/KeyDiscovery/1.hpp.
     </li>
     <li> 3-round DES, see
     Cryptography/DataEncryptionStandard/plans/KeyDiscovery/3.hpp.
     </li>
     <li> 4-round DES, see
     Cryptography/DataEncryptionStandard/plans/KeyDiscovery/4.hpp.
     </li>
     <li> 5-round DES, see
     Cryptography/DataEncryptionStandard/plans/KeyDiscovery/5.hpp.
     </li>
     <li> 16-round DES with some known key bits, see
     Cryptography/DataEncryptionStandard/plans/KeyDiscovery/KnownKeyBits.hpp.
     </li>
    </ul>
   </li>
  </ul>


  \todo Generating instances using multiple plaintext-ciphertext pairs
  <ul>
   <li> We can construct instances with multiple plaintext-ciphertext
   pairs by merging (using variable renamings which keep the key
   variables the same) multiple DES translations using the following code:
   \verbatim
/* The same variable v in subsequent instances of a problem is
   renamed to v, ren(v), ren(ren(v)), ren(ren(ren(v))) and so
   on */
declare(ren, noun)$
declare(ren, posfun)$

des_gen_multiple_plaintext(sbox_fcl_l, rounds, P_hex_l,K_hex) := block([aux_f : lambda([a],a), final_F : [[],[]],K],
  K : create_list(desk_var(i),i,1,64),
  if oklib_monitor then print("Generating DES..."),
  F : des2fcl_gen(sbox_fcl_l,rounds),
  if oklib_monitor then print("            Generated DES!"),
  for i : 1 thru length(P_hex_l) do block(
    if oklib_monitor then print("Calculating PC pair ", i),
    P : des_plain2fcl_gen(hexstr2binv(P_hex_l[i]),rounds),
    C_hex : des_encryption_hex_gen(rounds, P_hex_l[i],K_hex),
    C : des_cipher2fcl_gen(hexstr2binv(C_hex),rounds),
    if oklib_monitor then print("     standardising..."),
    Fs : [F[1],append(F[2],P[2],C[2])],
    if oklib_monitor then print("     renaming fcl..."),
    Fs_rem : rename_fcl(Fs, append(K, map(aux_f,rest(Fs[1],length(K))) )),
    if oklib_monitor then print("     combining..."),
    final_F : [stable_unique(append(final_F[1],Fs_rem[1])), append(final_F[2], Fs_rem[2])],
    aux_f : buildq([aux_f], lambda([a], ren(aux_f(a))))),
    return(final_F))$

gen_random_des_pc_pair(seed) := block(
  set_random(make_random_state(seed)),
  P_hex : lpad(int2hex(random(2**64)),"0",16),
  K_hex : lpad(int2hex(random(2**64)),"0",16),
  return([P_hex,K_hex]))$

output_des_gen_multiple_plaintext(name, sbox_fcl_l, rounds, P_hex_l,K_hex_l,seed) := block([Fs : standardise_fcl(des_gen_multiple_plaintext(sbox_fcl_l, rounds, P_hex_l,K_hex_l))],
  output_fcl_v(
    sconcat(rounds, "-round DES instantiated with plaintext and ciphertext generated from seed ", seed, "; translated using the ",name," translation for the S-boxes (6-to-4)."),
    Fs[1],
    sconcat("des_6t4_",name,"_r",rounds,"_s",seed,"_p",length(P_hex_l),".cnf"),
    Fs[2]))$
   \endverbatim
   </li>
   <li> We can then generate 20 4-round DES key-discovery instances with
   random plaintext-ciphertext pairs, where each instance includes 4
   plaintext-ciphertext pairs for the same key, as follows:
   \verbatim
sbox_fcl_l : create_list(dualts_fcl([listify(setn(10)), bf2relation_fullcnf_fcs(des_sbox_bf(i),10)]), i, 1, 8)$
for seed : 1 thru 20 do (print("Seed ", seed), output_des_gen_multiple_plaintext("canon", sbox_fcl_l, 5, create_list(gen_random_des_pc_pair(seed + i)[1], i, 1,4), gen_random_des_pc_pair(seed)[2],seed))$
   \endverbatim
   </li>
   <li> Translations using additional plaintext-ciphertext pairs should be compared.
   </li>
   <li> The above code should be tidied and implemented in the
   Maxima system. </li>
  </ul>


  \todo Experiment scripts
  <ul>
   <li> The argumentation below seems dubious to OK:
    <ol>
     <li> It seems to fit into the unfortunate pattern of just writing tools
     for themselves, without interest in the experiments. </li>
     <li> Special scripts for such special purposes will only be
     understandable, will only be used by the person running the scripts. </li>
     <li> Then it follows also that they will be of weak quality. </li>
     <li> We should only use general tools; except, of course, it is a real
     method, like for computing van der Waerden numbers the various scripts,
     which implement certain algorithms. </li>
     <li> No tiny ("dirty") scripts for this and that, as a private hobby of
     a single person --- but everything must connect to the whole library.
     </li>
    </ol>
   </li>
   <li> The presentation of experimental data for DES in
   Investigations/Cryptography/DataEncryptionStandard/plans/KeyDiscovery/
   is excessively verbose, and hides the underlying data. </li>
   <li> Experiment generation should be a single command where the key
   parameters can be easily seen, and there is no room for mistake. </li>
   <li> Experimental results should be concise. </li>
   <li> Experimental results should be extractable at any stage of the
   computation, not only once a batch of 20 instances have been run on.
   </li>
   <li> We need scripts for:
    <ul>
     <li> Generating DES data (S-box representations etc). </li>
     <li> Generating DES experiments; </li>
     <li> Running DES experiments; </li>
    </ul>
   </li>
   <li> Generating DES data:
    <ul>
     <li> We need scripts which generate CNF representations for all
     of the DES S-boxes, for each different translation. </li>
     <li> So we need the following scripts:
      <ul>
       <li> GenerateDESSboxes_Min: generates the CNF representations
       for the DES S-boxes with the smallest (conjectured) number of clauses.
       </li>
       <li> GenerateDESSboxes_1base: generates the CNF 1-base
       representations for the DES S-boxes with the smallest (conjectured)
       number of clauses. </li>
      </ul>
     </li>
     <li> Note, in all cases, the minimum sizes are *not* known, and
     so smaller representations might be found. </li>
     <li> These scripts can then be updated manually if new smaller
     representations are found. </li>
     <li> The scripts should create a directories DES_Sboxes_min_${date} and
     DES_Sboxes_1base_${date} respectively, and output the corresponding
     representations for S-box i to "Sbox_${i}.cnf" within the directory.
     </li>
     <li> ${date} is a timestamp: $(date +"%Y-%m-%d-%H%M%S"). </li>
    </ul>
   </li>
   <li> Generating DES experiments:
    <ul>
     <li> We need scripts which generate an uninstantiated DES instance
     using each of the box translations. </li>
     <li> So we need the following scripts (arguments given in parentheses):
      <ul>
       <li> GenerateDESExperiment_MinSbox(r): generates the r-round DES using
       the "minimum" translation for the S-boxes. </li>
       <li> GenerateDESExperiment_1baseSbox(r): generates the r-round DES
       using the 1-base translation for the S-boxes. </li>
       <li> GenerateDESExperiment_CanonSbox(r): generates the r-round DES
       using the canonical translation for the S-boxes. </li>
       <li> GenerateDESKeys(r,s_max): generates CNF Dimacs files
       containing unit-clauses for instantiating r-round DES with the
       plaintext-ciphertext pairs generated using seeds 1,...,s_max. </li>
      </ul>
     </li>
    </ul>
   </li>
   <li> To run the DES experiments, we should extend the standard
   experiment running scripts, discussed in "Running experiments"
   in ExperimentSystem/SolverMonitoring/plans/general.hpp. </ul>
   </li>
   <li> All DES experiments need to be rerun using the new experiment scripts
   discussed in "Running experiments"
   in ExperimentSystem/SolverMonitoring/plans/general.hpp. OK: ???
   Why this waste of time ??? We already suffer from a serious lack of data.
   This again seems to fit into the pattern of running the experiments as end
   in itself. </li>
   <li> See also "Update experiment script" in
   Investigations/Cryptography/AdvancedEncryptionStandard/plans/Experimentation.hpp.
   </li>
  </ul>


  \todo Add information on specific S-box translations to experiment instances
  <ul>
   <li> At present, if one encounters an experiment instance for a DES
   experiment, then it is not clear exactly how it was produced. </li>
   <li> The ambiguity occurs because, over time, smaller "minimum" and 1-base
   representations for the S-boxes are found. </li>
   <li> Based on these new representations, new translations are generated,
   and experiments rerun. </li>
   <li> This leaves one with several copies of the same translation file,
   and the possibility of uncertainty about which is which. </li>
   <li> All instance generation code for experiments should include
   information, via the DIMACS comments of the instance, on the S-box
   representations used. </li>
   <li> For example, the seeds given by RandomRUcpBases to generate the
   1-base for a DES S-box could be output as comment in the DIMACS FILE as:
   \verbatim
c DES S-box 1 1-base seeds: 1 (gen) 2 (base).
   \endverbatim
   </li>
   <li> Even better, tools and scripts should be written which take
   only parameters such as seeds from RandomRUcpBases or ubcsat etc and
   output the CNFs. </li>
   <li> Then the actual generation instructions could be added to the CNF
   file as comments. </li>
  </ul>


  \todo DONE Move into separate sub-module

*/
