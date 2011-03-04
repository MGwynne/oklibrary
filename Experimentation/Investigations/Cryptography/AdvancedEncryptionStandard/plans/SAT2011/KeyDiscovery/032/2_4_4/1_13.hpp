// Matthew Gwynne, 15.2.2011 (Swansea)
/* Copyright 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Investigations/Cryptography/AdvancedEncryptionStandard/plans/SAT2011/KeyDiscovery/032/2_4_4/1_13.hpp
  \brief Investigations into small scale AES key discovery for 1+1/3 round AES with a 2x4 block and 4-bit field elements (1+1/3)


  \todo Problem specification
  <ul>
   <li> In this file, we collect the investigations into translations of
   1 + 1/3 round small scale AES with two columns, four rows,
   using the 4-bit field size. </li>
   <li> The AES encryption scheme we model takes a 32-bit plaintext,
   32-bit key and applies the following operations:
   <ol>
    <li> Addition of round key 0 (input key) to plaintext. </li>
    <li> Application of SubBytes (Sbox to each byte) operation. </li>
    <li> Application of linear diffusion operation. </li>
    <li> Addition of round key 1, resulting in the ciphertext. </li>
   </ol>
   </li>
   <li> The linear diffusion operation applies a shift of row i by i-1 
   bytes to the left and then applies the AES MixColumns operation
   (a matrix multiplication at the byte level). </li>
  </ul>


  \todo Using the canonical translation
  <ul>
   <li> Generating small scale AES for 1 + 1/3 round:
   \verbatim
num_rounds : 1$
num_columns : 2$
num_rows : 4$
exp : 4$
final_round_b : false$
box_tran : aes_ts_box$
seed : 1$
mc_tran : aes_mc_bidirectional$
output_ss_fcl_std(num_rounds, num_columns, num_rows, exp, final_round_b, box_tran, mc_tran)$

shell> cat ssaes_r1_c2_rw4_e4_f0.cnf | ExtendedDimacsFullStatistics-O3-DNDEBUG n
 n non_taut_c red_l taut_c orig_l comment_count finished_bool
1396 10128 31316 0 31316 1397 1
 length count
1 4
2 7680
3 368
4 32
5 1024
9 960
16 60
   \endverbatim
   </li>
   <li> Note we have the following numbers of each type of box in this 
   translation:
   \verbatim
maxima> component_statistics_ss(1,2,4,4,false,aes_mc_bidirectional);
[1,0,8,128,[[1,16],[x,8],[x+1,8],[x^3+1,8],[x^3+x+1,8],[x^3+x^2+1,8],[x^3+x^2+x,8]],4,32,4]
   \endverbatim
   That is, we have:
   <ul>
    <li> One full round (Key Addition, SubBytes, and diffusion operation).
    </li>
    <li> No special rounds (Key Addition, SubBytes and ShiftRows). </li>
    <li> 8 Sboxes in the AES round components. This comes from the two 
    columns and four rows of the block with one round. </li>
    <li> 128 additions within the round and key additions, coming from:
     <ul>
      <li> Two 32-bit key additions (adding two bits), yielding 
      64 additions of arity two in total. </li>
      <li> four additions for the MixColumn operation over two columns, 
      applied twice (forward and backward), yielding 64 additions of arity two
      in total. </li>
     </ul>
    </li>
    <li> 8 multiplications each by 02, 03, 09, 11,13 and 14 across the 
    diffusion and inverse diffusion operations. We have four of each
    multiplications in each  matrix mulitiplication, across two columns, 
    applied twice (once forward and once in for the inverse MixColumn), 
    giving 4 x 2 x 2 = 16 instances of each multiplication. </li>
    <li> 4 Sboxes in the AES key schedule. </li>
    <li> 32 additions in the key schedule. One addition of arity three
    for each bit in the element in the AES key, and one addition of arity two
    for all remaining bits in the key schedule. </li>
    <li> 4 bits for the constant in the key schedule. </li>
   </ul>
   </li>
   <li> The number of clauses of each length in the translation, computed by:
   \verbatim
maxima> ncl_list_ss(1,2,4,4,false,aes_ts_box,aes_mc_bidirectional);
[[1,4],[2,7680],[3,368],[4,32],[5,1024],[9,960],[16,60]]
maxima> mul_map(epoly) := block([e:poly2nat(epoly,2)], 
  [epoly,[[2,'m(e,2)],[9,'m(e,9)],[16,'m(e,16)]]])$
maxima> ncl_list_ss_gen(1,4,2,4,ss_mixcolumns_matrix(2,4,2),[[2,'s2],[9,'s9],[16,'s16]],create_list(mul_map(p),p,[x,x+1,x^3+1,x^3+x+1,x^3+x^2+1,x^3+x^2+x]),false,aes_mc_bidirectional);
[[1,4],
 [2,12*s2+8*'m(14,2)+8*'m(13,2)+8*'m(11,2)+8*'m(9,2)+8*'m(3,2)+8*'m(2,2)],
 [3,368],[4,32],[5,1024],
 [9,12*s9+8*'m(14,9)+8*'m(13,9)+8*'m(11,9)+8*'m(9,9)+8*'m(3,9)+8*'m(2,9)],
 [16,12*s16+8*'m(14,16)+8*'m(13,16)+8*'m(11,16)+8*'m(9,16)+8*'m(3,16)+8*'m(2,16)]]
maxima> ncl_list_full_dualts(8,16);
[[2,128],[9,16],[16,1]]
   \endverbatim
   are comprised of:
   <ul>
    <li> 4 unit clauses for the 4-bit constant in the Key schedule. </li>
    <li> 7680 binary clauses, coming from 12 Sboxes and 8 of each of the six
    multiplications (60 * 128 = 7680). </li>
    <li> 368 ternary clauses, coming from 92 additions of arity two
    (92 * 4 = 624). </li>
    <li> 32 clauses of length four, coming from 4 additions of arity three
    (4 * 8 = 32). </li>
    <li> 1024 clauses of length 5, coming from 64 additions of arity 4
    from the diffusion operation (64 * 16 = 1024). </li>
    <li> 960 clauses of length 9, coming from 12 Sboxes and 8 of each of
    the six multiplications (60 * 16 = 960). </li>
    <li> 60 clauses of length sixteen, coming from from 12 Sboxes and 8 of 
    each of the six multiplications (60 * 1 = 60). </li>
   </ul>
   </li>
   <li> Then we can generate a random assignment with the plaintext and 
   ciphertext, leaving the key unknown:
   \verbatim
maxima> output_ss_random_pc_pair(seed,num_rounds,num_columns,num_rows,exp,final_round_b);
   \endverbatim
   and the merging the assignment with the translation:
   \verbatim
shell> AppendDimacs-O3-DNDEBUG ssaes_r1_c2_rw4_e4_f0.cnf ssaes_pkpair_r1_c2_rw4_e4_f0_s1.cnf > r1_keyfind.cnf
   \endverbatim
   </li>
   <li> OKsolver solves this without backtracking:
   \verbatim
shell> OKsolver_2002-O3-DNDEBUG r1_keyfind.cnf
s SATISFIABLE
c sat_status                            1
c initial_maximal_clause_length         16
c initial_number_of_variables           1396
c initial_number_of_clauses             10192
c initial_number_of_literal_occurrences 31380
c number_of_initial_unit-eliminations   68
c reddiff_maximal_clause_length         0
c reddiff_number_of_variables           68
c reddiff_number_of_clauses             212
c reddiff_number_of_literal_occurrences 660
c number_of_2-clauses_after_reduction   7808
c running_time(sec)                     42.8
c number_of_nodes                       2915
c number_of_single_nodes                0
c number_of_quasi_single_nodes          0
c number_of_2-reductions                25478
c number_of_pure_literals               0
c number_of_autarkies                   0
c number_of_missed_single_nodes         0
c max_tree_depth                        12
c number_of_table_enlargements          0
c number_of_1-autarkies                 0
c number_of_new_2-clauses               0
c maximal_number_of_added_2-clauses     0
c file_name                             r1_keyfind.cnf
   \endverbatim
   </li>
   <li> minisat-2.2.0 and glucose:
   \verbatim
shell> minisat-2.2.0 r1_keyfind.cnf
restarts              : 126
conflicts             : 38174          (11967 /sec)
decisions             : 41318          (0.00 % random) (12952 /sec)
propagations          : 15523483       (4866296 /sec)
conflict literals     : 1218353        (59.04 % deleted)
Memory used           : 19.00 MB
CPU time              : 3.19 s

shell> minisat2 r1_keyfind.cnf 
<snip>
restarts              : 14
conflicts             : 43604          (1401 /sec)
decisions             : 47364          (1.34 % random) (1522 /sec)
propagations          : 17037471       (547477 /sec)
conflict literals     : 1360321        (61.63 % deleted)
Memory used           : 18.44 MB
CPU time              : 31.12 s
shell> glucose r1_keyfind.cnf 
<snip>
c restarts              : 8
c nb ReduceDB           : 2
c nb learnts DL2        : 232
c nb learnts size 2     : 44
c nb learnts size 1     : 0
c conflicts             : 16554          (13035 /sec)
c decisions             : 21834          (1.56 % random) (17192 /sec)
c propagations          : 3407020        (2682693 /sec)
c conflict literals     : 705068         (42.14 % deleted)
c Memory used           : 4.88 MB
c CPU time              : 1.27 s
   \endverbatim
   </li>
   <li> We can check we get the right result with:
   \verbatim
shell> OKsolver_2002-O3-DNDEBUG -O r1_keyfind.cnf | grep "^v" | $OKlib/Experimentation/Investigations/Cryptography/AdvancedEncryptionStandard/validate_aes_assignment 1 2 4 4 0 && echo "VALID"
VALID
   \endverbatim
   </li>
  </ul>

*/
