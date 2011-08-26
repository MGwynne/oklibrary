// Matthew Gwynne, 22.8.2011 (Swansea)
/* Copyright 2011 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file Investigations/Cryptography/DataEncryptionStandard/plans/KeyDiscovery/Argo.hpp
  \brief On investigations into the Data Encryption Standard key discovery instances from the ARGO group


  \todo Overview
  <ul>
   <li> See "Argo DES instances" in
   Buildsystem/ExternalSources/SpecialBuilds/plans/Cryptography.hpp. </li>
   <li> We consider the key discovery instance on these problems. </li>
   <li> The files we consider are gss-i-s100.cnf where i in
   {13,...,17,19,...,28,31,34} is the number of unknown key bits. </li>
   <li> We need the statistics for the instances here. </li>
  </ul>


  \todo minisat-2.2.0
  <ul>
   <li> Running minisat-2.2.0 on the gss-*-s100.cnf instances:
   \verbatim
> mkdir Instances/
> for F in ExternalSources/Installations/SAT/SAT09/APPLICATIONS/crypto/desgen/*; do cp ${F} Instances/$(echo $(basename ${F}) | cut -d "-" -f "2"); done
Experiments/DES/Argo> ls Instances/
13  14  15  16  17  19  20  21  22  23  24  25  26  27  28  31  32  33  34
> for F in Instances/*; do RunMinisat ${F}; done
> cat ExperimentMinisat_Instances13_2011-08-22-111827/Environment
Linux csenceladus 2.6.37.1-1.2-desktop #1 SMP PREEMPT 2011-02-21 10:34:10 +0100 i686 i686 i386 GNU/Linux
processor       : 0
model name      : Intel(R) Core(TM)2 Duo CPU     E8400  @ 3.00GHz
cpu MHz         : 2003.000
cache size      : 6144 KB
bogomips        : 5999.41
processor       : 1
<same as processor 0>
             total       used       free     shared    buffers     cached
Mem:          3947       1113       2833          0        183        839
Swap:         2053          0       2053

> echo -n "ub "; ExtractMinisat header-only; for F in Instances/*; do echo -n "$(basename ${F}) "; tail -n1 ExperimentMinisat_Instances$(basename ${F})_*/Statistics; done
ub rn rc t sat cfs dec rts r1 mem ptime stime cfl
13 30867 92535 4.27935 1 4163 4782 22 32241454 20.00 0.05 0.17 53421
14 31229 93655 13.6159 1 13103 14368 59 105018641 20.00 0.05 0.18 162452
15 31238 93678 5.72913 1 5452 6451 29 43914380 20.00 0.05 0.18 78501
16 31248 93704 6.80497 1 6260 7575 30 51698260 20.00 0.05 0.18 98687
17 31318 93916 33.6599 1 32100 35152 120 253976822 20.00 0.04 0.18 579619
19 31435 94348 317.759 1 265675 280077 636 2213616862 33.00 0.05 0.18 4803791
20 31503 94548 1378.86 1 1266646 1339078 2428 8324740787 51.00 0.05 0.18 34985574
21 31613 94904 6230.85 1 4975819 5225600 8191 35394063729 83.00 0.05 0.19 121366390
22 31616 94910 17506.6 1 11661878 12189100 16891 92082425131 120.00 0.05 0.19 280720131
23 31711 95200 2167.9 1 1719380 1849480 3322 12190504675 68.00 0.05 0.19 51786283
24 31821 95535 39073.5 1 23385776 24574689 32767 187419566166 176.00 0.05 0.19 630593530
25 31931 95911 215.137 1 194200 217984 510 1389553850 42.00 0.05 0.19 6692588
26 31942 95938 107735 1 59528887 62568695 77051 476482081268 285.00 0.05 0.19 1787397560
   \endverbatim
   </li>
  </ul>


  \todo Applying SplittingViaOKsolver
  <ul>
   <li> Instructions on the options for SplittingViaOKsolver are
   at XXX. </li>
   <li> Examples for the use of SplittingViaOKsolver are at
    <ul>
     <li> XXX </li>
     <li> XXX </li>
    </ul>
   </li>
   <li> Setting up the experiment:
   \verbatim
> mkdir Instances/
> for F in ExternalSources/Installations/SAT/SAT09/APPLICATIONS/crypto/desgen/*; do cp ${F} Instances/$(echo $(basename ${F}) | cut -d "-" -f "2"); done
Experiments/DES/Argo> ls Instances/
13  14  15  16  17  19  20  21  22  23  24  25  26  27  28  31  32  33  34
   \endverbatim
   </li>
   <li> unknown_key_bits=17 (solvable by minisat-2.2.0 in 34s with
   32,100 conflicts):
    <ul>
     <li> The depth-interpretation:
     \verbatim
> SplittingViaOKsolver -D8 -SD Instances/17
> cd SplitViaOKsolver_D8SDInstances17_2011-08-22-144721
> more Md5sum
59fa6fdf02a0e3eb1d76056f23645d48
> more Statistics
> E=read.table("Data")
> summary(E$n)
   Min. 1st Qu.  Median    Mean 3rd Qu.    Max.
   3799    3913    3970    3972    4027    4177
> table(E$n)
3799 3802 3804 3807 3836 3839 3841 3844 3846 3849 3866 3868 3869 3871 3873 3874
   1    1    2    2    2    1    4    1    3    1    1    1    1    3    4    2
3876 3878 3883 3888 3889 3890 3895 3896 3903 3905 3906 3908 3910 3911 3913 3915
   3    2    2    1    1    1    1    1    3    2    1    9    2    1    6    2
3916 3918 3926 3927 3931 3932 3933 3935 3937 3938 3940 3942 3943 3945 3947 3950
   1    1    2    2    2    3    1    1    1    2    5    2    3    5    1    4
3955 3958 3959 3963 3964 3965 3968 3969 3970 3972 3973 3974 3975 3977 3980 3982
   2    3    3    2    5    3    2    3    2    2    1    2    5    4    3    3
3985 3995 3996 3997 4000 4001 4002 4005 4006 4007 4009 4012 4014 4017 4022 4027
   1    4    5    1    4    7    3    1    2    2    3    3    2    2    1    2
4028 4032 4033 4034 4037 4038 4039 4041 4043 4044 4049 4064 4065 4066 4070 4071
   2    2    5    3    1    4    3    1    1    3    1    2    4    2    5    5
4075 4076 4081 4101 4102 4103 4106 4107 4108 4133 4134 4139 4140 4171 4172 4176
   1    2    1    1    2    1    1    2    1    1    1    1    1    1    1    1
4177
   1
> more Result
c running_time(sec)                     242.9
c number_of_nodes                       511
c number_of_2-reductions                9062
c max_tree_depth                        8
c number_of_1-autarkies                 53824
c splitting_cases                       256

> ProcessSplitViaOKsolver SplitViaOKsolver_D8SDInstances17_2011-08-22-144721
> cd Process_SplitViaOKsolver_D8SDInstances17_2011-08-22-144721_2011-08-23-113916

> E=read_processsplit_minisat()
256: 16.01m, sum-cfs=3.608833e+06, mean-t=3.752s, mean-cfs=14097
$t:
   Min. 1st Qu.  Median    Mean 3rd Qu.    Max.
  3.407   3.658   3.756   3.752   3.841   4.184
sd= 0.1279239
     95%      96%      97%      98%      99%     100%
3.960400 3.989192 4.009590 4.033590 4.052780 4.184360
sum= 960.6059
$cfs:
   Min. 1st Qu.  Median    Mean 3rd Qu.    Max.
  12150   13610   14040   14100   14560   16800
sd= 751.1283
     95%      96%      97%      98%      99%     100%
15325.25 15419.60 15546.20 15726.80 16018.75 16796.00
sum= 3608833
$t ~ $cfs:
              Estimate Std. Error t value  Pr(>|t|)
(Intercept) 1.6598e+00 7.3953e-02  22.444 < 2.2e-16 ***
E$cfs       1.4844e-04 5.2386e-06  28.336 < 2.2e-16 ***
R-squared: 0.7597

> SplittingViaOKsolver -D12 -SD Instances/17
> cd SplitViaOKsolver_D12SDInstances17_2011-08-22-150706
> more Md5sum
4a9c4bd3f1dd0dc9f5b5e9a9ac9d478a
> more Statistics
> E=read.table("Data")
> summary(E$n)
   Min. 1st Qu.  Median    Mean 3rd Qu.    Max.
   4356    4513    4570    4570    4620    4811
> table(E$n)
4356 4357 4361 4362 4363 4364 4365 4366 4367 4368 4369 4370 4371 4393 4394 4398
   1    1    2    3    2    1    1    1    2    4    2    2    2    2    2    5
4399 4400 4401 4402 4403 4404 4405 4406 4407 4408 4409 4410 4411 4412 4413 4415
   7    4    2    1    4    5    7    5    1    1    1    4    3    1    1    1
4416 4420 4421 4422 4423 4424 4425 4426 4427 4428 4429 4430 4431 4432 4433 4434
   1    2    3    3    3    2    2    3    6    7    7    9    8    5    4    7
4435 4436 4437 4438 4439 4440 4441 4442 4443 4444 4445 4446 4447 4448 4449 4450
  11   15   16    8    4    8    8    9    9    3    3    4    4    4    2    1
4452 4453 4457 4458 4459 4460 4461 4462 4463 4464 4465 4466 4467 4468 4469 4470
   3    3    5    7    6    6    3    6    8   12   14   10   12   19   22   15
4471 4472 4473 4474 4475 4476 4477 4478 4479 4480 4481 4482 4483 4484 4485 4486
  16   19   21   20   11   12   14   15   17   14    7    4    4    6   12    8
4487 4488 4489 4490 4491 4492 4493 4494 4495 4496 4497 4498 4499 4500 4501 4502
   4    4    7    8    6    5    4   11   14   17   16   12   14   15   17   15
4503 4504 4505 4506 4507 4508 4509 4510 4511 4512 4513 4514 4515 4516 4517 4518
  18   23   28   31   21   13   15   22   27   27   19   13   14   12   13   14
4519 4520 4521 4522 4523 4524 4525 4526 4527 4528 4529 4530 4531 4532 4533 4534
  10    8   11   15   10    6    6   13   22   17   13   14   20   23   21   18
4535 4536 4537 4538 4539 4540 4541 4542 4543 4544 4545 4546 4547 4548 4549 4550
  21   26   28   38   32   23   20   22   33   30   24   21   23   30   28   17
4551 4552 4553 4554 4555 4556 4557 4558 4559 4560 4561 4562 4563 4564 4565 4566
  12   13   18   26   19   13   12   12   14   10    7    9   20   25   23   18
4567 4568 4569 4570 4571 4572 4573 4574 4575 4576 4577 4578 4579 4580 4581 4582
  12   14   22   28   23   24   25   24   29   28   24   18   19   32   38   28
4583 4584 4585 4586 4587 4588 4589 4590 4591 4592 4593 4594 4595 4596 4597 4598
  16   14   22   24   17   16   19   20   20   19   15   14   16   17   23   21
4599 4600 4601 4602 4603 4604 4605 4606 4607 4608 4609 4610 4611 4612 4613 4614
  13   12   19   24   14   15   19   18   26   24   16   13   13   20   31   27
4615 4616 4617 4618 4619 4620 4621 4622 4623 4624 4625 4626 4627 4628 4629 4630
  15   12   14   21   23   17   12   10   15   20   19   14    9   13   17   12
4631 4632 4633 4634 4635 4636 4637 4638 4639 4640 4641 4642 4643 4644 4645 4646
   9   12   18   23   16    9    7   12   24   18   11    9    7   14   19   18
4647 4648 4649 4650 4651 4652 4653 4654 4655 4656 4657 4658 4659 4660 4661 4662
  12    8    7   15   23   16    8    8   13   13   12   10    9   16   14    8
4663 4664 4665 4666 4667 4668 4669 4670 4671 4672 4673 4674 4675 4676 4677 4678
   9    8    6   10   11    6    3    6   12   10    6    4    4    7    9    8
4679 4680 4681 4682 4683 4684 4685 4686 4687 4688 4689 4690 4691 4692 4693 4694
   5    4    4   11   15    7    2    4    8    9    8    7    5    4    3    6
4695 4696 4697 4698 4699 4700 4701 4702 4703 4704 4705 4706 4707 4708 4709 4710
  12    9    5    8    8    5    3    3    8   11    6    1    2    4    3    2
4711 4712 4713 4714 4715 4716 4717 4718 4719 4720 4721 4722 4723 4724 4725 4726
   2    1    2    6    5    2    1    1    5    6    2    1    2    2    3    4
4727 4728 4729 4730 4731 4732 4733 4734 4735 4736 4737 4739 4740 4741 4742 4744
   3    2    3    4    4    3    1    1    3    3    1    2    5    4    1    1
4745 4746 4747 4751 4752 4753 4756 4757 4758 4759 4760 4761 4762 4763 4764 4765
   3    3    1    2    4    2    1    3    3    1    1    2    1    1    2    2
4766 4767 4768 4772 4773 4774 4783 4784 4785 4788 4789 4790 4795 4796 4797 4800
   3    3    1    1    2    1    1    2    1    1    2    1    1    2    1    1
4801 4802 4804 4805 4806 4809 4810 4811
   2    1    1    2    1    1    2    1
> more Result
c running_time(sec)                     3761.3
c number_of_nodes                       8191
c number_of_2-reductions                86886
c max_tree_depth                        12
c number_of_1-autarkies                 1383488
c splitting_cases                       4096

> ProcessSplitViaOKsolver SplitViaOKsolver_D12SDInstances17_2011-08-22-150706
> cd Process_SplitViaOKsolver_D12SDInstances17_2011-08-22-150706_2011-08-23-131520

> E=read_processsplit_minisat()
4096: 53.97m, sum-cfs=1.808982e+07, mean-t=0.791s, mean-cfs=4416
$t:
   Min. 1st Qu.  Median    Mean 3rd Qu.    Max.
 0.5969  0.7579  0.7949  0.7905  0.8279  0.9629
sd= 0.05480191
     95%      96%      97%      98%      99%     100%
0.872867 0.877866 0.883865 0.889864 0.900913 0.962853
sum= 3237.906
$cfs:
   Min. 1st Qu.  Median    Mean 3rd Qu.    Max.
   2884    4159    4483    4416    4752    5961
sd= 475.7205
    95%     96%     97%     98%     99%    100%
5093.25 5123.40 5175.15 5236.00 5343.20 5961.00
sum= 18089822
$t ~ $cfs:
              Estimate Std. Error t value  Pr(>|t|)
(Intercept) 3.1306e-01 2.7626e-03  113.32 < 2.2e-16 ***
E$cfs       1.0811e-04 6.2193e-07  173.82 < 2.2e-16 ***
R-squared: 0.8807
     \endverbatim
     Trying instead with D=10 and D=14.
     </li>
     <li> We should also try the n-interpretation. </li>
    </ul>
   </li>
  </ul>

*/
