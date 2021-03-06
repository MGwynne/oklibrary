# Matthew Gwynne, 2.6.2011 (Swansea)
# Copyright 2011 Oliver Kullmann
# This file is part of the OKlibrary. OKlibrary is free software; you can redistribute 
# it and/or modify it under the terms of the GNU General Public License as published by
# the Free Software Foundation and included in this library; either version 3 of the 
# License, or any later version.


# Extracts the numerical data from output of precosat236, in a single line.

BEGIN {
  rn=0; rc=0; t=0; sat=2; cfs=0; dec=0; rts=0; r1=0; mem=0; rnd=0; skip=0; enl=0;
  shk=0; resc=0; rebi=0; simp=0;red=0; nfix=0; neq=0; nel=0; nmg=0; elres=0;
  elph=0; elr=0; sb=0; sbn=0.0; sba=0.0; sbx=0.0; sbi=0.0; ar=0; arx=0; pb=0;
  pbph=0; pbr=0; pbf=0; pblf=0; pbmg=0; sccnt=0; sccf=0; sccm=0; hshu=0; hshm=0;
  minln=0; mindel=0; minst=0; mind=0; subf=0; subb=0; subdm=0; strf=0; strb=0;
  dom=0; domh=0; domlow=0; mpr=0; memr=0; }
/^c +found header 'p cnf/ { rn=$6; rc=$7; sub(/'/,"",rc); }
/^c [0-9]+.[0-9]+ seconds, [0-9]+ MB max, [0-9]+ MB/ { t=$2; mem=$4; memr=$7; }
/^s +UNSATISFIABLE *$/ { sat=0; }
/^s +SATISFIABLE *$/ { sat=1; }
/^\(*** CAUGHT SIGNAL +/ { sat=2; }
/^c +[0-9]+ conflicts, [0-9]+ decisions,/ { cfs=$2; dec=$4; rnd=$6; }
/^c +[0-9]+ iterations, [0-9]+ restarts,/ { its=$2; rts=$4; skip=$6; }
/^c +[0-9]+ enlarged, [0-9]+ shrunken,/ { enl=$2; shk=$4; resc=$6; rebi=$8; }
/^c +[0-9]+ simplifications, [0-9]+ reductions/ { simp=$2; red=$4; }
/^c +vars: [0-9]+ fixed, [0-9]+ equiv,/ { nfix=$3; neq=$5; nel=$7; nmg=$9; }
/^c +elim: [0-9]+ resolutions,/ { elres=$3; elph=$5; elr=$7; }
/c +sbst: [0-9\.]+% substituted,/ { 
  sb=$3; sub(/%/,"",sb); sbn=$5; sub(/%/,"",sbn); sba=$7;
  sub(/%/,"",sba); sbx=$9; sub(/%/,"",sbx); sbi=$11; sub(/%/,"",sbi); }
/^c +arty: [0-9\.]+ and [0-9\.]+ xor average arity/ { ar=$3; arx=$5; }
/^c +prbe: [0-9]+ probed, [0-9]+ phases,/ { pb=$3; pbph=$5; pbr=$7; }
/^c +prbe: [0-9]+ failed, [0-9]+ lifted,/ { pbf=$3; pblf=$5; pbmg=$7; }
/^c +sccs: [0-9]+ non trivial,/ { sccnt=$3; sccf=$6; sccm=$8; }
/^c +hash: [0-9]+ units, [0-9]+ merged/ { hshu=$3; hshm=$5; }
/^c +mins: [0-9]+ learned, [0-9]+% deleted,/ {
  minln=$3; mindel=$5; sub(/%/,"",mindel); minst=$7; mind=$9; }
/^c +subs: [0-9]+ forward, [0-9]+ backward,/ { subf=$3; subb=$5; subdm=$7; }
/^c +strs: [0-9]+ forward, [0-9]+ backward/ { strf=$3; strb=$5; }
/^c +doms: [0-9]+ dominators, [0-9]+ high,/ { dom=$3; domh=$5; domlow=$7; }
/^c +prps: [0-9]+ propagations, [0-9]+.[0-9]+ megaprops/ { r1=$3; mpr=$5; }
END {
  print rn " " rc " " t " " sat " " cfs " " dec " " rts " " r1 " " mem " " \
    rnd " " its " " skip " " enl " " shk " " resc " " rebi " " simp " " \
    red " " nfix " " neq " " nel " " nmg " " sb " " sbn " " sba " " sbx " " \
    sbi " " ar " " arx " " pb " " pbph " " pbr " " pbf " " pblf " " pbmg " " \
    sccnt " " sccf " " sccm " " hshu " " hshm " " minln " " mindel " " \
    minst " " mind " " subf " " subb " " subdm " " strf " " strb " " dom " " \
    domh " " domlow " " mpr " " memr }
