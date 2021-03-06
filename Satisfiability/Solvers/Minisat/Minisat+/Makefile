##
##  Makefile for Standard, Profile, Debug, and Release version of MiniSat
##

# Two new make-variables introduced by OK in order to be able to use
# local installations of GMP:
GMP_INCLUDE_OPTION =
GMP_LINK_OPTION = -lgmp
# And also introduced LFLAGS and ZLIB_INCLUDE_OPTION in order to use the
# local zlib-library.

CSRCS     = $(wildcard *.C)
CHDRS     = $(wildcard *.h)
COBJS     = $(addsuffix .o, $(basename $(CSRCS))) ADTs/Global.o ADTs/FEnv.o ADTs/File.o
#COBJS     = PbSolver_convertSort.o PbSolver.o PbSolver_convertAdd.o PbSolver_convertBdd.o PbSolver_convert.o Debug.o Hardware_adders.o Hardware_clausify.o Hardware_sorters.o Main.o MiniSat.o PbParser.o SatELite.o ADTs/Global.o ADTs/FEnv.o ADTs/File.o
PCOBJS    = $(addsuffix p,  $(COBJS))
DCOBJS    = $(addsuffix d,  $(COBJS))
RCOBJS    = $(addsuffix r,  $(COBJS))
R64COBJS  = $(addsuffix x,  $(COBJS))

EXEC      = minisat+

CXX       = g++
#CXX      = icpc
CFLAGS    = -Wall -ffloat-store 
CFLAGS   += -IADTs -include Global.h -include Main.h -D_FILE_OFFSET_BITS=64 
COPTIMIZE = -O3 #-fomit-frame-pointer # -falign-loops=4 -falign-functions=16 -foptimize-sibling-calls -finline-functions -fcse-follow-jumps -fcse-skip-blocks -frerun-cse-after-loop -frerun-loop-opt -fgcse


.PHONY : s p d r build clean depend

s:	WAY=standard
p:	WAY=profile
d:	WAY=debug
r:	WAY=release
rs:	WAY="release static / bignums"
rx:	WAY="release static / 64-bit integers"

s:	CFLAGS+=$(COPTIMIZE) -ggdb -D DEBUG
p:	CFLAGS+=$(COPTIMIZE) -pg -ggdb -D DEBUG
d:	CFLAGS+=-O0 -ggdb -D DEBUG
r:	CFLAGS+=$(COPTIMIZE) -D NDEBUG
rs:	CFLAGS+=$(COPTIMIZE) -D NDEBUG
rx:	CFLAGS+=$(COPTIMIZE) -D NDEBUG -D NO_GMP

s:	build $(EXEC)
p:	build $(EXEC)_profile
d:	build $(EXEC)_debug
r:	build $(EXEC)_release
rs:	build $(EXEC)_bignum_static
rx:	build $(EXEC)_64-bit_static

build:
	@echo Building $(EXEC) "("$(WAY)")"

clean:
	@rm -f $(EXEC) $(EXEC)_profile $(EXEC)_debug $(EXEC)_release $(EXEC)_static \
	  $(COBJS) $(PCOBJS) $(DCOBJS) $(RCOBJS) $(R64COBJS) depend.mak

## Build rule
%.o %.op %.od %.or %.ox: %.C
	@echo Compiling: $<
	@$(CXX) $(CFLAGS) $(ZLIB_INCLUDE_OPTION) $(GMP_INCLUDE_OPTION) -c -o $@ $<

## Linking rules (standard/profile/debug/release)
$(EXEC): $(COBJS)
	@echo Linking $(EXEC)
	@$(CXX) $(LFLAGS) $(COBJS) -lz $(GMP_LINK_OPTION) -ggdb -Wall -o $@ 

$(EXEC)_profile: $(PCOBJS)
	@echo Linking $@
	@$(CXX) $(LFLAGS) $(PCOBJS) -lz $(GMP_LINK_OPTION) -ggdb -Wall -pg -o $@

$(EXEC)_debug:	$(DCOBJS)
	@echo Linking $@
	@$(CXX) $(LFLAGS) $(DCOBJS) -lz $(GMP_LINK_OPTION) -ggdb -Wall -o $@

$(EXEC)_release: $(RCOBJS)
	@echo Linking $@
	@$(CXX) $(LFLAGS) $(RCOBJS) -lz $(GMP_LINK_OPTION) -Wall -o $@

$(EXEC)_bignum_static: $(RCOBJS)
	@echo Linking $@
	@$(CXX) $(LFLAGS) --static $(RCOBJS) -lz $(GMP_LINK_OPTION) -Wall -o $@

$(EXEC)_64-bit_static: $(R64COBJS)
	@echo Linking $@
	@$(CXX) $(LFLAGS) --static $(R64COBJS) -lz -Wall -o $@


## Make dependencies
depend:	depend.mak
depend.mak:	$(CSRCS) $(CHDRS)
	@echo Making dependencies...
	@$(CXX) -MM $(CSRCS) $(CFLAGS) $(ZLIB_INCLUDE_OPTION) > depend.mak
	@cp depend.mak /tmp/depend.mak.tmp
	@sed "s/o:/op:/" /tmp/depend.mak.tmp >> depend.mak
	@sed "s/o:/od:/" /tmp/depend.mak.tmp >> depend.mak
	@sed "s/o:/or:/" /tmp/depend.mak.tmp >> depend.mak
	@sed "s/o:/ox:/" /tmp/depend.mak.tmp >> depend.mak
	@rm /tmp/depend.mak.tmp

include depend.mak
