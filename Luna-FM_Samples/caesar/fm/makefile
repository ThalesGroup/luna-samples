##############################################################################
#
# Copyright (c) 2018 SafeNet. All rights reserved.
#
# This file contains information that is proprietary to SafeNet and may not be
# distributed or copied without written consent from SafeNet.
#
##############################################################################

# default the FMSDK path
FMSDK?=/usr/safenet/lunafmsdk

LUNASDK=/usr/safenet/lunaclient

include $(FMSDK)/samples/fmconfig.mk

NAME = caesar

FMTARGETDIR ?= .

ODIR = $(FMTARGETDIR)/obj-ppc
BDIR = $(FMTARGETDIR)/bin-ppc


_OBJS = \
	hdr.o \
	caesar.o

OBJS = $(patsubst %,$(ODIR)/%,$(_OBJS))

INCLUDE += \
    /usr/safenet/lunaclient/samples/include \
    $(FMSDK)/include \
    $(FMSDK)/include/fm/hsm \
    $(FMSDK)/include/fm/host \
	../include


FMLIBS:= \
	fmsupt

DEFINES+=

L_FLAGS +=-Wl,-t

LIBS := -L$(FMLIBDIR) $(addprefix -l,$(FMLIBS))

C_FLAGS += -O2

I_OPT    := $(addprefix -I, $(INCLUDE))

all: $(BDIR)/$(NAME).bin

$(BDIR):
	mkdir -p $(BDIR)

$(ODIR):
	mkdir -p $(ODIR)

$(ODIR)/%.o: %.c $(ODIR)
	$(CC) -c $(I_OPT) $(DEFINES) $(C_FLAGS) -o$@ $<

$(BDIR)/$(NAME).bin : $(BDIR) $(OBJS)
	$(CC) $(L_FLAGS) $(L_FLAGS2) -o$@ $(OBJS) $(LIBS) -lgcc

clean:
	-rm -r $(BDIR) $(ODIR)

dirs: $(BDIR) $(ODIR)

