# ebtables Makefile

PROGNAME:=ebtables
PROGVERSION:=2.0.7
PROGDATE:=January\ 2004

# default paths
LIBDIR:=/usr/lib
MANDIR:=/usr/local/man
BINDIR:=/usr/sbin
ETCDIR:=/etc
DESTDIR:=

# include DESTDIR param
override LIBDIR:=$(DESTDIR)$(LIBDIR)
override MANDIR:=$(DESTDIR)$(MANDIR)
override BINDIR:=$(DESTDIR)$(BINDIR)
override ETCDIR:=$(DESTDIR)$(ETCDIR)


CFLAGS:=-Wall -Wunused
CC:=gcc
LD:=ld

ifeq ($(shell uname -m),sparc64)
CFLAGS+=-DEBT_MIN_ALIGN=8 -DKERNEL_64_USERSPACE_32
endif

include extensions/Makefile

OBJECTS2:=getethertype.o communication.o libebtc.o \
useful_functions.o

OBJECTS:=$(OBJECTS2) ebtables.o $(EXT_OBJS) $(EXT_LIBS)

KERNEL_INCLUDES?=include/

ETHERTYPESPATH?=$(ETCDIR)
ETHERTYPESFILE:=$(ETHERTYPESPATH)/ethertypes

PIPE_DIR?=/tmp/$(PROGNAME)-v$(PROGVERSION)
PIPE=$(PIPE_DIR)/ebtablesd_pipe
EBTD_CMDLINE_MAXLN?=2048
EBTD_ARGC_MAX?=50

BINFILE_EBT:=$(BINDIR)/$(PROGNAME)
BINFILE_EBTD:=$(BINDIR)/$(PROGNAME)d
BINFILE_EBTU:=$(BINDIR)/$(PROGNAME)u

PROGSPECS:=-DPROGVERSION=\"$(PROGVERSION)\" \
	-DPROGNAME=\"$(PROGNAME)\" \
	-DPROGDATE=\"$(PROGDATE)\" \
	-D_PATH_ETHERTYPES=\"$(ETHERTYPESFILE)\"

PROGSPECSD:=-DPROGVERSION=\"$(PROGVERSION)\" \
	-DPROGNAME=\"$(PROGNAME)\" \
	-DPROGDATE=\"$(PROGDATE)\" \
	-D_PATH_ETHERTYPES=\"$(ETHERTYPESFILE)\" \
	-DEBTD_CMDLINE_MAXLN=$(EBTD_CMDLINE_MAXLN) \
	-DEBTD_ARGC_MAX=$(EBTD_ARGC_MAX) \
	-DEBTD_PIPE=\"$(PIPE)\" \
	-DEBTD_PIPE_DIR=\"$(PIPE_DIR)\"

all: ebtables daemon

communication.o: communication.c include/ebtables_u.h
	$(CC) $(CFLAGS) $(PROGSPECS) -c -o $@ $< -I$(KERNEL_INCLUDES)

libebtc.o: libebtc.c include/ebtables_u.h
	$(CC) $(CFLAGS) $(PROGSPECS) -c -o $@ $< -I$(KERNEL_INCLUDES)

useful_functions.o: useful_functions.c include/ebtables_u.h
	$(CC) $(CFLAGS) $(PROGSPECS) -c -o $@ $< -I$(KERNEL_INCLUDES)

getethertype.o: getethertype.c include/ethernetdb.h
	$(CC) $(CFLAGS) $(PROGSPECS) -c -o $@ $< -Iinclude/

ebtables.o: ebtables.c include/ebtables_u.h
	$(CC) $(CFLAGS) $(PROGSPECS) -c -o $@ $< -I$(KERNEL_INCLUDES)

ebtables-standalone.o: ebtables-standalone.c ebtables.c include/ebtables_u.h
	$(CC) $(CFLAGS) $(PROGSPECS) -c $< ebtables.c -o $@ -I$(KERNEL_INCLUDES)

ebtables: $(OBJECTS) ebtables-standalone.o
	$(LD) -shared -soname libebtc.so -o libebtc.so -lc $(OBJECTS2)
	$(CC) $(CFLAGS) -o $@ ebtables-standalone.o -I$(KERNEL_INCLUDES) -L/root/ \
	-L. -Lextensions/ -lebtc $(EXT_LIBSI)

ebtablesu: ebtablesu.c
	$(CC) $(CFLAGS) $(PROGSPECSD) $< -o $@

ebtablesd.o: ebtablesd.c ebtables.c include/ebtables_u.h
	$(CC) $(CFLAGS) $(PROGSPECSD) -c $< ebtables.c -o $@  -I$(KERNEL_INCLUDES)

ebtablesd: $(OBJECTS) ebtablesd.o
	$(LD) -shared -soname libebtc.so -o libebtc.so -lc $(OBJECTS2)
	$(CC) $(CFLAGS) -o $@ ebtablesd.o -I$(KERNEL_INCLUDES) -L/root/ \
	-L. -Lextensions/ -lebtc $(EXT_LIBSI)

.PHONY: daemon
daemon: ebtablesd ebtablesu

$(MANDIR)/man8/ebtables.8: ebtables.8
	mkdir -p $(@D)
	install -m 0644 -o root -g root $< $@

$(ETHERTYPESFILE): ethertypes
	mkdir -p $(@D)
	install -m 0644 -o root -g root $< $@

.PHONY: exec
exec: ebtables daemon
	mkdir -p $(BINDIR)
	install -m 0755 -o root -g root $(PROGNAME) $(BINFILE_EBT)
	install -m 0755 -o root -g root $(PROGNAME)d  $(BINFILE_EBTD)
	install -m 0755 -o root -g root $(PROGNAME)u $(BINFILE_EBTU)

.PHONY: install
install: $(MANDIR)/man8/ebtables.8 $(ETHERTYPESFILE) exec
	mkdir -p $(LIBDIR)
	install -m 0755 extensions/*.so $(LIBDIR)
	install -m 0755 *.so $(LIBDIR)

.PHONY: clean
clean:
	rm -f ebtables ebtablesd ebtablesu
	rm -f *.o *.c~ *.so
	rm -f extensions/*.o extensions/*.c~ extensions/*.so

DIR:=$(PROGNAME)-v$(PROGVERSION)
# This is used to make a new userspace release
.PHONY: release
release:
	mkdir -p include/linux/netfilter_bridge
	install -m 0644 -o root -g root \
		$(KERNEL_INCLUDES)/linux/netfilter_bridge.h include/linux/
# To keep possible compile error complaints about undefined ETH_P_8021Q
# off my back
	install -m 0644 -o root -g root \
		$(KERNEL_INCLUDES)/linux/if_ether.h include/linux/
	install -m 0644 -o root -g root \
		$(KERNEL_INCLUDES)/linux/netfilter_bridge/*.h \
		include/linux/netfilter_bridge/
	install -m 0644 -o root -g root \
		include/ebtables.h include/linux/netfilter_bridge/
	make clean
	touch *
	touch extensions/*
	touch include/*
	touch include/linux/*
	touch include/linux/netfilter_bridge/*
	cd ..;tar -c $(DIR) | gzip >$(DIR).tar.gz

.PHONY: test_ulog
test_ulog: examples/ulog/test_ulog.c getethertype.o
	$(CC) $(CFLAGS)  $< -o test_ulog -I$(KERNEL_INCLUDES) -lc \
	getethertype.o
	mv test_ulog examples/ulog/

.PHONY: examples
examples: test_ulog
