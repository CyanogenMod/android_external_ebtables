# ebtables Makefile

PROGNAME:=ebtables
PROGVERSION:=2.0.7
PROGDATE:=January\ 2004

# default paths
LIBDIR:=/usr/lib
MANDIR:=/usr/local/man
BINDIR:=/sbin
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

BINFILE:=$(BINDIR)/ebtables

PROGSPECS:=-DPROGVERSION=\"$(PROGVERSION)\" \
	-DPROGNAME=\"$(PROGNAME)\" \
	-DPROGDATE=\"$(PROGDATE)\" \
	-D_PATH_ETHERTYPES=\"$(ETHERTYPESFILE)\"


all: ebtables

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

ebtables: $(OBJECTS)
	$(LD) -shared -soname libebtc.so -o libebtc.so -lc $(OBJECTS2)
	$(CC) $(CFLAGS) -o $@ ebtables.o -I$(KERNEL_INCLUDES) -L/root/ \
	-L. -Lextensions/ -lebtc $(EXT_LIBSI)
	

$(MANDIR)/man8/ebtables.8: ebtables.8
	mkdir -p $(@D)
	install -m 0644 -o root -g root $< $@

$(ETHERTYPESFILE): ethertypes
	mkdir -p $(@D)
	install -m 0644 -o root -g root $< $@

.PHONY: exec
exec: ebtables
	mkdir -p $(BINDIR)
	install -m 0755 -o root -g root $< $(BINFILE)

.PHONY: install
install: $(MANDIR)/man8/ebtables.8 $(ETHERTYPESFILE) exec
	mkdir -p $(LIBDIR)
	install -m 0755 extensions/*.so $(LIBDIR)
	install -m 0755 *.so $(LIBDIR)

.PHONY: clean
clean:
	rm -f ebtables
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
