# Standard part of Makefile for topdir.
TOPLEVEL_INCLUDED=YES

ifndef KERNEL_DIR
KERNEL_DIR=include/linux
endif
ARPTABLES_VERSION:=0.0.3
OLD_ARPTABLES_VERSION:=0.0.2
MANDIR?=/usr/local/man

PREFIX:=/usr/local
LIBDIR:=$(PREFIX)/lib
BINDIR:=$(PREFIX)/sbin
MANDIR:=$(PREFIX)/man
INCDIR:=$(PREFIX)/include
BINFILE:=$(BINDIR)/arptables

# directory for new arptables releases
RELEASE_DIR:=/tmp

COPT_FLAGS:=-O2
CFLAGS:=$(COPT_FLAGS) -Wall -Wunused -I$(KERNEL_DIR)/include/ -Iinclude/ -DARPTABLES_VERSION=\"$(ARPTABLES_VERSION)\" #-g -DDEBUG #-pg # -DARPTC_DEBUG

EXTRAS+=iptables iptables.o
EXTRA_INSTALLS+=$(DESTDIR)$(BINDIR)/iptables $(DESTDIR)$(MANDIR)/man8/iptables.8

ifndef ARPT_LIBDIR
ARPT_LIBDIR:=$(LIBDIR)/arptables
endif

include extensions/Makefile

all: arptables

arptables.o: arptables.c
	$(CC) $(CFLAGS) -DIPT_LIB_DIR=\"$(IPT_LIBDIR)\" -c -o $@ $<

arptables-standalone.o: arptables-standalone.c
	$(CC) $(CFLAGS) -DIPT_LIB_DIR=\"$(IPT_LIBDIR)\" -c -o $@ $<

libarptc/libarptc.o: libarptc/libarptc.c libarptc/libarptc_incl.c
	$(CC) $(CFLAGS) -DIPT_LIB_DIR=\"$(IPT_LIBDIR)\" -c -o $@ $<

arptables: arptables-standalone.o arptables.o libarptc/libarptc.o $(EXT_OBJS)
	$(CC) $(CFLAGS)  -o $@ $^

$(DESTDIR)$(BINDIR)/arptables: arptables
	@[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	cp $< $@

$(MANDIR)/man8/arptables.8: arptables.8
	mkdir -p $(@D)
	install -m 0644 -o root -g root $< $@

.PHONY: exec
exec: arptables
	install -m 0755 -o root -g root $< $(BINFILE)

.PHONY: install
install: $(MANDIR)/man8/arptables.8 exec

.PHONY: clean
clean:
	rm -f arptables
	rm -f *.o *.c~
	rm -f extensions/*.o extensions/*.c~
	rm -f libarptc/*.o libarptc/*.c~

DIR:=arptables-v$(ARPTABLES_VERSION)
# This is used to make a new userspace release
.PHONY: release
release:
	mkdir -p include/linux/netfilter_arp
	install -m 0644 -o root -g root \
		$(KERNEL_DIR)/include/linux/netfilter_arp.h include/linux/
	install -m 0644 -o root -g root \
		$(KERNEL_DIR)/include/linux/netfilter_arp/*.h \
		include/linux/netfilter_arp/
	install -m 0644 -o root -g root \
		include/netfilter_arp.h include/linux/netfilter_arp.h
	install -m 0644 -o root -g root \
		include/arp_tables.h include/linux/netfilter_arp/arp_tables.h
	make clean
	cd ..;tar -c $(DIR) | gzip >$(DIR).tar.gz
