# Standard part of Makefile for topdir.
TOPLEVEL_INCLUDED=YES

ifndef KERNEL_DIR
KERNEL_DIR=include/linux
endif
ARPTABLES_VERSION:=0.0.3
OLD_ARPTABLES_VERSION:=0.0.2

# default paths
PREFIX:=/usr/local
LIBDIR:=$(PREFIX)/lib
BINDIR:=$(PREFIX)/sbin
MANDIR:=$(PREFIX)/man
DESTDIR:=


# directory for new arptables releases
RELEASE_DIR:=/tmp

COPT_FLAGS:=-O2
CFLAGS:=$(COPT_FLAGS) -Wall -Wunused -I$(KERNEL_DIR)/include/ -Iinclude/ -DARPTABLES_VERSION=\"$(ARPTABLES_VERSION)\" #-g -DDEBUG #-pg # -DARPTC_DEBUG

ifndef ARPT_LIBDIR
ARPT_LIBDIR:=$(LIBDIR)/arptables
endif

include extensions/Makefile

all: arptables

arptables.o: arptables.c
	$(CC) $(CFLAGS) -c -o $@ $<

arptables-standalone.o: arptables-standalone.c
	$(CC) $(CFLAGS) -c -o $@ $<

libarptc/libarptc.o: libarptc/libarptc.c libarptc/libarptc_incl.c
	$(CC) $(CFLAGS) -c -o $@ $<

arptables: arptables-standalone.o arptables.o libarptc/libarptc.o $(EXT_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(MANDIR)/man8/arptables.8: arptables.8
	mkdir -p $(DESTDIR)$(@D)
	install -m 0644 -o root -g root $< $(DESTDIR)$@

.PHONY: exec
exec: arptables
	mkdir -p $(DESTDIR)$(BINDIR)
	install -m 0755 -o root -g root $< $(DESTDIR)$(BINDIR)/arptables

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
		include/arp_tables.h include/linux/netfilter_arp/arp_tables.h
	make clean
	cd ..;tar -c $(DIR) | gzip >$(DIR).tar.gz
