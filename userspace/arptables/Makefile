ARPTABLES_VERSION:=0.0.3-3

KERNEL_DIR:=./
# default paths
PREFIX:=/usr/local
LIBDIR:=$(PREFIX)/lib
BINDIR:=$(PREFIX)/sbin
MANDIR:=$(PREFIX)/man
DESTDIR:=

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

$(DESTDIR)$(MANDIR)/man8/arptables.8: arptables.8
	mkdir -p $(@D)
	install -m 0644 -o root -g root $< $@

$(DESTDIR)$(BINDIR)/arptables: arptables
	mkdir -p $(DESTDIR)$(BINDIR)
	install -m 0755 -o root -g root $< $@

.PHONY: install
install: $(DESTDIR)$(MANDIR)/man8/arptables.8 $(DESTDIR)$(BINDIR)/arptables

.PHONY: clean
clean:
	rm -f arptables
	rm -f *.o *~
	rm -f extensions/*.o extensions/*~
	rm -f libarptc/*.o libarptc/*~
	rm -f include/*~ include/libarptc/*~

DIR:=arptables-v$(ARPTABLES_VERSION)
CVSDIRS:=CVS extensions/CVS libarptc/CVS include/CVS include/libarptc/CVS
# This is used to make a new userspace release
.PHONY: release
release:
	rm -rf $(CVSDIRS)
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
