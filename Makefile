# ebtables Makefile

KERNEL_DIR?=/usr/src/linux
PROGNAME:=ebtables
PROGVERSION:="2.0.1"
PROGDATE:="October 2002"

MANDIR?=/usr/local/man
CFLAGS:=-Wall -Wunused
CC:=gcc
include extensions/Makefile

# Some kernel testers prefer to use a symlink for /usr/include/linux
ifeq ($(SYMLINK), y)
KERNEL_INCLUDES=symlink
else
KERNEL_INCLUDES=headers
endif

all:	ebtables

.PHONY: headers
headers:
	mkdir -p /usr/include/linux/netfilter_bridge
	cp -f $(KERNEL_DIR)/include/linux/netfilter_bridge/* \
		/usr/include/linux/netfilter_bridge/
	cp -f $(KERNEL_DIR)/include/linux/netfilter_bridge.h \
		/usr/include/linux/netfilter_bridge.h
	cp -f $(KERNEL_DIR)/include/linux/if_ether.h \
		/usr/include/linux/if_ether.h

.PHONY: symlink
symlink:
	rm -f /usr/include/linux
	ln -fs $(KERNEL_DIR)/include/linux /usr/include/linux

communication.o: communication.c include/ebtables_u.h
	$(CC) $(CFLAGS) -DPROGVERSION=\"$(PROGVERSION)\" -c -o $@ $<

ebtables.o: ebtables.c include/ebtables_u.h
	$(CC) $(CFLAGS) -DPROGVERSION=\"$(PROGVERSION)\" \
	-DPROGNAME=\"$(PROGNAME)\" -DPROGDATE=\"$(PROGDATE)\" -c -o $@ $<

ebtables: ebtables.o communication.o $(EXT_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(MANDIR)/man8/ebtables.8: ebtables.8
	mkdir -p $(@D)
	install -m 0644 -o root -g root $< $@

/etc/ethertypes: ethertypes
	mkdir -p $(@D)
	install -m 0644 -o root -g root $< $@
.PHONY: exec
exec: ebtables
	install -m 0755 -o root -g root $< /sbin/ebtables

install: $(MANDIR)/man8/ebtables.8 $(KERNEL_INCLUDES) \
	ebtables /etc/ethertypes exec

clean:
	rm -f ebtables
	rm -f *.o *.c~
	rm -f extensions/*.o extensions/*.c~
