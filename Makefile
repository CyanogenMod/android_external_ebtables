# ebtables Makefile

PROGNAME:=ebtables
PROGVERSION:="2.0.1"
PROGDATE:="October 2002"

MANDIR?=/usr/local/man
CFLAGS:=-Wall -Wunused
CC:=gcc
include extensions/Makefile

OBJECTS:=getethertype.o ebtables.o communication.o $(EXT_OBJS)

# Use the option NONSTANDARD=y when you don't want to use the kernel includes
# that are included in this package. You should set KERNEL_INCLUDES to
# the right directory (eg /usr/src/linux/include).
# You should only need this when compiling the CVS or when adding new code.
ifeq ($(NONSTANDARD), y)
KERNEL_INCLUDES?=/usr/include/
else
KERNEL_INCLUDES:=include/
endif

#ETHERTYPESFILE:="/etc/ethertypes"
ETHERTYPESFILE:="/usr/local/etc/ethertypes"

PROGSPECS:=-DPROGVERSION=\"$(PROGVERSION)\" \
	-DPROGNAME=\"$(PROGNAME)\" \
	-DPROGDATE=\"$(PROGDATE)\" \
	-D_PATH_ETHERTYPES=\"$(ETHERTYPESFILE)\"


all: ebtables

communication.o: communication.c include/ebtables_u.h
	$(CC) $(CFLAGS) $(PROGSPECS) -c -o $@ $< -I$(KERNEL_INCLUDES)

getethertype.o: getethertype.c include/ethernetdb.h
	$(CC) $(CFLAGS) $(PROGSPECS) -c -o $@ $< -Iinclude/

ebtables.o: ebtables.c include/ebtables_u.h
	$(CC) $(CFLAGS) $(PROGSPECS) -c -o $@ $< -I$(KERNEL_INCLUDES)

ebtables: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ -I$(KERNEL_INCLUDES)

$(MANDIR)/man8/ebtables.8: ebtables.8
	mkdir -p $(@D)
	install -m 0644 -o root -g root $< $@

/etc/ethertypes: ethertypes
	mkdir -p $(@D)
	install -m 0644 -o root -g root $< $@

.PHONY: exec
exec: ebtables
	install -m 0755 -o root -g root $< /sbin/ebtables

.PHONY: install
install: $(MANDIR)/man8/ebtables.8 ebtables /etc/ethertypes exec

.PHONY: clean
clean:
	rm -f ebtables
	rm -f *.o *.c~
	rm -f extensions/*.o extensions/*.c~

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
	make clean
	cd ..;tar -c $(DIR) | gzip >$(DIR).tar.gz
