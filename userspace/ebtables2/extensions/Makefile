#! /usr/bin/make

EXT_FUNC+=nat arp ip standard log redirect vlan
EXT_TABLES+=filter nat broute
EXT_OBJS+=$(foreach T,$(EXT_FUNC), extensions/ebt_$(T).o)
EXT_OBJS+=$(foreach T,$(EXT_TABLES), extensions/ebtable_$(T).o)

extensions/ebt_%.o: extensions/ebt_%.c include/ebtables_u.h
	$(CC) $(CFLAGS) -c -o $@ $<
extensions/ebtable_%.o: extensions/ebtable_%.c
	$(CC) $(CFLAGS) -c -o $@ $<

