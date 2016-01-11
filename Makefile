ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

# Uncomment if SNMP++ compiled with SNMPv3 support
#DES		= -ldes
SNMPINC 	= /usr/local/include
SNMPLIB		= /usr/local/lib/libsnmp++.a $(DES)

#
# Module name
#
MOD      =  nssnmp.so

#
# Objects to build.
#
MODOBJS     = nssnmp.o

#
# Library Tcl files
#
PROCS	= nsmib_procs.tcl

INSTALL += install-procs

CFLAGS	 += -I$(SNMPINC)
MODLIBS	 = $(SNMPLIB)

include  $(NAVISERVER)/include/Makefile.module

CC	= g++
LDSO	= g++ -shared

install-procs: $(PROCS)
	for f in $(PROCS); do $(INSTALL_SH) $$f $(INSTTCL)/; done

nsmibdump:	nsmibdump.c
	gcc -o nsmibdump nsmibdump.c -lsmi

snmp_pp:
	rm -rf snmp++
	wget -c -O /tmp/snmp++.tar.gz http://www.agentpp.com/snmp++v3.2.21.tar.gz
	tar -xzf /tmp/snmp++.tar.gz
	sed -i 's/\/\/ #define _NO_SNMPv3/#define _NO_SNMPv3/' snmp++/include/snmp_pp/config_snmp_pp.h
	make -C snmp++/src -f Makefile.linux USEROPTS="-g -fPIC" install
	rm -rf snmp++

