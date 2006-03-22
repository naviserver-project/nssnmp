ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

# Uncomment if SNMP++ compiled with SNMPv3 support
#DES		= -ldes
SNMPINC 	= /usr/local/include/snmp++
SNMPLIB		= -lsnmp++ $(DES)

#
# Module name
#
MOD      =  nssnmp.so

#
# Objects to build.
#
OBJS     = nssnmp.o

#
# Library Tcl files
#
PROCS	= nsmib_procs.tcl nsradius_procs.tcl syslog_procs.tcl

INSTALL += install-procs

CFLAGS	 += -I$(SNMPINC)
MODLIBS	 = $(SNMPLIB)

include  $(NAVISERVER)/include/Makefile.module

CC	= g++
LDSO	= g++ -shared -nostartfiles

install-procs: $(PROCS)
	for f in $(PROCS); do $(INSTALL_SH) $$f $(INSTTCL)/; done

nsmibdump:	nsmibdump.c
	gcc -o nsmibdump nsmibdump.c -lsmi
