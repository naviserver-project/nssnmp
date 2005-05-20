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
PROCS	= nsmib_procs.tcl

#
# Objects to clean
#
CLEAN   += clean-bak
INSTALL += install-procs

CFLAGS	 = -I$(SNMPINC) -I/usr/local/aolserver/include
MODLIBS	 = $(SNMPLIB)

include  $(NAVISERVER)/include/Makefile.module

CC	= g++
LDSO	= g++ -shared -nostartfiles

clean-bak:
	rm -rf *~ nsmibdump

install-procs: $(PROCS)
	$(INSTALL_SH) $(PROCS) $(INSTTCL)/

nsmibdump:	nsmibdump.c
	gcc -o nsmibdump nsmibdump.c -lsmi
