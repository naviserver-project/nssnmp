# Retrieve ifTable columns

set fd [ns_snmp create localhost -community public]
set table(count) 0
set table(header) { ifIndex ifDescr }

ns_snmp walk $fd [ns_mib oid ifTable] var {
    set oid [lindex $var 0]
    set ifIndex [lindex [split $oid "."] end]
    lappend table($ifIndex) [ns_mib value $oid [lindex $var 2]]
    # Add data column names to column header
    if { $ifIndex == 1 } {
      lappend table(header) [ns_mib label $oid]
    }
}

ns_snmp destroy $fd

ns_log debug [array get table]

# Example of trap handler, should be placed somewhere under modules/
# directory to be loaded on startup
proc snmp_trap_handler {} {

    set ipaddr [ns_trap address]
    set oid [nms::mib::label [ns_trap oid]]
    set enterprise [nms::mib::label [ns_trap enterprise]]
    set uptime [ns_trap uptime]
    set vars ""
    foreach vb [ns_trap vb] {
      append vars "[nms::mib::label [lindex $vb 0]]([lindex $vb 1]) = [lindex $vb 2], "
    }
    ns_log Notice TRAP: From: $ipaddr, Enterprise: $enterprise, OID: $oid, Uptime: $uptime, $vars
}

