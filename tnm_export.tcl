#!/usr/bin/env scotty

# Function for creation of ns_mib initialization directives using scotty
proc tnm_export { { root iso.org } { file_name "" } } {
    
    if { $file_name != "" } {
      set fd [open $file_name w]
    } else {
      set fd stdout
    }
    Tnm::mib walk v $root {
       set enum ""
       set type [Tnm::mib macro $v]
       if { [catch { set hint [Tnm::mib displayhint [Tnm::mib type $v]] }] } { set hint "" }
       switch $type {
        "" -
        OBJECT-TYPE {
          set type [Tnm::mib syntax $v]
        }
       }
       switch $type {
        Integer32 {
          # Take first 99 enum values
          for { set i 1 } { $i < 99 } { incr i } {
            set val [Tnm::mib format $v $i]
            if { $val == $i || 
                 [string is integer -strict [string index $val 0]] } { break }
            append enum "${val}($i) "
          }  
        }
       }
       puts $fd "ns_mib set [Tnm::mib oid $v] [Tnm::mib module $v] [Tnm::mib label $v] {$type} {$hint} $enum"
    }
    if { $fd != "stdout" } { close $fd }
    return
}

tnm_export iso.org nsmib_procs.tcl

