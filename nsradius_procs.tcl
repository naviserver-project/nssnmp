# Simple RADIUS server

proc RadiusServer {} {

    ns_log debug Request: [ns_radiusreq array]
    switch -- [ns_radiusreq get code] {
     1 {
       set user [ns_radiusreq get User-Name]
       set passwd [ns_radiusreq get User-Password]
       ns_log debug User $user Password $passwd
       if { $user == "test" && $passwd == "test" } {
         ns_radiusreq set code 2 Reply-Message Verified
       } else {
         ns_radiusreq set code 3 Reply-Message "Wrong username/password"
       }
     }
    }
}

# Add localhost client
ns_radiusclient add localhost secret

# Standard attributes
ns_radiusdict add User-Name 1 0 string
ns_radiusdict add Password 2 0 string
ns_radiusdict add CHAP-Password 3 0 string
ns_radiusdict add NAS-IP-Address 4 0 ipaddr
ns_radiusdict add NAS-Port-Id 5 0 integer
ns_radiusdict add Service-Type 6 0 integer
ns_radiusdict add Framed-Protocol 7 0 integer
ns_radiusdict add Framed-IP-Address 8 0 ipaddr
ns_radiusdict add Framed-IP-Netmask 9 0 ipaddr
ns_radiusdict add Framed-Routing 10 0 integer
ns_radiusdict add Filter-Id 11 0 string
ns_radiusdict add Framed-MTU 12 0 integer
ns_radiusdict add Framed-Compression 13 0 integer
ns_radiusdict add Login-IP-Host 14 0 ipaddr
ns_radiusdict add Login-Service 15 0 integer
ns_radiusdict add Login-TCP-Port 16 0 integer
ns_radiusdict add Reply-Message 18 0 string
ns_radiusdict add Callback-Number 19 0 string
ns_radiusdict add Callback-Id 20 0 string
ns_radiusdict add Framed-Route 22 0 string
ns_radiusdict add Framed-IPX-Network 23 0 ipaddr
ns_radiusdict add State 24 0 string
ns_radiusdict add Class 25 0 string
ns_radiusdict add Vendor-Specific 26 0 string
ns_radiusdict add Session-Timeout 27 0 integer
ns_radiusdict add Idle-Timeout 28 0 integer
ns_radiusdict add Termination-Action 29 0 integer
ns_radiusdict add Called-Station-Id 30 0 string
ns_radiusdict add Calling-Station-Id 31 0 string
ns_radiusdict add NAS-Identifier 32 0 string
ns_radiusdict add Proxy-State 33 0 string
ns_radiusdict add Login-LAT-Service 34 0 string
ns_radiusdict add Login-LAT-Node 35 0 string
ns_radiusdict add Login-LAT-Group 36 0 string
ns_radiusdict add Framed-AppleTalk-Link 37 0 integer
ns_radiusdict add Framed-AppleTalk-Network 38 0 integer
ns_radiusdict add Framed-AppleTalk-Zone 39 0 string
ns_radiusdict add Acct-Status-Type 40 0 integer
ns_radiusdict add Acct-Delay-Time 41 0 integer
ns_radiusdict add Acct-Input-Octets 42 0 integer
ns_radiusdict add Acct-Output-Octets 43 0 integer
ns_radiusdict add Acct-Session-Id 44 0 string
ns_radiusdict add Acct-Authentic 45 0 integer
ns_radiusdict add Acct-Session-Time 46 0 integer
ns_radiusdict add Acct-Input-Packets 47 0 integer
ns_radiusdict add Acct-Output-Packets 48 0 integer
ns_radiusdict add Acct-Terminate-Cause 49 0 integer
ns_radiusdict add Acct-Multi-Session-Id 50 0 string
ns_radiusdict add Acct-Link-Count 51 0 integer
ns_radiusdict add CHAP-Challenge 60 0 string
ns_radiusdict add NAS-Port-Type 61 0 integer
ns_radiusdict add Port-Limit 62 0 integer
ns_radiusdict add Login-LAT-Port 63 0 integer
ns_radiusdict add Connect-Info 77 0 string
ns_radiusdict add Old-Huntgroup-Name 221 0 string
ns_radiusdict add Fall-Through 500 0 integer
ns_radiusdict add Add-Port-To-IP-Address 501 0 integer
ns_radiusdict add Exec-Program 502 0 string
ns_radiusdict add Exec-Program-Wait 503 0 string
ns_radiusdict add User-Category 1029 0 string
ns_radiusdict add Group-Name 1030 0 string
ns_radiusdict add Huntgroup-Name 1031 0 string
ns_radiusdict add Simultaneous-Use 1034 0 integer
ns_radiusdict add Strip-User-Name 1035 0 integer
ns_radiusdict add Old-Fall-Through 1036 0 integer
ns_radiusdict add Old-Add-Port-To-IP-Address 1037 0 integer
ns_radiusdict add Old-Exec-Program 1038 0 string
ns_radiusdict add Old-Exec-Program-Wait 1039 0 string
ns_radiusdict add Hint 1040 0 string
ns_radiusdict add Pam-Auth 1041 0 string
ns_radiusdict add Login-Time 1042 0 string
ns_radiusdict add Realm 1045 0 string
ns_radiusdict add Expiration 21 0 date
ns_radiusdict add Auth-Type 1000 0 integer
ns_radiusdict add Menu 1001 0 string
ns_radiusdict add Termination-Menu 1002 0 string
ns_radiusdict add Prefix 1003 0 string
ns_radiusdict add Suffix 1004 0 string
ns_radiusdict add Group 1005 0 string
ns_radiusdict add Crypt-Password 1006 0 string
ns_radiusdict add Connect-Rate 1007 0 integer

# Tunnel attributes
ns_radiusdict add Tunnel-Type 64 0 integer
ns_radiusdict add Tunnel-Medium-Type 65 0 integer
ns_radiusdict add Acct-Tunnel-Client-Endpoint 66 0 string
ns_radiusdict add Tunnel-Server-Endpoint 67 0 string
ns_radiusdict add Acct-Tunnel-Connection-Id 68 0 string
ns_radiusdict add Tunnel-Password 69 0 string
ns_radiusdict add Private-Group-Id 75 0 integer
ns_radiusdict add Tunnel-Assignment-ID 82 0 string

# Ascend attributes
ns_radiusdict add Ascend-FCP-Parameter 119 0 string
ns_radiusdict add Ascend-Modem-PortNo 120 0 integer
ns_radiusdict add Ascend-Modem-SlotNo 121 0 integer
ns_radiusdict add Ascend-Modem-ShelfNo 122 0 integer
ns_radiusdict add Ascend-Call-Attempt-Limit 123 0 integer
ns_radiusdict add Ascend-Call-Block-Duration 124 0 integer
ns_radiusdict add Ascend-Maximum-Call-Duration 125 0 integer
ns_radiusdict add Ascend-Temporary-Rtes 126 0 integer
ns_radiusdict add Ascend-Tunneling-Protocol 127 0 integer
ns_radiusdict add Ascend-Shared-Profile-Enable 128 0 integer
ns_radiusdict add Ascend-Primary-Home-Agent 129 0 string
ns_radiusdict add Ascend-Secondary-Home-Agent 130 0 string
ns_radiusdict add Ascend-Dialout-Allowed 131 0 integer
ns_radiusdict add Ascend-Client-Gateway 132 0 ipaddr
ns_radiusdict add Ascend-BACP-Enable 133 0 integer
ns_radiusdict add Ascend-DHCP-Maximum-Leases 134 0 integer
ns_radiusdict add Ascend-Client-Primary-DNS 135 0 ipaddr
ns_radiusdict add Ascend-Client-Secondary-DNS 136 0 ipaddr
ns_radiusdict add Ascend-Client-Assign-DNS 137 0 integer
ns_radiusdict add Ascend-User-Acct-Type 138 0 integer
ns_radiusdict add Ascend-User-Acct-Host 139 0 ipaddr
ns_radiusdict add Ascend-User-Acct-Port 140 0 integer
ns_radiusdict add Ascend-User-Acct-Key 141 0 string
ns_radiusdict add Ascend-User-Acct-Base 142 0 integer
ns_radiusdict add Ascend-User-Acct-Time 143 0 integer
ns_radiusdict add Ascend-Assign-IP-Client 144 0 ipaddr
ns_radiusdict add Ascend-Assign-IP-Server 145 0 ipaddr
ns_radiusdict add Ascend-Assign-IP-Global-Pool 146 0 string
ns_radiusdict add Ascend-DHCP-Reply 147 0 integer
ns_radiusdict add Ascend-DHCP-Pool-Number 148 0 integer
ns_radiusdict add Ascend-Expect-Callback 149 0 integer
ns_radiusdict add Ascend-Event-Type 150 0 integer
ns_radiusdict add Ascend-Session-Svr-Key 151 0 string
ns_radiusdict add Ascend-Multicast-Rate-Limit 152 0 integer
ns_radiusdict add Ascend-IF-Netmask 153 0 ipaddr
ns_radiusdict add Ascend-Remote-Addr 154 0 ipaddr
ns_radiusdict add Ascend-Multicast-Client 155 0 integer
ns_radiusdict add Ascend-FR-Circuit-Name 156 0 string
ns_radiusdict add Ascend-FR-LinkUp 157 0 integer
ns_radiusdict add Ascend-FR-Nailed-Grp 158 0 integer
ns_radiusdict add Ascend-FR-Type 159 0 integer
ns_radiusdict add Ascend-FR-Link-Mgt 160 0 integer
ns_radiusdict add Ascend-FR-N391 161 0 integer
ns_radiusdict add Ascend-FR-DCE-N392 162 0 integer
ns_radiusdict add Ascend-FR-DTE-N392 163 0 integer
ns_radiusdict add Ascend-FR-DCE-N393 164 0 integer
ns_radiusdict add Ascend-FR-DTE-N393 165 0 integer
ns_radiusdict add Ascend-FR-T391 166 0 integer
ns_radiusdict add Ascend-FR-T392 167 0 integer
ns_radiusdict add Ascend-Bridge-Address 168 0 string
ns_radiusdict add Ascend-TS-Idle-Limit 169 0 integer
ns_radiusdict add Ascend-TS-Idle-Mode 170 0 integer
ns_radiusdict add Ascend-DBA-Monitor 171 0 integer
ns_radiusdict add Ascend-Base-Channel-Count 172 0 integer
ns_radiusdict add Ascend-Minimum-Channels 173 0 integer
ns_radiusdict add Ascend-IPX-Route 174 0 string
ns_radiusdict add Ascend-FT1-Caller 175 0 integer
ns_radiusdict add Ascend-Backup 176 0 string
ns_radiusdict add Ascend-Call-Type 177 0 integer
ns_radiusdict add Ascend-Group 178 0 string
ns_radiusdict add Ascend-FR-DLCI 179 0 integer
ns_radiusdict add Ascend-FR-Profile-Name 180 0 string
ns_radiusdict add Ascend-Ara-PW 181 0 string
ns_radiusdict add Ascend-IPX-Node-Addr 182 0 string
ns_radiusdict add Ascend-Home-Agent-IP-Addr 183 0 ipaddr
ns_radiusdict add Ascend-Home-Agent-Password 184 0 string
ns_radiusdict add Ascend-Home-Network-Name 185 0 string
ns_radiusdict add Ascend-Home-Agent-UDP-Port 186 0 integer
ns_radiusdict add Ascend-Multilink-ID 187 0 integer
ns_radiusdict add Ascend-Num-In-Multilink 188 0 integer
ns_radiusdict add Ascend-First-Dest 189 0 ipaddr
ns_radiusdict add Ascend-Pre-Input-Octets 190 0 integer
ns_radiusdict add Ascend-Pre-Output-Octets 191 0 integer
ns_radiusdict add Ascend-Pre-Input-Packets 192 0 integer
ns_radiusdict add Ascend-Pre-Output-Packets 193 0 integer
ns_radiusdict add Ascend-Maximum-Time 194 0 integer
ns_radiusdict add Ascend-Disconnect-Cause 195 0 integer
ns_radiusdict add Ascend-Connect-Progress 196 0 integer
ns_radiusdict add Ascend-Data-Rate 197 0 integer
ns_radiusdict add Ascend-PreSession-Time 198 0 integer
ns_radiusdict add Ascend-Token-Idle 199 0 integer
ns_radiusdict add Ascend-Token-Immediate 200 0 integer
ns_radiusdict add Ascend-Require-Auth 201 0 integer
ns_radiusdict add Ascend-Number-Sessions 202 0 string
ns_radiusdict add Ascend-Authen-Alias 203 0 string
ns_radiusdict add Ascend-Token-Expiry 204 0 integer
ns_radiusdict add Ascend-Menu-Selector 205 0 string
ns_radiusdict add Ascend-Menu-Item 206 0 string
ns_radiusdict add Ascend-PW-Warntime 207 0 integer
ns_radiusdict add Ascend-PW-Lifetime 208 0 integer
ns_radiusdict add Ascend-IP-Direct 209 0 ipaddr
ns_radiusdict add Ascend-PPP-VJ-Slot-Comp 210 0 integer
ns_radiusdict add Ascend-PPP-VJ-1172 211 0 integer
ns_radiusdict add Ascend-PPP-Async-Map 212 0 integer
ns_radiusdict add Ascend-Third-Prompt 213 0 string
ns_radiusdict add Ascend-Send-Secret 214 0 string
ns_radiusdict add Ascend-Receive-Secret 215 0 string
ns_radiusdict add Ascend-IPX-Peer-Mode 216 0 integer
ns_radiusdict add Ascend-IP-Pool-Definition 217 0 string
ns_radiusdict add Ascend-Assign-IP-Pool 218 0 integer
ns_radiusdict add Ascend-FR-Direct 219 0 integer
ns_radiusdict add Ascend-FR-Direct-Profile 220 0 string
ns_radiusdict add Ascend-FR-Direct-DLCI 221 0 integer
ns_radiusdict add Ascend-Handle-IPX 222 0 integer
ns_radiusdict add Ascend-Netware-timeout 223 0 integer
ns_radiusdict add Ascend-IPX-Alias 224 0 integer
ns_radiusdict add Ascend-Metric 225 0 integer
ns_radiusdict add Ascend-PRI-Number-Type 226 0 integer
ns_radiusdict add Ascend-Dial-Number 227 0 string
ns_radiusdict add Ascend-Route-IP 228 0 integer
ns_radiusdict add Ascend-Route-IPX 229 0 integer
ns_radiusdict add Ascend-Bridge 230 0 integer
ns_radiusdict add Ascend-Send-Auth 231 0 integer
ns_radiusdict add Ascend-Send-Passwd 232 0 string
ns_radiusdict add Ascend-Link-Compression 233 0 integer
ns_radiusdict add Ascend-Target-Util 234 0 integer
ns_radiusdict add Ascend-Maximum-Channels 235 0 integer
ns_radiusdict add Ascend-Inc-Channel-Count 236 0 integer
ns_radiusdict add Ascend-Dec-Channel-Count 237 0 integer
ns_radiusdict add Ascend-Seconds-Of-History 238 0 integer
ns_radiusdict add Ascend-History-Weigh-Type 239 0 integer
ns_radiusdict add Ascend-Add-Seconds 240 0 integer
ns_radiusdict add Ascend-Remove-Seconds 241 0 integer
ns_radiusdict add Ascend-Data-Filter 242 0 string
ns_radiusdict add Ascend-Call-Filter 243 0 string
ns_radiusdict add Ascend-Idle-Limit 244 0 integer
ns_radiusdict add Ascend-Preempt-Limit 245 0 integer
ns_radiusdict add Ascend-Callback 246 0 integer
ns_radiusdict add Ascend-Data-Svc 247 0 integer
ns_radiusdict add Ascend-Force-56 248 0 integer
ns_radiusdict add Ascend-Billing-Number 249 0 string
ns_radiusdict add Ascend-Call-By-Call 250 0 integer
ns_radiusdict add Ascend-Transit-Number 251 0 string
ns_radiusdict add Ascend-Host-Info 252 0 string
ns_radiusdict add Ascend-PPP-Address 253 0 ipaddr
ns_radiusdict add Ascend-MPP-Idle-Percent 254 0 integer
ns_radiusdict add Ascend-Xmit-Rate 255 0 integer

# Cisco attributes
ns_radiusdict add Cisco-AVPair 1 9 string
ns_radiusdict add Cisco-Multilink-ID 187 9 integer
ns_radiusdict add Cisco-Num-In-Multilink 188 9 integer
ns_radiusdict add Cisco-Pre-Input-Octets 190 9 integer
ns_radiusdict add Cisco-Pre-Output-Octets 191 9 integer
ns_radiusdict add Cisco-Pre-Input-Packets 192 9 integer
ns_radiusdict add Cisco-Pre-Output-Packets 193 9 integer
ns_radiusdict add Cisco-Maximum-Time 194 9 integer
ns_radiusdict add Cisco-Disconnect-Cause 195 9 integer
ns_radiusdict add Cisco-Data-Rate 197 9 integer
ns_radiusdict add Cisco-PreSession-Time 198 9 integer
ns_radiusdict add Cisco-PW-Lifetime 208 9 integer
ns_radiusdict add Cisco-IP-Direct 209 9 integer
ns_radiusdict add Cisco-PPP-VJ-Slot-Comp 210 9 integer
ns_radiusdict add Cisco-PPP-Async-Map 212 9 integer
ns_radiusdict add Cisco-IP-Pool-Definition 217 9 integer
ns_radiusdict add Cisco-Asing-IP-Pool 218 9 integer
ns_radiusdict add Cisco-Route-IP 228 9 integer
ns_radiusdict add Cisco-Link-Compression 233 9 integer
ns_radiusdict add Cisco-Target-Util 234 9 integer
ns_radiusdict add Cisco-Maximum-Channels 235 9 integer
ns_radiusdict add Cisco-Data-Filter 242 9 integer
ns_radiusdict add Cisco-Call-Filter 243 9 integer
ns_radiusdict add Cisco-Idle-Limit 244 9 integer
ns_radiusdict add Cisco-Xmit-Rate 255 9 integer

# Livingston attributes
ns_radiusdict add LE-Terminate-Detail 2 307 string
ns_radiusdict add LE-Advice-of-Charge 3 307 string

# Shiva attributes
ns_radiusdict add Shiva-User-Attributes 51 166 string
ns_radiusdict add Shiva-User-Attributes 1 166 string
ns_radiusdict add Shiva-Called-Number 90 166 string
ns_radiusdict add Shiva-Calling-Number 91 166 string
ns_radiusdict add Shiva-Customer-Id 92 166 string
ns_radiusdict add Shiva-Type-Of-Service 93 166 integer
ns_radiusdict add Shiva-Link-Speed 94 166 integer
ns_radiusdict add Shiva-Links-In-Bundle 95 166 integer
ns_radiusdict add Shiva-Compression-Type 96 166 integer
ns_radiusdict add Shiva-Link-Protocol 97 166 integer
ns_radiusdict add Shiva-Network-Protocols 98 166 integer
ns_radiusdict add Shiva-Session-Id 99 166 integer
ns_radiusdict add Shiva-Disconnect-Reason 100 166 integer
ns_radiusdict add Shiva-Acct-Serv-Switch 101 166 ipaddr
ns_radiusdict add Shiva-Event-Flags 102 166 integer
ns_radiusdict add Shiva-Function 103 166 integer
ns_radiusdict add Shiva-Connect-Reason 104 166 integer
