/* 
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1(the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis,WITHOUT WARRANTY OF ANY KIND,either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * Alternatively,the contents of this file may be used under the terms
 * of the GNU General Public License(the "GPL"),in which case the
 * provisions of GPL are applicable instead of those above.  If you wish
 * to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the
 * License,indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the GPL.
 * If you do not delete the provisions above,a recipient may use your
 * version of this file under either the License or the GPL.
 *
 * Author Vlad Seryakov vlad@crystalballinc.com
 * 
 */

/*
 * nssnmp.c -- SNMP module
 *
 * How it works
 *  It can make SNMP requests and receive SNMP traps.
 *
 *  ns_snmp command is used to create SNMP sessions and make requests.
 *  ns_snmp usage:
 *
 *    ns_snmp sessions
 *      Outputs currenttly open connections as Tcl list:
 *        id access_time host ...
 *
 *    ns_snmp gc
 *       Calls session garbage collector which closes inactive sessions
 *       according to idle_timeout parameter
 *
 *    ns_snmp create host {-port p -community c -writecommunity c -timeout t -retries r -version 1|2 -bulk b}
 *      creates new SNMP session for specified host. Optional parameters 
 *      can be specified.
 *      Example:
 *         ns_snmp create localhost -community aaa -bulk 25 -timeout 3
 *         Default SNMP version is 2c, some devices support only version 1
 *
 *    ns_snmp config #s name
 *      returns information about SNMP session
 *      where name can be one of -address,-port,-community,-writecommunity,-timeout,-retries
 *
 *    ns_snmp get #s OID ...
 *      retrieves one or more variables
 *      Example:
 *         set fd [ns_snmp create localhost]
 *         set val [ns_snmp get $fd get 1.3.6.1.2.1.2.2.1.6]
 *
 *    ns_snmp walk #s OID var script
 *      walks SNMP MIB tree and executes script for every variable which is 
 *      stored in specified Tcl variable var.
 *      Example:
 *         set fd [ns_snmp create localhost]
 *         ns_snmp walk $fd 1.3.6.1.2.1.2.2.1 vb { ns_log debug VB: $vb }
 *
 *    ns_snmp set #s OID type value
 *      sets SNMP variable with specified value
 *      where type is:
 *        i: INTEGER, u: unsigned INTEGER, t: TIMETICKS, a: IPADDRESS, o: OID, s: STRING
 *      Example:
 *         set fd [ns_snmp create localhost]
 *         ns_snmp set $fd 1.3.6.1.2.1.1.1 s "Linux"
 *
 *    ns_snmp trap #s ID EnterpriseID ?oid type value ... ?
 *    ns_snmp inform #s ID EnterpriseID ?oid type value ... ?
 *      sends SNMP trap
 *      where type is:
 *        i: INTEGER, u: unsigned INTEGER, t: TIMETICKS, a: IPADDRESS, o: OID, s: STRING
 *      Example:
 *         set fd [ns_snmp create localhost]
 *         ns_snmp trap $fd 1.3.6.1.6.3.1.1.5.1 1.3.6.1.2.1.1.1.2.0.1 1.3.6.1.2.1.1.1 s "Linux"
 *
 *    ns_snmp destroy $s
 *      destroys SNMP session
 *
 *  To receive traps the module should listens on SNMP trap port 162 or as 
 *  specified in config file.
 *
 *  Trap config example:
 *  ns_section ns/server/test_server/module/nssnmp
 *  ns_param    trap_port      1187
 *  ns_param    trap_address   127.0.0.1
 *  ns_param    trap_proc      snmp_trap_handler
 *
 *  For each incoming SNMP trap it spawns separate thread and calls configured
 *  Tcl proc. Inside that proc special command ns_trap is available with the following
 *  parameters:
 *  ns_trap oid|enterprise|type|vb|uptime|address
 *    where
 *      oid is notification OID
 *      enterprise is Enterprise specific OID
 *      uptime is timeticks
 *      type is PDU type: TRAP|TRAP2
 *      vb is variable bind list in format  { { oid type value } .. }
 *
 *  Primitive MIB support, maintains hash tabel with all known MIB
 *  OID to label mapping.
 *  ns_mib usage:
 *
 *    ns_mib set OID module label syntax hint enum(N) ...
 *       create new MIB node with optional enum values for Integer
 *
 *    ns_mib info
 *       returns the whole structure about given MIB node
 *
 *    ns_mib value OID value
 *       returns enumeration name if exists or the same value
 *
 *    ns_mib name OID
 *    ns_mib label OID
 *    ns_mib module OID|label
 *    ns_mib oid name
 *    ns_mib syntax OID|label
 *
 *  ICMP requests
 *    ns_ping host {-count n -timeout n -size n}
 *    performs ICMP ECHO queries
 *     where
 *       -count n specifies to send n ICMP packets
 *       -timeout n specifies to wait n seconds for reply
 *       -size n specifies n bytes of data to be sent
 *       all these options are optional
 *
 *     returns the following Tcl list:
 *      { requests_sent requests_received loss_percentage rtt_min rtt_avg rtt_max }
 *
 *  RADIUS requests
 *    ns_radius send host port secret ?Code code? ?Retries retries? ?Timeout timeout? ?attr value? ...
 *     performs RADIUS requests
 *
 *     Example:
 *       ns_radius send localhost 1645 secret User-Name test User-Password test2
 *
 * Authors
 *
 *     Vlad Seryakov vlad@crystalballinc.com
 */

#define USE_TCL8X

extern "C" {
#include "ns.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
}

#include "snmp_pp/snmp_pp.h"

#define SNMP_VERSION  "2.0"

typedef struct _icmpPort {
  struct _icmpPort *next,*prev;
  int fd;
  int flag;
} IcmpPort;

class SnmpSession {
  public:
   SnmpSession(char *host,int port):snmp(0),addr(0),next(0),prev(0) {
     addr = new UdpAddress(host);
     addr->set_port(port);
     if(!addr->valid()) {
       free();
       return;
     }
     int status;
     snmp = new Snmp(status);
     if(status != SNMP_CLASS_SUCCESS) {
       free();
       return;
     }
     target.set_address(*addr);
     access_time = time(0);
   }
   ~SnmpSession() {
     free();
   }
   void free() {
     if(snmp) delete snmp;
     if(addr) delete addr;
     snmp = 0;addr = 0;
   }
   unsigned long id;
   Snmp *snmp;
   UdpAddress *addr;
   CTarget target;
   Pdu pdu;
   int bulk;
   SnmpSession *next;
   SnmpSession *prev;
   time_t access_time;
   void *server;
};

class SnmpString : public OctetStr {
  public:
   char *get_printable();
   char *get_printable_hex();
   SnmpString& operator=(unsigned long val);
};

class SnmpVb: public Vb {
  public:
   char *get_printable_value();
   int get_exception_status() { return exception_status; }
   int SetValue(char *type,char *value);
  protected:
   SnmpString str;
   char *value;
};

typedef struct _mibEntry {
  char *oid;
  char *label;
  char *module;
  char *syntax;
  char *hint;
  struct {
    int count;
    char **names;
    short *values;
  } Enum;
} MibEntry;

// MD5 implementation
#define MD5_DIGEST_CHARS         16

#ifdef sun
#define HIGHFIRST
#endif

/* The four core functions - F1 is optimized somewhat */

/* #define F1(x,  y,  z) (x & y | ~x & z) */
#define F1(x,  y,  z) (z ^ (x & (y ^ z)))
#define F2(x,  y,  z) F1(z,  x,  y)
#define F3(x,  y,  z) (x ^ y ^ z)
#define F4(x,  y,  z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f,  w,  x,  y,  z,  data,  s) \
	( w += f(x,  y,  z) + data,   w = w<<s | w>>(32-s),   w += x )

struct MD5Context {
    unsigned int buf[4];
    unsigned int bits[2];
    unsigned char in[64];
};
// To make happy RSA MD5 implementation
typedef struct MD5Context MD5_CTX;

// RADIUS ID definitions. See RFC 2138
#define RADIUS_ACCESS_REQUEST               1
#define RADIUS_ACCESS_ACCEPT                2
#define RADIUS_ACCESS_REJECT                3
#define RADIUS_ACCOUNTING_REQUEST           4
#define RADIUS_ACCOUNTING_RESPONSE          5
#define RADIUS_ACCOUNTING_STATUS            6
#define RADIUS_PASSWORD_REQUEST             7
#define RADIUS_PASSWORD_ACK                 8
#define RADIUS_PASSWORD_REJECT              9
#define RADIUS_ACCOUNTING_MESSAGE           10
#define RADIUS_ACCESS_CHALLENGE             11
#define RADIUS_STATUS_SERVER                12
#define RADIUS_STATUS_CLIENT                13

// RADIUS attribute definitions. Also from RFC 2138
#define RADIUS_USER_NAME                    1       /* string */
#define RADIUS_USER_PASSWORD                2       /* string */
#define RADIUS_CHAP_PASSWORD                3       /* string */
#define RADIUS_NAS_IP_ADDRESS               4       /* ipaddr */
#define RADIUS_NAS_PORT                     5       /* integer */
#define RADIUS_SERVICE_TYPE                 6       /* integer */
#define RADIUS_FRAMED_PROTOCOL              7       /* integer */
#define RADIUS_FRAMED_IP_ADDRESS            8       /* ipaddr */
#define RADIUS_FRAMED_IP_NETMASK            9       /* ipaddr */
#define RADIUS_FRAMED_ROUTING               10      /* integer */
#define RADIUS_FILTER_ID                    11      /* string */
#define RADIUS_FRAMED_MTU                   12      /* integer */
#define RADIUS_FRAMED_COMPRESSION           13      /* integer */
#define RADIUS_LOGIN_IP_HOST                14      /* ipaddr */
#define RADIUS_LOGIN_SERVICE                15      /* integer */
#define RADIUS_LOGIN_PORT                   16      /* integer */
#define RADIUS_OLD_PASSWORD                 17      /* string */
#define RADIUS_REPLY_MESSAGE                18      /* string */
#define RADIUS_LOGIN_CALLBACK_NUMBER        19      /* string */
#define RADIUS_FRAMED_CALLBACK_ID           20      /* string */
#define RADIUS_FRAMED_ROUTE                 22      /* string */
#define RADIUS_STATE                        24      /* string */
#define RADIUS_CLASS                        25      /* string */
#define RADIUS_VENDOR_SPECIFIC              26      /* string */
#define RADIUS_SESSION_TIMEOUT              27      /* integer */
#define RADIUS_IDLE_TIMEOUT                 28      /* integer */
#define RADIUS_TERMINATION_ACTION           29      /* integer */
#define RADIUS_CALLED_STATION_ID            30      /* string */
#define RADIUS_CALLING_STATION_ID           31      /* string */
#define RADIUS_NAS_IDENTIFIER               32      /* string */
#define RADIUS_PROXY_STATE                  33      /* string */
#define RADIUS_CHAP_CHALLENGE               60      /* string */
#define RADIUS_NAS_PORT_TYPE                61      /* integer */
#define RADIUS_PORT_LIMIT                   62      /* integer */
#define RADIUS_USER_ID                      99      /* string */

// Service types
#define RADIUS_LOGIN                  1
#define RADIUS_FRAMED                 2
#define RADIUS_CALLBACK_LOGIN         3
#define RADIUS_CALLBACK_FRAMED        4
#define RADIUS_OUTBOUND_USER          5
#define RADIUS_ADMINISTRATIVE_USER    6
#define RADIUS_SHELL_USER             7
#define RADIUS_AUTHENTICATE_ONLY      8
#define RADIUS_CALLBACK_ADMIN_USER    9

// Attribute types
#define RADIUS_TYPE_STRING            0
#define RADIUS_TYPE_INTEGER           1
#define RADIUS_TYPE_IPADDR            2
#define RADIUS_TYPE_DATE              3
#define RADIUS_TYPE_FILTER_BINARY     4

// RADIUS string limits
#define RADIUS_VECTOR_LEN             16
#define RADIUS_STRING_LEN             253
#define RADIUS_BUFFER_LEN             1524

// Default RADIUS ports
#define RADIUS_AUTH_PORT              1645
#define RADIUS_ACCT_PORT              1646

typedef unsigned char RadiusVector[RADIUS_VECTOR_LEN];

// Radius packet header
typedef struct _radiusHeader_t {
   unsigned char code;
   unsigned char id;
   unsigned short length;
   RadiusVector vector;
} RadiusHeader;

// Radius attribute
typedef struct _radiusAttr_t {
   struct _radiusAttr_t *next;
   short type;
   short vendor;
   short attribute;
   char name[RADIUS_STRING_LEN+1];
   unsigned char sval[RADIUS_STRING_LEN+1];
   unsigned int lval;
} RadiusAttr;

// Dictionary value
typedef struct _radiusValue_t {
   struct _radiusValue_t *next;
   char name[RADIUS_STRING_LEN+1];
   int value;
} RadiusValue;

// Dictionary attribute
typedef struct _radiusDict_t {
   struct _radiusDict_t *next;
   struct _radiusDict_t *prev;
   char name[RADIUS_STRING_LEN+1];
   int attribute;
   short vendor;
   short type;
   RadiusValue *values;
} RadiusDict;

// Client secret
typedef struct _radiusClient {
   struct _radiusClient *next;
   struct _radiusClient *prev;
   struct in_addr addr;
   char secret[RADIUS_VECTOR_LEN+1];
} RadiusClient;

// User record
typedef struct _radiusUser {
   RadiusAttr *config;
   RadiusAttr *reply;
} RadiusUser;

typedef struct _server {
   char *name;
   char *community;
   char *writecommunity;
   int debug;
   int port;
   int bulk;
   int timeout;
   int retries;
   int version;
   int idle_timeout;
   int gc_interval;
   unsigned long sessionID;
   SnmpSession *sessions;
   Ns_Mutex snmpMutex;
   Tcl_HashTable mib;
   Ns_Mutex mibMutex;
   struct {
     int id;
     int count;
     Ns_Mutex mutex;
     IcmpPort *ports;
   } icmp;
   struct {
     int port;
     Snmp *snmp;
     char *proc;
     char *address;
   } trap;
   struct {
     char *proc;
     char *address;
     int auth_port;
     int acct_port;
     int enabled;
     int auth_sock;
     int acct_sock;
     short errors;
     Ns_Mutex userMutex;
     Ns_Mutex clientMutex;
     Ns_Mutex requestMutex;
     Tcl_HashTable userList;
     RadiusClient *clientList;
     Ns_Mutex dictMutex;
     RadiusDict *dictList;
   } radius;
   struct {
     char *proc;
     char *path;
     char *address;
     int port;
     int enabled;
     int udp_sock;
     int unix_sock;
     short errors;
     Ns_DString buffer;
   } syslog;
} Server;

class TrapContext {
 public:
   SOCKET sock;
   struct sockaddr_in sa;
   Pdu pdu;
   SnmpTarget *target;
   Server *server;
   TrapContext(Server *srv): target(0), server(srv) {}
   ~TrapContext() {
      if(target) delete target;
   }
};

typedef struct _radiusRequest {
   struct _radiusRequest *next,*prev;
   int sock;
   int req_id;
   int req_code;
   int reply_code;
   Server *server;
   RadiusAttr *req;
   RadiusAttr *reply;
   RadiusVector vector;
   RadiusClient *client;
   struct sockaddr_in addr;
} RadiusRequest;

static Ns_SockProc RadiusProc;
static Ns_ThreadProc RadiusThread;

static Ns_SockProc TrapProc;
static Ns_ThreadProc TrapThread;

static Ns_SockProc SyslogProc;

extern int receive_snmp_notification(int sock, Snmp &snmp_session,Pdu &pdu, SnmpTarget **target);
static int SnmpCmd(ClientData arg, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int TrapCmd(ClientData arg, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int MibCmd(ClientData arg, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int PingCmd(ClientData arg, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int IcmpCmd(ClientData arg, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int RadiusCmd(ClientData arg, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static void TrapDump(Server *server,Pdu &pdu,SnmpTarget &target);
static const char *SnmpError(SnmpSession *session,int status);
static int SnmpInterpInit(Tcl_Interp *interp, void *context);
static void FormatIntTC(Tcl_Interp *interp,char *bytes,char *fmt);
static void FormatStringTC(Tcl_Interp *interp,char *bytes,char *fmt);
static SnmpSession *SessionFind(Server *server,unsigned long id);
static void SessionLink(Server *server,SnmpSession* session);
static void SessionUnlink(Server *server,SnmpSession* session,int lock);
static void SessionGC(void *ctx);
static char *PduTypeStr(int type);
static char *SyntaxStr(int type);
static int SyntaxValid(int type);
static void RadiusInit(Server *server);
static void byteReverse(unsigned char *buf,  unsigned len);
static void MD5Transform(unsigned int buf[4],  unsigned int const in[16]);

extern "C" {

extern int Ns_SockListenEx2(char *,char *,int,int);
extern int Ns_SockListenUdp(char *,int);
int Ns_SockListenRaw(int proto);

static Ns_Tls trapTls;
static Ns_Tls radiusTls;

NS_EXPORT int Ns_ModuleVersion = 1;

/*
 *----------------------------------------------------------------------
 *
 * Ns_ModuleInit --
 *
 *	Load the config parameters, setup the structures, and
 *	listen on the trap port.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Server will listen for SNMP traps on specified address and port.
 *
 *----------------------------------------------------------------------
 */

NS_EXPORT int Ns_ModuleInit(char *server, char *module)
{
    char *path;
    SOCKET sock;
    int status;
    Server *srvPtr;
    static int initialized = 0;

    if (!initialized) {
        initialized = 1;
        Ns_TlsAlloc(&trapTls, 0);
        Ns_TlsAlloc(&radiusTls, 0);
    }

    Ns_Log(Notice, "nssnmp module version %s server: %s", SNMP_VERSION, server);

    path = Ns_ConfigGetPath(server, module, NULL);
    srvPtr = (Server*)ns_calloc(1,sizeof(Server));
    srvPtr->name = server;
    Tcl_InitHashTable(&srvPtr->mib, TCL_STRING_KEYS);
    Tcl_InitHashTable(&srvPtr->radius. userList, TCL_STRING_KEYS);
    if (!Ns_ConfigGetInt(path,"debug", &srvPtr->debug)) {
        srvPtr->debug = 0;
    }
    if (!Ns_ConfigGetInt(path, "idle_timeout", &srvPtr->idle_timeout)) {
        srvPtr->idle_timeout = 600;
    }
    if (!Ns_ConfigGetInt(path, "gc_interval", &srvPtr->gc_interval)) {
        srvPtr->gc_interval = 600;
    }
    if (!(srvPtr->community = Ns_ConfigGetValue(path, "community"))) {
        srvPtr->community = "public";
    }
    if (!(srvPtr->writecommunity = Ns_ConfigGetValue(path, "writecommunity"))) {
        srvPtr->writecommunity = "private";
    }
    if (!Ns_ConfigGetInt(path, "port", &srvPtr->port)) {
        srvPtr->port = 161;
    }
    if (!Ns_ConfigGetInt(path, "timeout", &srvPtr->timeout)) {
        srvPtr->timeout = 2;
    }
    if (!Ns_ConfigGetInt(path, "retries", &srvPtr->retries)) {
        srvPtr->retries = 2;
    }
    if (!Ns_ConfigGetInt(path, "version", &srvPtr->version)) {
        srvPtr->version = 2;
    }
    if (!Ns_ConfigGetInt(path, "bulk", &srvPtr->bulk)) {
        srvPtr->bulk = 10;
    }

    srvPtr->trap.proc = Ns_ConfigGetValue(path,"trap_proc");
    if (!Ns_ConfigGetInt(path, "trap_port", &srvPtr->trap.port)) {
        srvPtr->trap.port = 162;
    }
    if (!(srvPtr->trap.address = Ns_ConfigGetValue(path, "trap_address"))) {
        srvPtr->trap.address = "0.0.0.0";
    }

    srvPtr->radius.proc = Ns_ConfigGetValue(path, "radius_proc");
    if (!Ns_ConfigGetInt(path, "radius_auth_port", &srvPtr->radius.auth_port)) {
        srvPtr->radius.auth_port = RADIUS_AUTH_PORT;
    }
    if (!Ns_ConfigGetInt(path, "radius_acct_port", &srvPtr->radius.acct_port)) {
        srvPtr->radius.acct_port = RADIUS_ACCT_PORT;
    }
    if (!(srvPtr->radius.address = Ns_ConfigGetValue(path, "radius_address"))) {
        srvPtr->radius.address = "0.0.0.0";
    }

    srvPtr->syslog.proc = Ns_ConfigGetValue(path, "syslog_proc");
    srvPtr->syslog.address = Ns_ConfigGetValue(path, "syslog_address");
    srvPtr->syslog.port = Ns_ConfigIntRange(path, "syslog_port", 514, 1, 65535);
    if (!(srvPtr->syslog.path = Ns_ConfigGetValue(path, "syslog_path"))) {
        srvPtr->syslog.path = "/dev/log";
    }

    // Initialize ICMP system
    if (Ns_ConfigGetInt(path, "icmp_ports", &srvPtr->icmp.count) > 0) {
        IcmpPort *icmp;
        for (int i = 0; i < srvPtr->icmp.count; i++) {
          if ((sock = Ns_SockListenRaw(IPPROTO_ICMP)) == -1) {
              Ns_Log(Error,"nssnmp: couldn't create icmp socket: %s", strerror(errno));
              return NS_ERROR;
          }
          icmp = (IcmpPort*)ns_calloc(1,sizeof(IcmpPort));
          icmp->fd = sock;
          icmp->next = srvPtr->icmp.ports;
          if (icmp->next) icmp->next->prev = icmp;
          srvPtr->icmp.ports = icmp;
        }
        Ns_Log(Notice,"nssnmp: allocated %d ICMP ports", srvPtr->icmp.count);
    }

    /* Configure SNMP trap listener */
    if (srvPtr->trap.proc) {
        srvPtr->trap.snmp = new Snmp(status);
        if (status != SNMP_CLASS_SUCCESS) {
            Ns_Log(Error,"nssnmp: snmp initialization failed: %s", srvPtr->trap.snmp->error_msg(status));
            return NS_ERROR;
        }
        if ((sock = Ns_SockListenUdp(srvPtr->trap.address, srvPtr->trap.port)) == -1) {
            Ns_Log(Error,"nssnmp: couldn't create socket: %s:%d: %s", srvPtr->trap.address, srvPtr->trap.port, strerror(errno));
        } else {
            Ns_SockCallback(sock, TrapProc, srvPtr, NS_SOCK_READ|NS_SOCK_EXIT|NS_SOCK_EXCEPTION);
            Ns_Log(Notice,"nssnmp: listening on %s:%d by %s",
                          srvPtr->trap.address?srvPtr->trap.address:"0.0.0.0",
                          srvPtr->trap.port,
                          srvPtr->trap.proc);
        }
    }

    /* Configure RADIUS server */
    if (Ns_ConfigGetBool(path, "enableradius", &srvPtr->radius.enabled) && srvPtr->radius.proc) {
        if ((sock = Ns_SockListenUdp(srvPtr->radius.address, srvPtr->radius.auth_port)) == -1) {
            Ns_Log(Error,"nssnmp: couldn't create socket: %s:%d: %s", srvPtr->radius.address, srvPtr->radius.auth_port, strerror(errno));
        } else {
            srvPtr->radius.auth_sock = sock;
            Ns_SockCallback(sock, RadiusProc, srvPtr, NS_SOCK_READ|NS_SOCK_EXIT|NS_SOCK_EXCEPTION);
            Ns_Log(Notice,"nssnmp: radius: listening on %s:%d by %s",
                          srvPtr->radius.address?srvPtr->radius.address:"0.0.0.0",
                          srvPtr->radius.auth_port,
                          srvPtr->radius.proc);
        }
        if ((sock = Ns_SockListenUdp(srvPtr->radius.address, srvPtr->radius.acct_port)) == -1) {
            Ns_Log(Error,"nssnmp: couldn't create socket: %s:%d: %s", srvPtr->radius.address, srvPtr->radius.acct_port, strerror(errno));
        } else {
            srvPtr->radius.acct_sock = sock;
            Ns_SockCallback(sock, RadiusProc, srvPtr, NS_SOCK_READ|NS_SOCK_EXIT|NS_SOCK_EXCEPTION);
            Ns_Log(Notice,"nssnmp: radius: listening on %s:%d by %s",
                          srvPtr->radius.address?srvPtr->radius.address:"0.0.0.0",
                          srvPtr->radius.acct_port,
                          srvPtr->radius.proc);
        }
    }

    /* Configure Syslog listener */
    if (Ns_ConfigGetBool(path, "enablesyslog", &srvPtr->syslog.enabled)) {
        if (srvPtr->syslog.address) {
            if ((sock = Ns_SockListenUdp(srvPtr->syslog.address, srvPtr->syslog.port)) == -1) {
                Ns_Log(Error,"nssnmp: couldn't create socket: %s:%d: %s", srvPtr->trap.address, srvPtr->trap.port, strerror(errno));
            } else {
                srvPtr->syslog.udp_sock = sock;
                Ns_SockCallback(sock, SyslogProc, srvPtr, NS_SOCK_READ|NS_SOCK_EXIT|NS_SOCK_EXCEPTION);
                Ns_Log(Notice,"nssnmp: listening on %s:%d by %s",
                              srvPtr->syslog.address, srvPtr->syslog.port,
                              srvPtr->syslog.proc?srvPtr->syslog.proc:"None");
            }
        }
        if (srvPtr->syslog.path) {
            if ((sock = Ns_SockListenUnix(srvPtr->syslog.path, 0, 0666)) == -1) {
                Ns_Log(Error,"nssnmp: couldn't create socket: %s: %s", srvPtr->syslog.path, strerror(errno));
            } else {
                srvPtr->syslog.unix_sock = sock;
                Ns_SockCallback(sock, SyslogProc, srvPtr, NS_SOCK_READ|NS_SOCK_EXIT|NS_SOCK_EXCEPTION);
                Ns_Log(Notice,"nssnmp: listening on %s by %s",
                              srvPtr->syslog.path, srvPtr->syslog.proc?srvPtr->syslog.proc:"None");
            }
        }
        Ns_DStringInit(&srvPtr->syslog.buffer);
    }

    /* Schedule garbage collection proc for automatic session close/cleanup */
    if (srvPtr->gc_interval > 0) {
        Ns_ScheduleProc(SessionGC, srvPtr, 1, srvPtr->gc_interval);
        Ns_Log(Notice,"ns_snmp: scheduling GC proc for every %d secs", srvPtr->gc_interval);
    }
    RadiusInit(srvPtr);
    Ns_MutexSetName2(&srvPtr->radius.dictMutex, "nssnmp", "radiusDict");
    Ns_MutexSetName2(&srvPtr->radius.userMutex, "nssnmp", "radiusUser");
    Ns_MutexSetName2(&srvPtr->radius.clientMutex, "nssnmp", "radiusClient");
    Ns_MutexSetName2(&srvPtr->radius.requestMutex, "nssnmp", "radiusRequest");
    Ns_MutexSetName2(&srvPtr->icmp.mutex, "nssnmp", "icmp");
    Ns_MutexSetName2(&srvPtr->mibMutex, "nssnmp", "mib");
    Ns_MutexSetName2(&srvPtr->snmpMutex, "nssnmp", "snmp");
    Ns_TclRegisterTrace(server, SnmpInterpInit, srvPtr, NS_TCL_TRACE_CREATE);
    return NS_OK;
}

}

/*
 *----------------------------------------------------------------------
 *
 * SnmpInterpInit --
 *
 *      Add ns_snmp commands to interp.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
static int SnmpInterpInit(Tcl_Interp *interp, void *arg)
{
    Tcl_CreateObjCommand(interp, "ns_snmp", SnmpCmd, arg, NULL);
    Tcl_CreateObjCommand(interp, "ns_mib", MibCmd, arg, NULL);
    Tcl_CreateObjCommand(interp, "ns_ping", PingCmd, arg, NULL);
    Tcl_CreateObjCommand(interp, "ns_icmp", IcmpCmd, arg, NULL);
    Tcl_CreateObjCommand(interp, "ns_radius", RadiusCmd, arg, NULL);
    Tcl_CreateObjCommand(interp, "ns_trap", TrapCmd, arg, NULL);
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * TrapProc --
 *
 *	Socket callback to receive SNMP traps.
 *
 * Results:
 *	NS_TRUE
 *
 * Side effects:
 *  	New TrapThread will be created.
 *
 *----------------------------------------------------------------------
 */

static int TrapProc(SOCKET sock,void *arg,int why)
{
    if (why != NS_SOCK_READ) {
        close(sock);
        return NS_FALSE;
    }
    Server *server = (Server*)arg;
    TrapContext *ctx = new TrapContext(server);
    if (!receive_snmp_notification(sock,*server->trap.snmp,ctx->pdu,&ctx->target)) {
        if (server->debug) {
            TrapDump(server,ctx->pdu,*ctx->target);
        }
        /* SNMP inform trap requires response */
        if (ctx->pdu.get_type() == sNMP_PDU_INFORM) {
            Pdu pdu = ctx->pdu;
            server->trap.snmp->response(pdu,*ctx->target);
        }
        /* Call trap handler if configured */
        if (server->trap.proc) {
            Ns_ThreadCreate(TrapThread,(void *)ctx, 0, NULL);
            return NS_TRUE;
        }
    }
    delete ctx;
    return NS_TRUE;
}

/*
 *----------------------------------------------------------------------
 *
 * TrapThread --
 *
 *	Tcl handler for a trap
 *
 * Results:
 *	None.
 *
 * Side effects:
 *      None
 *----------------------------------------------------------------------
 */

static void TrapThread(void *arg)
{
    TrapContext *ctx = (TrapContext *)arg;
    Tcl_Interp *interp = Ns_TclAllocateInterp(((Server*)(ctx->server))->name);

    Ns_TlsSet(&trapTls, ctx);
    if (Tcl_Eval(interp,((Server*)(ctx->server))->trap.proc) != TCL_OK) {
        Ns_TclLogError(interp);
    }
    Ns_TclDeAllocateInterp(interp);
    Ns_TlsSet(&trapTls, 0);
    delete ctx;
}

/*
 *----------------------------------------------------------------------
 *
 * TrapCmd --
 *
 *	Special ns_trap command for access to current trap structure
 *
 * Results:
 *  	Standard Tcl result.
 *
 * Side effects:
 *  	None.
 *
 *----------------------------------------------------------------------
 */

static int TrapCmd(ClientData arg, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    int cmd;
    enum commands {
        cmdOid, cmdType, cmdUptime,
        cmdEnterprise, cmdAddress, cmdVb
    };

    static const char *sCmd[] = {
        "oid", "type", "uptime",
        "enterprise", "address", "vb",
        0
    };

    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "args");
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], sCmd, "command", TCL_EXACT, (int *)&cmd) != TCL_OK) {
        return TCL_ERROR;
    }
    Oid id;
    TimeTicks tm;
    TrapContext *ctx = (TrapContext *)Ns_TlsGet(&trapTls);
    switch(cmd) {
     case cmdOid:
        ctx->pdu.get_notify_id(id);
        Tcl_AppendResult(interp, id.get_printable(), 0);
        break;

     case cmdType:
        Tcl_AppendResult(interp,PduTypeStr(ctx->pdu.get_type()),0);
        break;

     case cmdUptime:
        ctx->pdu.get_notify_timestamp(tm);
        Tcl_AppendResult(interp,tm.get_printable(),0);
        break;

     case cmdEnterprise:
        ctx->pdu.get_notify_enterprise(id);
        Tcl_AppendResult(interp,id.get_printable(),0);
        break;

     case cmdAddress: {
        GenAddress addr;
        ctx->target->get_address(addr);
        char *s,*saddr = (char*)addr.get_printable();
        if ((s = strchr(saddr,'/'))) *s = 0;
        Tcl_AppendResult(interp,saddr,0);
        break;
     }

     case cmdVb: {
        Vb vb;
        Tcl_Obj *obj,*list = Tcl_NewListObj(0,0);
        for (int i = 0; i < ctx->pdu.get_vb_count(); i++) {
            ctx->pdu.get_vb(vb,i);
            obj = Tcl_NewListObj(0,0);
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj((char*)vb.get_printable_oid(),-1));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(SyntaxStr(vb.get_syntax()),-1));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj((char*)vb.get_printable_value(),-1));
            Tcl_ListObjAppendElement(interp, list, obj);
        }
        Tcl_SetObjResult(interp,list);
        break;
     }
    }
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * TrapDump --
 *
 *      Outputs SNMP trap information into log
 *
 * Results:
 *      None
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static void TrapDump(Server *server,Pdu &pdu,SnmpTarget &target)
{
    Vb vb;
    Oid id,eid;
    TimeTicks tm;
    Ns_DString ds;
    GenAddress addr;

    target.get_address(addr);
    pdu.get_notify_id(id);
    pdu.get_notify_enterprise(eid);
    pdu.get_notify_timestamp(tm);

    Ns_DStringInit(&ds);

    Ns_DStringPrintf(&ds,"Status %s From %s Uptime %s Enterprise {%s} ID {%s} Type {%s} ",
                         server->trap.snmp->error_msg(pdu.get_error_status()),
                         addr.get_printable(),
                         tm.get_printable(),
                         eid.get_printable(),
                         id.get_printable(),
                         PduTypeStr(pdu.get_type()));
    for (int i = 0; i < pdu.get_vb_count(); i++) {
        pdu.get_vb(vb,i);
        Ns_DStringPrintf(&ds,"%s {%s} {%s} ",
                         vb.get_printable_oid(),
                         SyntaxStr(vb.get_syntax()),
                         vb.get_printable_value());
    }
    Ns_Log(Debug,"nssnmp: %s",Ns_DStringValue(&ds));
    Ns_DStringFree(&ds);
}

/*
 *----------------------------------------------------------------------
 *
 * PduTypeStr --
 *
 *      Returns name for SNMP PDU
 *
 * Results:
 *      Pointer to char string
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static char *PduTypeStr(int type)
{
    switch(type) {
      case GET_REQ_MSG: return "GET";
      case GETNEXT_REQ_MSG: return "GETNEXT";
      case GET_RSP_MSG: return "RESPONSE";
      case SET_REQ_MSG: return "SET";
      case GETBULK_REQ_MSG: return "GETBULK";
      case INFORM_REQ_MSG: return "INFORM";
      case TRP2_REQ_MSG: return "TRAP2";
      case TRP_REQ_MSG: return "TRAP";
      case REPORT_MSG: return "REPORT";
      default: return "UNKNOWN";
    }
}

/*
 *----------------------------------------------------------------------
 *
 * SyntaxStr --
 *
 *      Returns name for MIB syntax
 *
 * Results:
 *      Pointer to char string
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static char *SyntaxStr(int type)
{
    switch(type) {
      case sNMP_SYNTAX_INT32: return "Integer32";
      case sNMP_SYNTAX_TIMETICKS: return "TimeTicks";
      case sNMP_SYNTAX_CNTR32: return "Counter32";
      case sNMP_SYNTAX_UINT32: return "Unsigned32";
      case sNMP_SYNTAX_CNTR64: return "Counter64";
      case sNMP_SYNTAX_OCTETS: return "OCTET STRING";
      case sNMP_SYNTAX_BITS: return "BITS";
      case sNMP_SYNTAX_OPAQUE: return "OPAQUE";
      case sNMP_SYNTAX_IPADDR: return "IpAddress";
      case sNMP_SYNTAX_OID: return "OBJECT IDENTIFIER";
      case sNMP_SYNTAX_NULL: return "NULL";
      case sNMP_SYNTAX_NOSUCHINSTANCE: return "noSuchName";
      case sNMP_SYNTAX_NOSUCHOBJECT: return "noSuchObject";
      case sNMP_SYNTAX_ENDOFMIBVIEW: return "endOfMibView";
      case sNMP_SYNTAX_SEQUENCE: return "SEQUENCE";
      default: return "UNKNOWN";
    }
}

/*
 *----------------------------------------------------------------------
 *
 * SessionFind --
 *
 *      Returns pointer on existing SNMP session by id
 *
 * Results:
 *      Pointer to SNMP session
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static SnmpSession *SessionFind(Server *server,unsigned long id)
{
   SnmpSession *session;
   Ns_MutexLock(&server->snmpMutex);
   for (session = (SnmpSession*)server->sessions;session;session = (SnmpSession*)session->next) {
       if (session->id == id) {
           break;
       }
   }
   Ns_MutexUnlock(&server->snmpMutex);
   return session;
}

/*
 *----------------------------------------------------------------------
 *
 * SnmpGC
 *
 *      Garbage collection routine, closes expired sessions
 *
 * Results:
 *      None
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static void SessionGC(void *arg)
{
    Server *server = (Server*)arg;
    SnmpSession *session;
    time_t now = time(0);

    Ns_MutexLock(&server->snmpMutex);
    for (session = (SnmpSession*)server->sessions;session;) {
        if (now - session->access_time > server->idle_timeout) {
            SnmpSession *next = (SnmpSession*)session->next;
            Ns_Log(Notice,"ns_snmp: GC: inactive session %ld: %s",session->id,session->addr->get_printable());
            SessionUnlink(server,session,0);
            session = next;
            continue;
        }
        session = (SnmpSession*)session->next;
    }
    Ns_MutexUnlock(&server->snmpMutex);
}

/*
 *----------------------------------------------------------------------
 *
 * SessionLink --
 *
 *      Link new session to global session list
 *
 * Results:
 *      None
 *
 * Side effects:
 *      Global session id counter is insreased
 *
 *----------------------------------------------------------------------
 */

static void SessionLink(Server *server,SnmpSession* session)
{
    if (!session) {
        return;
    }
    Ns_MutexLock(&server->snmpMutex);
    session->id = ++server->sessionID;
    session->next = server->sessions;
    if (server->sessions) {
        server->sessions->prev = session;
    }
    server->sessions = session;
    Ns_MutexUnlock(&server->snmpMutex);
}

/*
 *----------------------------------------------------------------------
 *
 * SessionUnlink --
 *
 *      Removes sessions from the global session list and
 *      deallocates session structure
 *
 * Results:
 *      None
 *
 * Side effects:
 *      Head of global session list may be changed
 *
 *----------------------------------------------------------------------
 */

static void SessionUnlink(Server *server,SnmpSession* session,int lock)
{
    if (!session) {
        return;
    }
    if (lock) {
        Ns_MutexLock(&server->snmpMutex);
    }
    if (session->prev) {
        session->prev->next = session->next;
    }
    if (session->next) {
        session->next->prev = session->prev;
    }
    if (session == server->sessions) {
        server->sessions = (SnmpSession*)session->next;
    }
    if (lock) {
        Ns_MutexUnlock(&server->snmpMutex);
    }
    delete session;
}

/*
 *----------------------------------------------------------------------
 *
 * SnmpError --
 *
 *      Returns error message for given status
 *
 * Results:
 *      error string
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static const char *SnmpError(SnmpSession *session,int status)
{
   switch(status) {
    case SNMP_CLASS_SUCCESS: return "";
    case SNMP_CLASS_TIMEOUT: return "noResponse";
    default: return session->snmp->error_msg(status);
   }
}

/*
 *----------------------------------------------------------------------
 *
 * SyntaxValid --
 *
 *      Returns 1 if specified syntax code is valid variable
 *
 * Results:
 *      1 on success, -1 on error
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static int SyntaxValid(int syntax)
{
   switch(syntax) {
    case sNMP_SYNTAX_ENDOFMIBVIEW:
    case sNMP_SYNTAX_NOSUCHINSTANCE:
    case sNMP_SYNTAX_NOSUCHOBJECT: return 0;
    default: return 1;
   }
}

/*
 *----------------------------------------------------------------------
 *
 * SnmpCmd --
 *
 *	Special ns_snmp command for making SNMP requests
 *
 * Results:
 *  	Standard Tcl result.
 *
 * Side effects:
 *  	None.
 *
 *----------------------------------------------------------------------
 */

static int SnmpCmd(ClientData arg, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    Server *server = (Server*)arg;
    int cmd,status,id;
    SnmpSession *session;
    enum commands {
        cmdGc, cmdSessions, cmdCreate,
        cmdConfig, cmdGet, cmdWalk, cmdSet, 
        cmdTrap, cmdInform, cmdDestroy
    };

    static const char *sCmd[] = {
        "gc", "sessions", "create",
        "config", "get", "walk", "set", 
        "trap", "inform", "destroy", 0
    };

    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "args");
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], sCmd, "command", TCL_EXACT, (int *)&cmd) != TCL_OK) {
        return TCL_ERROR;
    }
    switch(cmd) {
     case cmdGc:
        SessionGC(0);
        return TCL_OK;

     case cmdSessions: {
        // List opened sessions
        Tcl_Obj *list = Tcl_NewListObj(0,0);
        Ns_MutexLock(&server->snmpMutex);
        for (session = server->sessions;session;session = session->next) {
            Tcl_ListObjAppendElement(interp,list,Tcl_NewIntObj(session->id));
            Tcl_ListObjAppendElement(interp,list,Tcl_NewIntObj(session->access_time));
            Tcl_ListObjAppendElement(interp,list,Tcl_NewStringObj((char*)session->addr->get_printable(),-1));
        }
        Ns_MutexUnlock(&server->snmpMutex);
        Tcl_SetObjResult(interp,list);
        return TCL_OK;
     }
     case cmdCreate: {
        int bulk = server->bulk;
        int port = server->port;
        int timeout = server->timeout;
        int retries = server->retries;
        int version = server->version;
        char *community = server->community;
        char *writecommunity = server->writecommunity;

        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "host ?-port? ?-timeout? ?-retries? ?-version? ?-bulk? ?-community? ?-writecommunity?");
            return TCL_ERROR;
        }

        for (int i = 3;i < objc-1;i = i+2) {
            if (!strcmp(Tcl_GetStringFromObj(objv[i],0), "-port")) {
                Tcl_GetIntFromObj(interp,objv[i+1], &port);
            } else
            if (!strcmp(Tcl_GetStringFromObj(objv[i],0), "-timeout")) {
                Tcl_GetIntFromObj(interp,objv[i+1], &timeout);
            } else
            if (!strcmp(Tcl_GetStringFromObj(objv[i],0), "-retries")) {
                Tcl_GetIntFromObj(interp,objv[i+1], &retries);
            } else
            if (!strcmp(Tcl_GetStringFromObj(objv[i],0), "-version")) {
                Tcl_GetIntFromObj(interp,objv[i+1], &version);
            } else
            if (!strcmp(Tcl_GetStringFromObj(objv[i],0), "-bulk")) {
                Tcl_GetIntFromObj(interp,objv[i+1], &bulk);
            } else
            if (!strcmp(Tcl_GetStringFromObj(objv[i],0), "-community")) {
                community = Tcl_GetString(objv[i+1]);
            } else
            if (!strcmp(Tcl_GetStringFromObj(objv[i],0), "-writecommunity")) {
                writecommunity = Tcl_GetString(objv[i+1]);
            }
        }
        session = new SnmpSession(Tcl_GetStringFromObj(objv[2],0), port);
        if (!session->snmp) {
            delete session;
            Tcl_AppendResult(interp,"noHost: wrong host or port: ",Tcl_GetStringFromObj(objv[2], 0),0);
            return TCL_ERROR;
        }
        session->bulk = bulk;
        session->target.set_version(version==1?version1:version2c);
        session->target.set_retry(retries);
        session->target.set_timeout(timeout*100);
        session->target.set_readcommunity(community);
        session->target.set_writecommunity(writecommunity?writecommunity:community);
        SessionLink(server,session);
        Tcl_SetObjResult(interp, Tcl_NewIntObj(session->id));
        return TCL_OK;
     }
     case cmdConfig:
     case cmdGet:
     case cmdWalk:
     case cmdSet:
     case cmdTrap:
     case cmdInform:
     case cmdDestroy:
         break;
    }
    if (Tcl_GetIntFromObj(interp, objv[2], &id) != TCL_OK) {
        return TCL_ERROR;
    }
    /* All other commands require existig sesion */
    if (!(session = SessionFind(server,id))) {
        Tcl_AppendResult(interp,"wrong session #s",0);
        return TCL_ERROR;
    }
    session->access_time = time(0);

    switch(cmd) {
     case cmdGc:
     case cmdSessions:
     case cmdCreate:
        break;
     case cmdConfig:
        if (objc < 4) {
            Tcl_AppendResult(interp,"wrong # args: should be ns_snmp config #s name", 0);
            return TCL_ERROR;
        }
        if (!strcmp(Tcl_GetStringFromObj(objv[3],0), "-address")) {
            IpAddress ipaddr = *session->addr;
            Tcl_AppendResult(interp, ipaddr.get_printable(),0);
        } else
        if (!strcmp(Tcl_GetStringFromObj(objv[3],0), "-port")) {
            char tmp[32];
            sprintf(tmp,"%d",session->addr->get_port());
            Tcl_AppendResult(interp, tmp, 0);
        } else
        if (!strcmp(Tcl_GetStringFromObj(objv[3],0), "-community")) {
            OctetStr community;
            session->target.get_readcommunity(community);
            Tcl_AppendResult(interp, community.get_printable(), 0);
        } else
        if (!strcmp(Tcl_GetStringFromObj(objv[3],0), "-writecommunity")) {
            OctetStr community;
            session->target.get_writecommunity(community);
            Tcl_AppendResult(interp, community.get_printable(), 0);
        } else
        if (!strcmp(Tcl_GetStringFromObj(objv[3],0), "-timeout")) {
            char tmp[32];
            sprintf(tmp,"%ld",session->target.get_timeout());
            Tcl_AppendResult(interp, tmp, 0);
        } else
        if (!strcmp(Tcl_GetStringFromObj(objv[3],0), "-version")) {
            char tmp[32];
            sprintf(tmp,"%d",session->target.get_version()+1);
            Tcl_AppendResult(interp, tmp, 0);
        } else
        if (!strcmp(Tcl_GetStringFromObj(objv[3],0), "-retries")) {
            char tmp[32];
            sprintf(tmp,"%d",session->target.get_retry());
            Tcl_AppendResult(interp, tmp, 0);
        }
        break;

     case cmdGet: {
        if (objc < 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_snmp get #s vb ...", 0);
            return TCL_ERROR;
        }
        SnmpVb vb;
        Oid oid;
        session->pdu.set_vblist(&vb, 0);
        for (int i = 3;i < objc;i++) {
             oid = Tcl_GetStringFromObj(objv[i], 0);
             if (!oid.valid()) {
                 Tcl_AppendResult(interp, "invalid OID ", Tcl_GetStringFromObj(objv[i],0), 0);
                 return TCL_ERROR;
             }
             vb.set_oid(oid);
             session->pdu += vb;
        }
        if ((status = session->snmp->get(session->pdu, session->target)) != SNMP_CLASS_SUCCESS) {
            Tcl_AppendResult(interp, SnmpError(session,status),0);
            return TCL_ERROR;
        }
        Tcl_Obj *obj,*list = Tcl_NewListObj(0, 0);
        for (int i = 0; i < session->pdu.get_vb_count(); i++) {
            session->pdu.get_vb(vb,i);
            if (!SyntaxValid(vb.get_syntax())) {
                continue;
            }
            obj = Tcl_NewListObj(0,0);
            Tcl_ListObjAppendElement(interp, obj,Tcl_NewStringObj((char*)vb.get_printable_oid(), -1));
            Tcl_ListObjAppendElement(interp, obj,Tcl_NewStringObj(SyntaxStr(vb.get_syntax()), -1));
            Tcl_ListObjAppendElement(interp, obj,Tcl_NewStringObj((char*)vb.get_printable_value(), -1));
            Tcl_ListObjAppendElement(interp, list, obj);
        }
        Tcl_SetObjResult(interp,list);
        break;
     }
     case cmdWalk: {
        if (objc < 6) {
            Tcl_AppendResult(interp,"wrong # args: should be ns_snmp walk #s OID var script",0);
            return TCL_ERROR;
        }
        SnmpVb vb;
        Tcl_Obj *obj;
        Oid oid(Tcl_GetStringFromObj(objv[3], 0));
        if (!oid.valid()) {
            Tcl_AppendResult(interp, "invalid OID ", Tcl_GetStringFromObj(objv[3],0),0);
            return TCL_ERROR;
        }
        char *oidStr = (char*)oid.get_printable();
        vb.set_oid(oid);
        session->pdu.set_vblist(&vb,1);
        while((status = session->snmp->get_bulk(session->pdu,session->target, 0, session->bulk)) == SNMP_CLASS_SUCCESS) {
          for (int i = 0; i < session->pdu.get_vb_count(); i++) {
              session->pdu.get_vb(vb,i);
              if (!SyntaxValid(vb.get_syntax()) || strncmp(vb.get_printable_oid(), oidStr, strlen(oidStr))) {
                  goto done;
              }
              obj = Tcl_NewListObj(0,0);
              Tcl_ListObjAppendElement(interp,obj, Tcl_NewStringObj((char*)vb.get_printable_oid(), -1));
              Tcl_ListObjAppendElement(interp,obj, Tcl_NewStringObj(SyntaxStr(vb.get_syntax()), -1));
              Tcl_ListObjAppendElement(interp,obj, Tcl_NewStringObj(vb.get_printable_value(), -1));
              if (Tcl_SetVar2Ex(interp, Tcl_GetStringFromObj(objv[4],0), NULL, obj, TCL_LEAVE_ERR_MSG) == NULL) {
                  return TCL_ERROR;
              }
              switch(Tcl_Eval(interp,Tcl_GetStringFromObj(objv[5],0))) {
               case TCL_OK:
               case TCL_CONTINUE: break;
               case TCL_BREAK: goto done;
               case TCL_ERROR: {
                  char msg[100];
                  sprintf(msg, "\n\t(\"ns_snmp walk\" body line %d)",interp->errorLine);
                  Tcl_AddErrorInfo(interp,msg);
                  goto done;
               }
              }
          }
          session->pdu.set_vblist(&vb, 1);
        }
done:
        if (status != SNMP_CLASS_SUCCESS && status != SNMP_ERROR_NO_SUCH_NAME && status != SNMP_ERROR_GENERAL_VB_ERR) {
            Tcl_SetObjResult(interp,Tcl_NewStringObj((char*)SnmpError(session,status),-1));
            return TCL_ERROR;
        }
        break;
     }
     case cmdSet: {
        if (objc < 6) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_snmp set #s OID type value", 0);
            return TCL_ERROR;
        }
        SnmpVb vb;
        Oid oid(Tcl_GetStringFromObj(objv[3], 0));
        char *type = Tcl_GetStringFromObj(objv[4], 0);
        char *value = Tcl_GetStringFromObj(objv[5], 0);
        vb.set_oid(oid);
        if (vb.SetValue(type, value) != TCL_OK) {
            Tcl_AppendResult(interp, "invalid variable type, should one of i,u,t,a,o,s", 0);
            return TCL_ERROR;
        }
        session->pdu.set_vblist(&vb,1);
        if ((status = session->snmp->set(session->pdu, session->target)) != SNMP_CLASS_SUCCESS) {
            Tcl_AppendResult(interp, SnmpError(session, status), 0);
            return TCL_ERROR;
        }
        break;
     }
     case cmdTrap:
     case cmdInform: {
        if (objc < 5) {
            Tcl_AppendResult(interp,"wrong # args: should be ns_snmp trap #s ID EnterpriseID ?oid type value oid type value ...?",0);
            return TCL_ERROR;
        }
        Oid tid(Tcl_GetString(objv[3]));
        Oid eid(Tcl_GetString(objv[4]));
        for (int i = 5; i < objc - 2; i += 3) {
            SnmpVb vb;
            Oid oid(Tcl_GetString(objv[i]));
            char *type = Tcl_GetString(objv[i+1]);
            char *value = Tcl_GetString(objv[i+2]);
            vb.set_oid(oid);
            if (vb.SetValue(type,value) != TCL_OK) {
                Tcl_AppendResult(interp, "invalid variable type, should one of i,u,t,a,o,s", 0);
                return TCL_ERROR;
            }
            session->pdu += vb;
        }
        session->pdu.set_notify_id(tid);
        session->pdu.set_notify_enterprise(eid);
        if (cmd == cmdTrap) {
            status = session->snmp->trap(session->pdu, session->target);
        } else {
            status = session->snmp->inform(session->pdu, session->target);
        }
        if (status != SNMP_CLASS_SUCCESS) {
            Tcl_AppendResult(interp, SnmpError(session, status), 0);
            return TCL_ERROR;
        }
        break;
     }
     case cmdDestroy:
        SessionUnlink(server, session, 1);
        break;
    }
    return TCL_OK;
}

char *SnmpString::get_printable()
{
    for (unsigned long i=0;i < smival.value.string.len;i++){
        if ((smival.value.string.ptr[i] != '\r') &&
            (smival.value.string.ptr[i] != '\n') &&
            (isprint((int) (smival.value.string.ptr[i])) == 0)) {
            return(get_printable_hex());
        }
    }
    if (output_buffer) {
        delete [] output_buffer;
    }
    output_buffer = new char[smival.value.string.len + 1];
    if (smival.value.string.len) {
        memcpy(output_buffer, smival.value.string.ptr, (unsigned int)smival.value.string.len);
    }
    output_buffer[smival.value.string.len] = '\0';
    return(output_buffer);
}

char *SnmpString::get_printable_hex()
{
    int local_len = (int) smival.value.string.len;
    unsigned char *bytes = smival.value.string.ptr;
    char *ptr;

    if (output_buffer) {
        delete [] output_buffer;
    }
    ptr = output_buffer = new char[smival.value.string.len*3+1];
    while (local_len > 0) {
        sprintf(ptr,"%2.2X ",*bytes++);
        ptr += 3;
        local_len--;
    }
    return output_buffer;
}

SnmpString& SnmpString::operator=(unsigned long val)
{
    delete [] smival.value.string.ptr;
    smival.value.string.len = 32;
    smival.value.string.ptr = new unsigned char[33];
    sprintf((char*)smival.value.string.ptr, "%lu", val);
    return *this;
}

char *SnmpVb::get_printable_value()
{
    /* Take care about hex printable format for strings */
    switch (get_syntax()) {
     case sNMP_SYNTAX_TIMETICKS: {
        unsigned long val;
        get_value(val);
        str = val;
        value = (char*)str.data();
        break;
     }
     case sNMP_SYNTAX_BITS:
     case sNMP_SYNTAX_OPAQUE:
     case sNMP_SYNTAX_OCTETS:
        get_value(str);
        value = str.get_printable();
        break;
     default:
        value = (char*)Vb::get_printable_value();
    }
    return value;
}

int SnmpVb::SetValue(char *type,char *value)
{
   switch (type[0]) {
    case 'i':
       set_value((long)atol(value));
       break;
    case 'u':
       set_value((unsigned long)atol(value));
       break;
    case 't': {
       TimeTicks tm(atol(value));
       if (tm.valid()) {
           set_value(tm);
       } else {
           return TCL_ERROR;
       }
       break;
    }
    case 'a': {
       IpAddress ipaddr(value);
       if (ipaddr.valid()) {
           set_value(ipaddr);
       } else {
           return TCL_ERROR;
       }
       break;
    }
    case 'o': {
       Oid oid(value);
       if (oid.valid()) {
           set_value(oid);
       } else {
           return TCL_ERROR;
       }
       break;
    }
    case 's': {
       OctetStr str(value);
       if (str.valid()) {
           set_value(str);
       } else {
           return TCL_ERROR;
       }
       break;
    }
    default:
       return TCL_ERROR;
   }
   return TCL_OK;
}

static int MibCmd(ClientData arg, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    Server *server = (Server*)arg;
    MibEntry *mib = 0;
    char *lastOctet = 0;
    Tcl_HashEntry *entry;
    enum commands {
        cmdLabels, cmdSet, cmdName,
        cmdValue, cmdOid, cmdLabel, cmdModule,
        cmdSyntax, cmdInfo, cmdHint
    };
    static const char *sCmd[] = {
        "labels", "set", "name",
        "value", "oid", "label", "module",
        "syntax", "info", "hint", 0
    };
    int cmd;

    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "args");
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], sCmd, "command", TCL_EXACT, (int *)&cmd) != TCL_OK) {
        return TCL_ERROR;
    }
    switch (cmd) {
     case cmdLabels: {
        char *pattern = (objc > 2 ? Tcl_GetString(objv[2]) : 0);
        char *syntax = (objc > 3 ? Tcl_GetString(objv[3]) : 0);
        Tcl_HashSearch search;

        Ns_MutexLock(&server->mibMutex);
        entry = Tcl_FirstHashEntry(&server->mib,&search);
        while (entry) {
            if ((mib = (MibEntry*)Tcl_GetHashValue(entry))) {
                if (!syntax || Tcl_RegExpMatch(interp, mib->syntax, syntax)) {
                    if (!pattern || Tcl_RegExpMatch(interp, mib->label, pattern)) {
                        Tcl_AppendResult(interp, mib->label, " ", 0);
                    }
                }
            }
            entry = Tcl_NextHashEntry(&search);
        }
        Ns_MutexUnlock(&server->mibMutex);
        return TCL_OK;
     }
    }
    if (objc < 3) {
        Tcl_WrongNumArgs(interp, 2, objv, "oid");
        return TCL_ERROR;
    }

    switch (cmd) {
     case cmdSet:
        if (objc < 6) {
            Tcl_WrongNumArgs(interp, 2, objv, "oid module label syntax hint enum(N) ...");
            return TCL_ERROR;
        }
        int flag, enumidx = 7;
        Ns_MutexLock(&server->mibMutex);
        entry = Tcl_CreateHashEntry(&server->mib,Tcl_GetString(objv[2]), &flag);
        if (flag) {
            mib = (MibEntry*)ns_calloc(1,sizeof(MibEntry));
            mib->oid = strdup(Tcl_GetString(objv[2]));
            mib->module = strdup(Tcl_GetString(objv[3]));
            mib->label = strdup(Tcl_GetString(objv[4]));
            mib->syntax = strdup(Tcl_GetString(objv[5]));
            /* Enumeration for integer type, hint can be skipped */
            if (!strcmp(Tcl_GetString(objv[5]), "Integer32")) {
                if (objc > 6 && Tcl_GetString(objv[6])[0]) {
                    if (strchr(Tcl_GetString(objv[6]),'(')) {
                        enumidx = 6;
                    } else {
                        mib->hint = strdup(Tcl_GetString(objv[6]));
                    }
                }
                for (int i = enumidx;i < objc; i++) {
                    char *s = strchr(Tcl_GetString(objv[i]),'(');
                    if (!s) break;
                    char *e = strchr(s,')');
                    if (!e) break;
                    *s++ = 0;*e = 0;
                    mib->Enum.count++;
                    mib->Enum.names = (char**)ns_realloc(mib->Enum.names,sizeof(char**)*mib->Enum.count);
                    mib->Enum.values = (short*)ns_realloc(mib->Enum.values,sizeof(short)*mib->Enum.count);
                    mib->Enum.names[mib->Enum.count-1] = ns_strdup(Tcl_GetString(objv[i]));
                    mib->Enum.values[mib->Enum.count-1] = atoi(s);
                }
            } else
            if (objc > 6 && Tcl_GetString(objv[6])[0]) {
                mib->hint = strdup(Tcl_GetString(objv[6]));
            }
            Tcl_SetHashValue(entry,mib);
            entry = Tcl_CreateHashEntry(&server->mib, Tcl_GetString(objv[4]), &flag);
            Tcl_SetHashValue(entry,mib);
        }
        Ns_MutexUnlock(&server->mibMutex);
        return TCL_OK;
    }

    Ns_MutexLock(&server->mibMutex);
    if (!(entry = Tcl_FindHashEntry(&server->mib, Tcl_GetString(objv[2])))) {
        /* Try without last octet */
        if ((lastOctet = strrchr(Tcl_GetString(objv[2]), '.'))) {
            *lastOctet = 0;
            entry = Tcl_FindHashEntry(&server->mib, Tcl_GetString(objv[2]));
            *lastOctet = '.';
        }
    }
    if (entry) {
        mib = (MibEntry*)Tcl_GetHashValue(entry);
    }
    Ns_MutexUnlock(&server->mibMutex);
    if (!entry) {
        Tcl_AppendResult(interp, Tcl_GetString(objv[2]), 0);
        return TCL_OK;
    }

    switch (cmd) {
     case cmdInfo: {
        Tcl_Obj *obj = Tcl_NewListObj(0, 0);
        Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(mib->oid, -1));
        Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(mib->module, -1));
        Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(mib->label, -1));
        Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(mib->syntax, -1));
        Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(mib->hint, -1));
        if (mib->Enum.count) {
            Tcl_Obj *Enum = Tcl_NewListObj(0, 0);
            for (int i = 0;i < mib->Enum.count;i++) {
                Tcl_ListObjAppendElement(interp, Enum, Tcl_NewStringObj(mib->Enum.names[i], -1));
                Tcl_ListObjAppendElement(interp, Enum, Tcl_NewIntObj(mib->Enum.values[i]));
            }
            Tcl_ListObjAppendElement(interp, obj, Enum);
        }
        Tcl_SetObjResult(interp, obj);
        break;
     }

     case cmdName:
        Tcl_AppendResult(interp, mib->module, "!", mib->label, 0);
        break;

     case cmdValue:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "value OID val");
            return TCL_ERROR;
        }
        if (!strcmp(mib->syntax, "OBJECT IDENTIFIER")) {
            Ns_MutexLock(&server->mibMutex);
            if ((entry = Tcl_FindHashEntry(&server->mib, Tcl_GetString(objv[3]))) &&
                (mib = (MibEntry*)Tcl_GetHashValue(entry))) {
                Tcl_AppendResult(interp, mib->label, 0);
            } else {
                Tcl_AppendResult(interp, Tcl_GetString(objv[3]), 0);
            }
            Ns_MutexUnlock(&server->mibMutex);
            return TCL_OK;
        } else
        if (!strcmp(mib->syntax, "Integer32")) {
            if (mib->Enum.count) {
                int val = atoi(Tcl_GetString(objv[3]));
                for (int i = 0;i < mib->Enum.count;i++)
                    if (val == mib->Enum.values[i]) {
                        Tcl_AppendResult(interp, mib->Enum.names[i], 0);
                        return TCL_OK;
                    }
            } else
            if (mib->hint) {
                FormatIntTC(interp, Tcl_GetString(objv[3]), mib->hint);
                return TCL_OK;
            }
        } else
        if (!strcmp(mib->syntax, "OCTET STRING") && mib->hint) {
            FormatStringTC(interp, Tcl_GetString(objv[3]), mib->hint);
            return TCL_OK;
        }
        Tcl_AppendResult(interp, Tcl_GetString(objv[3]), 0);
        break;

     case cmdModule:
        Tcl_AppendResult(interp, mib->module, 0);
        break;

     case cmdLabel:
        Tcl_AppendResult(interp, mib->label, 0);
        break;

     case cmdOid:
        Tcl_AppendResult(interp, mib->oid, 0);
        if (lastOctet) {
            Tcl_AppendResult(interp, lastOctet, 0);
        }
        break;

     case cmdSyntax:
        Tcl_AppendResult(interp, mib->syntax, 0);
        break;

     case cmdHint:
        Tcl_AppendResult(interp, mib->hint, 0);
        break;
    }
    return TCL_OK;
}

// Calculate checksum for given buffer
static int IcmpChksum(u_short *p,  int n)
{
    register u_short answer;
    register long sum = 0;
    u_short odd_byte = 0;

    while (n > 1) {
        sum += *p++;
        n -= 2;
    }
    if (n == 1) {
        *(u_char *)(&odd_byte) = *(u_char *)p;
        sum += odd_byte;
    }
    sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
    sum += (sum >> 16);			/* add carry */
    answer = ~sum;			/* ones-complement,  truncate*/
    return (answer);
}

static int IcmpLock(Server *server)
{
   int fd = -1, count = 3;
   IcmpPort *icmp;

   // Get next available socket
   Ns_MutexLock(&server->icmp.mutex);
   while (--count && fd == -1) {
       for (icmp = server->icmp.ports;icmp;icmp = icmp->next) {
            if (!icmp->flag) {
                icmp->flag = 1;
                fd = icmp->fd;
                break;
            }
       }
       if (fd == -1) {
           sleep(1);
       }
   }
   Ns_MutexUnlock(&server->icmp.mutex);
   return fd;
}

static void IcmpUnlock(Server *server, int fd)
{
   IcmpPort *icmp, *tail;

   Ns_MutexLock(&server->icmp.mutex);
   for (icmp = server->icmp.ports;icmp;icmp = icmp->next) {
       if (icmp->fd == fd) {
           icmp->flag = 0;
           // Move just used socket to the end of the list
           if ((tail = icmp->next)) {
               if (icmp->prev) {
                   icmp->prev->next = icmp->next;
               }
               if (icmp->next) {
                   icmp->next->prev = icmp->prev;
               }
               if (!icmp->prev) {
                   server->icmp.ports = icmp->next;
               }
               while (tail->next) {
                   tail = tail->next;
               }
               tail->next = icmp;
               icmp->prev = tail;
               icmp->next = 0;
               break;
           }
       }
   }
   Ns_MutexUnlock(&server->icmp.mutex);
}

// Check host availability by simulating PING
static int IcmpCmd(ClientData arg,  Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
   Server *server = (Server*)arg;
   IcmpPort *icmp;

   if (objc < 2) {
       Tcl_WrongNumArgs(interp, 1, objv, "args");
       return TCL_ERROR;
   }
   if (!strcmp(Tcl_GetString(objv[1]), "sockets")) {
       Tcl_Obj *list = Tcl_NewListObj(0, 0);
       Ns_MutexLock(&server->icmp.mutex);
       for (icmp = server->icmp.ports;icmp;icmp = icmp->next) {
           Tcl_ListObjAppendElement(interp, list, Tcl_NewIntObj(icmp->fd));
           Tcl_ListObjAppendElement(interp, list, Tcl_NewIntObj(icmp->flag));
       }
       Ns_MutexUnlock(&server->icmp.mutex);
       Tcl_SetObjResult(interp, list);
   }
   return TCL_OK;
}

// Check host availability by simulating PING
static int PingCmd(ClientData arg,  Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
   Server *server = (Server*)arg;
   if (objc < 2) {
       Tcl_WrongNumArgs(interp, 1, objv, "host ?-timeout n? ?-debug 0|1? ?-count n? ?-size n?");
       return TCL_ERROR;
   }
   int i;
   int len;
   int hlen;
   int loss;
   int fd = -1;
   int sent = 0;
   int count = 3;
   int debug = 0;
   int timeout = 5;
   int received = 0;
   int retry_count = 0;
   int id;
#ifdef linux
   socklen_t slen = sizeof(struct sockaddr);
#else
   int slen = sizeof(struct sockaddr);
#endif
   time_t start_time;
   int size = 56;
   char buf[4096];
   fd_set fds;
   float delay;
   float rtt_min = 0;
   float rtt_avg = 0;
   float rtt_max = 0;
   struct ip *ip;
   struct timeval t1;
   struct timeval t2;
   struct sockaddr_in addr;
   struct sockaddr_in addr2;
   struct icmp *icp;
   char *host = Tcl_GetString(objv[1]);

   if (Ns_GetSockAddr(&addr, host, 0) != NS_OK) {
       Tcl_AppendResult(interp, "noHost: unknown host: ", host, 0);
       return TCL_ERROR;
   }
   for (i = 2;i < objc-1;i = i+2) {
       if (!strcmp(Tcl_GetString(objv[i]), "-timeout")) {
           timeout = atoi(Tcl_GetString(objv[i+1]));
       } else
       if (!strcmp(Tcl_GetString(objv[i]), "-debug")) {
           debug = atoi(Tcl_GetString(objv[i+1]));
       } else
       if (!strcmp(Tcl_GetString(objv[i]), "-count")) {
           count = atoi(Tcl_GetString(objv[i+1]));
       } else
       if (!strcmp(Tcl_GetString(objv[i]), "-size")) {
           if ((size = atoi(Tcl_GetString(objv[i+1]))) < 56 || size > (int)sizeof(buf)-8) {
               size = 56;
           }
       }
   }
   if ((fd = IcmpLock(server)) <= 0) {
       Tcl_AppendResult(interp, "noResources: no more ICMP sockets for ", host, 0);
       return TCL_ERROR;
   }
   // Allocate unique id
   Ns_MutexLock(&server->icmp.mutex);
   if ((id = ++server->icmp.id) > 65535) {
       server->icmp.id = id = 1;
   }
   Ns_MutexUnlock(&server->icmp.mutex);
   start_time = time(0);

   for (i = 0; i < count;i++) {
       icp = (struct icmp *)buf;
       icp->icmp_type = ICMP_ECHO;
       icp->icmp_code = 0;
       icp->icmp_cksum = 0;
       icp->icmp_seq = sent;
       icp->icmp_id = id;
       gettimeofday((struct timeval*)&buf[8], 0);
       len = size + 8;
       icp->icmp_cksum = IcmpChksum((u_short *)icp, len);

       if (sendto(fd, buf, len, 0, (struct sockaddr *)&addr, sizeof(addr)) != len) {
           Tcl_AppendResult(interp, "noResponse: ", host, " sendto error: ", strerror(errno), 0);
           Ns_Log(Error, "ns_ping: %d/%d: %s: sendto error: %s", id, fd, host, strerror(errno));
           IcmpUnlock(server, fd);
           return TCL_ERROR;
       }
       sent++;
       retry_count = 0;
again  :
       // Check the total time we spent pinging
       if (time(0) - start_time > timeout) break;
       FD_ZERO(&fds);
       FD_SET(fd, &fds);
       t2.tv_usec = 0;
       t2.tv_sec = timeout;
       switch(select(fd+1, &fds, 0, 0, &t2)) {
        case 1:
           if ((len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr2, &slen)) <= 0) {
               Tcl_AppendResult(interp, "noResponse: ", host, " recvfrom error: ", strerror(errno), 0);
               Ns_Log(Error, "ns_ping: %d/%d: %s: recvfrom error: %s", id, fd, host, strerror(errno));
               IcmpUnlock(server, fd);
               return TCL_ERROR;
           }
           gettimeofday(&t2, 0);
           if (addr.sin_addr.s_addr != addr2.sin_addr.s_addr) {
               if (debug) {
                   Ns_Log(Debug, "ns_ping: %d/%d: %s: invalid IP %s", id, fd, host, ns_inet_ntoa(addr2.sin_addr));
               }
               goto again;
           }
           break;
        case -1:
           if ((errno == EINTR || errno == EAGAIN || errno == EINPROGRESS) && ++retry_count < 2) {
               if (debug) {
                   Ns_Log(Debug, "ns_ping: %d/%d: %s: interrupted,  %d retry", id, fd, host, retry_count);
               }
               goto again;
           }
        default:
           if (debug) {
               Ns_Log(Debug, "ns_ping: %d/%d: %s: timeout,  %d sent", id, fd, host, sent);
           }
           continue;
       }
     // Parse reply header
     ip = (struct ip *) buf;
     if (len < (hlen = ip->ip_hl << 2) + ICMP_MINLEN) {
         if (debug) {
             Ns_Log(Debug, "ns_ping: %d/%d: %s: corrupted packet,  %d", id, fd, host, len);
         }
         goto again;
     }
     icp = (struct icmp *)(buf + hlen);
     /* Wrong packet */
     if (icp->icmp_type != ICMP_ECHOREPLY || icp->icmp_id != id) {
         if (debug) {
             Ns_Log(Debug, "ns_ping: %d/%d: %s: invalid type %d or id %d", id, fd, host, icp->icmp_type, icp->icmp_id);
         }
         goto again;
     }
     received++;
     memcpy(&t1, &buf[hlen+8], sizeof(struct timeval));
     delay = (double)(t2.tv_sec-t1.tv_sec)*1000.0+(double)(t2.tv_usec-t1.tv_usec)/1000.0;
     if (!rtt_min || delay < rtt_min) {
         rtt_min = delay;
     }
     if (!rtt_max || delay > rtt_max) {
         rtt_max = delay;
     }
     rtt_avg = (rtt_avg*(received-1)/received)+(delay/received);
   }
   IcmpUnlock(server, fd);
   if (!received) {
       Tcl_AppendResult(interp, "noConnectivity: no reply from ", host, 0);
       return TCL_ERROR;
   }
   // Calculate statistics
   loss = received > 0 ? 100 - ((received*100)/sent) : !sent ? 0 : 100;

   Tcl_Obj *obj = Tcl_NewListObj(0, 0);
   Tcl_ListObjAppendElement(interp, obj, Tcl_NewIntObj(sent));
   Tcl_ListObjAppendElement(interp, obj, Tcl_NewIntObj(received));
   Tcl_ListObjAppendElement(interp, obj, Tcl_NewIntObj(loss));
   Tcl_ListObjAppendElement(interp, obj, Tcl_NewDoubleObj(rtt_min));
   Tcl_ListObjAppendElement(interp, obj, Tcl_NewDoubleObj(rtt_avg));
   Tcl_ListObjAppendElement(interp, obj, Tcl_NewDoubleObj(rtt_max));
   Tcl_SetObjResult(interp, obj);

   return TCL_OK;
}

// Formatting functions are borrowed from scotty and slightly modified
static void FormatStringTC(Tcl_Interp *interp, char *bytes, char *fmt)
{
    int i = 0,  len = strlen(bytes),  pfx,  have_pfx;
    char *last_fmt;
    Ns_DString ds;

    Ns_DStringInit(&ds);

    while (*fmt && i < len) {
        last_fmt = fmt;		/* save for loops */
        have_pfx = pfx = 0;	/* scan prefix: */
        while (*fmt && isdigit((int) *fmt)) {
            pfx = pfx * 10 + *fmt - '0',  have_pfx = 1,  fmt++;
        }
        if (!have_pfx) {
            pfx = 1;
        }
        switch (*fmt) {
         case 'a': {
            int n = (pfx < (len-i)) ? pfx : len-i;
            Ns_DStringNAppend(&ds, bytes+i, n);
            i += n;
	    break;
         }
        case 'b':
        case 'd':
        case 'o':
        case 'x': {
            long vv;
	    for (vv = 0;pfx > 0 && i < len;i++, pfx--) vv = vv * 256 + (bytes[i] & 0xff);
	    switch (*fmt) {
	     case 'd':
	        Ns_DStringPrintf(&ds, "%ld", vv);
 	       break;
             case 'o':
                Ns_DStringPrintf(&ds, "%lo", vv);
                break;
             case 'x':
                Ns_DStringPrintf(&ds, "%.*lX",  pfx * 2,  vv);
                break;
             case 'b': {
	        int i,  j;
                 char buf[32];
	        for (i = (sizeof(int) * 8 - 1); i >= 0 && ! (vv & (1 << i)); i--);
                for (j = 0; i >= 0; i--,  j++) {
                    buf[j] = vv & (1 << i) ? '1' : '0';
                }
                buf[j] = 0;
                Ns_DStringAppend(&ds, buf);
                break;
             }
            }
            break;
        }
       }
       fmt++;
       // Check for a separator and repeat with last format if
       // data is still available.
       if (*fmt && !isdigit((int) *fmt) && *fmt != '*') {
           if (i < len) {
               Ns_DStringNAppend(&ds, fmt, 1);
           }
           fmt++;
       }
       if (!*fmt && (i < len)) {
           fmt = last_fmt;
       }
    }
    Tcl_AppendResult(interp, Ns_DStringValue(&ds), 0);
    Ns_DStringFree(&ds);
}

static void FormatIntTC(Tcl_Interp *interp, char *bytes, char *fmt)
{
    char buffer[32];

    switch (fmt[0]) {
     case 'd': {
        int dot = 0;
        float value = atof(bytes);
	if (fmt[1] == '-' && isdigit((int)fmt[2])) {
            if ((dot = atoi(&fmt[2]))) {
                value = value/(10*dot);
            }
        }
        snprintf(buffer, 31, "%.*f", dot, value);
        Tcl_AppendResult(interp, buffer, 0);
	break;
     }
    case 'x': {
	sprintf(buffer, "%lx", atol(bytes));
        Tcl_AppendResult(interp, buffer, 0);
	break;
     }
    case 'o': {
	sprintf(buffer, "%lo", atol(bytes));
        Tcl_AppendResult(interp, buffer, 0);
        break;
     }
    case 'b': {
        long i,  j = 0,  value = atol(bytes);
	if (value < 0) buffer[j++] = '-', value *= -1;
	for (i = (sizeof(long) * 8 - 1); i > 0 && ! (value & (1 << i)); i--);
	for (; i >= 0; i--,  j++) buffer[j] = value & (1 << i) ? '1' : '0';
	buffer[j] = 0;
	Tcl_AppendResult(interp, buffer, 0);
	break;
     }
    }
}

/*
 * Note: this code is harmless on little-endian machines.
 */
static void byteReverse(unsigned char *buf,  unsigned len)
{
#ifdef HIGHFIRST
    unsigned int t;
    do {
      t = (unsigned int) ((unsigned) buf[3] << 8 | buf[2]) << 16 | ((unsigned) buf[1] << 8 | buf[0]);
      *(unsigned int *) buf = t;
      buf += 4;
    } while (--len);
#endif
}

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
static void MD5Init(struct MD5Context *ctx)
{
    ctx->buf[0] = 0x67452301U;
    ctx->buf[1] = 0xefcdab89U;
    ctx->buf[2] = 0x98badcfeU;
    ctx->buf[3] = 0x10325476U;
    ctx->bits[0] = 0;
    ctx->bits[1] = 0;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
static void MD5Update(struct MD5Context *ctx,  unsigned const char *buf,  unsigned len)
{
    unsigned int t;

    /* Update bitcount */
    t = ctx->bits[0];
    if ((ctx->bits[0] = t + ((unsigned int) len << 3)) < t) ctx->bits[1]++;
    ctx->bits[1] += len >> 29;
    t = (t >> 3) & 0x3f;	/* Bytes already in shsInfo->data */
    /* Handle any leading odd-sized chunks */
    if (t) {
	unsigned char *p = (unsigned char *) ctx->in + t;
	t = 64 - t;
	if (len < t) {
	  memcpy(p,  buf,  len);
          return;
	}
	memcpy(p,  buf,  t);
	byteReverse(ctx->in,  16);
	MD5Transform(ctx->buf,  (unsigned int *) ctx->in);
	buf += t;
	len -= t;
    }
    /* Process data in 64-byte chunks */
    while (len >= 64) {
        memcpy(ctx->in,  buf,  64);
        byteReverse(ctx->in,  16);
        MD5Transform(ctx->buf,  (unsigned int *) ctx->in);
        buf += 64;
        len -= 64;
    }
    /* Handle any remaining bytes of data. */
    memcpy(ctx->in,  buf,  len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of bits processed,  MSB-first)
 */
static void MD5Final(unsigned char digest[16],  struct MD5Context *ctx)
{
    unsigned count;
    unsigned char *p;

    /* Compute number of bytes mod 64 */
    count = (ctx->bits[0] >> 3) & 0x3F;
    /* Set the first char of padding to 0x80.  This is safe since there is
       always at least one byte free */
    p = ctx->in + count;
    *p++ = 0x80;
    /* Bytes of padding needed to make 64 bytes */
    count = 64 - 1 - count;
    /* Pad out to 56 mod 64 */
    if (count < 8) {
        /* Two lots of padding:  Pad the first block to 64 bytes */
        memset(p,  0,  count);
        byteReverse(ctx->in,  16);
        MD5Transform(ctx->buf,  (unsigned int *) ctx->in);
        /* Now fill the next block with 56 bytes */
        memset(ctx->in,  0,  56);
    } else {
        /* Pad block to 56 bytes */
        memset(p,  0,  count - 8);
    }
    byteReverse(ctx->in,  14);
    /* Append length in bits and transform */
    ((unsigned int *) ctx->in)[14] = ctx->bits[0];
    ((unsigned int *) ctx->in)[15] = ctx->bits[1];
    MD5Transform(ctx->buf,  (unsigned int *) ctx->in);
    byteReverse((unsigned char *) ctx->buf,  4);
    memcpy(digest,  ctx->buf,  16);
    memset(ctx,  0,  sizeof(ctx));	/* In case it's sensitive */
}

/*
 * The core of the MD5 algorithm,  this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
static void MD5Transform(unsigned int buf[4],  unsigned int const in[16])
{
    register unsigned int a,  b,  c,  d;

    a = buf[0];
    b = buf[1];
    c = buf[2];
    d = buf[3];

    MD5STEP(F1,  a,  b,  c,  d,   in[0] + 0xd76aa478U,   7);
    MD5STEP(F1,  d,  a,  b,  c,   in[1] + 0xe8c7b756U,  12);
    MD5STEP(F1,  c,  d,  a,  b,   in[2] + 0x242070dbU,  17);
    MD5STEP(F1,  b,  c,  d,  a,   in[3] + 0xc1bdceeeU,  22);
    MD5STEP(F1,  a,  b,  c,  d,   in[4] + 0xf57c0fafU,   7);
    MD5STEP(F1,  d,  a,  b,  c,   in[5] + 0x4787c62aU,  12);
    MD5STEP(F1,  c,  d,  a,  b,   in[6] + 0xa8304613U,  17);
    MD5STEP(F1,  b,  c,  d,  a,   in[7] + 0xfd469501U,  22);
    MD5STEP(F1,  a,  b,  c,  d,   in[8] + 0x698098d8U,   7);
    MD5STEP(F1,  d,  a,  b,  c,   in[9] + 0x8b44f7afU,  12);
    MD5STEP(F1,  c,  d,  a,  b,  in[10] + 0xffff5bb1U,  17);
    MD5STEP(F1,  b,  c,  d,  a,  in[11] + 0x895cd7beU,  22);
    MD5STEP(F1,  a,  b,  c,  d,  in[12] + 0x6b901122U,   7);
    MD5STEP(F1,  d,  a,  b,  c,  in[13] + 0xfd987193U,  12);
    MD5STEP(F1,  c,  d,  a,  b,  in[14] + 0xa679438eU,  17);
    MD5STEP(F1,  b,  c,  d,  a,  in[15] + 0x49b40821U,  22);

    MD5STEP(F2,  a,  b,  c,  d,   in[1] + 0xf61e2562U,   5);
    MD5STEP(F2,  d,  a,  b,  c,   in[6] + 0xc040b340U,   9);
    MD5STEP(F2,  c,  d,  a,  b,  in[11] + 0x265e5a51U,  14);
    MD5STEP(F2,  b,  c,  d,  a,   in[0] + 0xe9b6c7aaU,  20);
    MD5STEP(F2,  a,  b,  c,  d,   in[5] + 0xd62f105dU,   5);
    MD5STEP(F2,  d,  a,  b,  c,  in[10] + 0x02441453U,   9);
    MD5STEP(F2,  c,  d,  a,  b,  in[15] + 0xd8a1e681U,  14);
    MD5STEP(F2,  b,  c,  d,  a,   in[4] + 0xe7d3fbc8U,  20);
    MD5STEP(F2,  a,  b,  c,  d,   in[9] + 0x21e1cde6U,   5);
    MD5STEP(F2,  d,  a,  b,  c,  in[14] + 0xc33707d6U,   9);
    MD5STEP(F2,  c,  d,  a,  b,   in[3] + 0xf4d50d87U,  14);
    MD5STEP(F2,  b,  c,  d,  a,   in[8] + 0x455a14edU,  20);
    MD5STEP(F2,  a,  b,  c,  d,  in[13] + 0xa9e3e905U,   5);
    MD5STEP(F2,  d,  a,  b,  c,   in[2] + 0xfcefa3f8U,   9);
    MD5STEP(F2,  c,  d,  a,  b,   in[7] + 0x676f02d9U,  14);
    MD5STEP(F2,  b,  c,  d,  a,  in[12] + 0x8d2a4c8aU,  20);

    MD5STEP(F3,  a,  b,  c,  d,   in[5] + 0xfffa3942U,   4);
    MD5STEP(F3,  d,  a,  b,  c,   in[8] + 0x8771f681U,  11);
    MD5STEP(F3,  c,  d,  a,  b,  in[11] + 0x6d9d6122U,  16);
    MD5STEP(F3,  b,  c,  d,  a,  in[14] + 0xfde5380cU,  23);
    MD5STEP(F3,  a,  b,  c,  d,   in[1] + 0xa4beea44U,   4);
    MD5STEP(F3,  d,  a,  b,  c,   in[4] + 0x4bdecfa9U,  11);
    MD5STEP(F3,  c,  d,  a,  b,   in[7] + 0xf6bb4b60U,  16);
    MD5STEP(F3,  b,  c,  d,  a,  in[10] + 0xbebfbc70U,  23);
    MD5STEP(F3,  a,  b,  c,  d,  in[13] + 0x289b7ec6U,   4);
    MD5STEP(F3,  d,  a,  b,  c,   in[0] + 0xeaa127faU,  11);
    MD5STEP(F3,  c,  d,  a,  b,   in[3] + 0xd4ef3085U,  16);
    MD5STEP(F3,  b,  c,  d,  a,   in[6] + 0x04881d05U,  23);
    MD5STEP(F3,  a,  b,  c,  d,   in[9] + 0xd9d4d039U,   4);
    MD5STEP(F3,  d,  a,  b,  c,  in[12] + 0xe6db99e5U,  11);
    MD5STEP(F3,  c,  d,  a,  b,  in[15] + 0x1fa27cf8U,  16);
    MD5STEP(F3,  b,  c,  d,  a,   in[2] + 0xc4ac5665U,  23);

    MD5STEP(F4,  a,  b,  c,  d,   in[0] + 0xf4292244U,   6);
    MD5STEP(F4,  d,  a,  b,  c,   in[7] + 0x432aff97U,  10);
    MD5STEP(F4,  c,  d,  a,  b,  in[14] + 0xab9423a7U,  15);
    MD5STEP(F4,  b,  c,  d,  a,   in[5] + 0xfc93a039U,  21);
    MD5STEP(F4,  a,  b,  c,  d,  in[12] + 0x655b59c3U,   6);
    MD5STEP(F4,  d,  a,  b,  c,   in[3] + 0x8f0ccc92U,  10);
    MD5STEP(F4,  c,  d,  a,  b,  in[10] + 0xffeff47dU,  15);
    MD5STEP(F4,  b,  c,  d,  a,   in[1] + 0x85845dd1U,  21);
    MD5STEP(F4,  a,  b,  c,  d,   in[8] + 0x6fa87e4fU,   6);
    MD5STEP(F4,  d,  a,  b,  c,  in[15] + 0xfe2ce6e0U,  10);
    MD5STEP(F4,  c,  d,  a,  b,   in[6] + 0xa3014314U,  15);
    MD5STEP(F4,  b,  c,  d,  a,  in[13] + 0x4e0811a1U,  21);
    MD5STEP(F4,  a,  b,  c,  d,   in[4] + 0xf7537e82U,   6);
    MD5STEP(F4,  d,  a,  b,  c,  in[11] + 0xbd3af235U,  10);
    MD5STEP(F4,  c,  d,  a,  b,   in[2] + 0x2ad7d2bbU,  15);
    MD5STEP(F4,  b,  c,  d,  a,   in[9] + 0xeb86d391U,  21);

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}

static void MD5Calc(unsigned char *output,  unsigned char *input,  unsigned int inlen)
{
    MD5_CTX context;

    MD5Init(&context);
    MD5Update(&context,  input,  inlen);
    MD5Final(output,  &context);
}

static RadiusDict *RadiusDictFind(Server *server, char *name, int attr, int vendor, int unlink)
{
    RadiusDict *dict;

    if (attr == -1 && name) {
        attr = atoi(name);
    }
    Ns_MutexLock(&server->radius.dictMutex);
    for (dict = server->radius.dictList; dict; dict = dict->next) {
        if (vendor == -1 || dict->vendor == vendor) {
            if (dict->attribute == attr || (name && !strcasecmp(dict->name, name))) {
                break;
            }
        }
    }
    if (unlink && dict) {
        if (dict->prev) {
            dict->prev->next = dict->next;
        }
        if (dict->next) {
            dict->next->prev = dict->prev;
        }
        if (dict == server->radius.dictList) {
            server->radius.dictList = dict->next;
        }
        dict->next = dict->prev = 0;
    }
    Ns_MutexUnlock(&server->radius.dictMutex);
    return dict;
}

static RadiusDict *RadiusDictAdd(Server *server, char *name, int attr, int vendor, int type)
{
    RadiusDict *dict = 0;

    if (attr && name) {
        dict = (RadiusDict*)ns_calloc(1, sizeof(RadiusDict));
        dict->type = type;
        dict->vendor = vendor;
        dict->attribute = attr;
        strncpy(dict->name, name, RADIUS_STRING_LEN);
        Ns_StrToLower(dict->name);
        Ns_MutexLock(&server->radius.dictMutex);
        dict->next = server->radius.dictList;
        if (dict->next) {
            dict->next->prev = dict;
        }
        server->radius.dictList = dict;
        Ns_MutexUnlock(&server->radius.dictMutex);
    }
    return dict;
}

static void RadiusDictPrintf(Server *server, Ns_DString *ds)
{
    RadiusDict *dict;
    RadiusValue *value;

    Ns_MutexLock(&server->radius.dictMutex);
    for (dict = server->radius.dictList; dict; dict = dict->next) {
        Ns_DStringPrintf(ds, "%s %d %d %d {", dict->name, dict->attribute, dict->vendor, dict->type);
        for (value = dict->values; value; value = value->next) {
            Ns_DStringPrintf(ds, "%s %d ", value->name, value->value);
        }
        Ns_DStringPrintf(ds, "} ");
    }
    Ns_MutexUnlock(&server->radius.dictMutex);
}

// generate a random vector
static void RadiusVectorCreate(RadiusVector vector)
{
    MD5_CTX md5;
    struct timeval tv;
    struct timezone tz;

    // Use the time of day with the best resolution the system can
    // give us -- often close to microsecond accuracy.
    gettimeofday(&tv, &tz);
    tv.tv_sec ^= getpid() * (int)pthread_self(); /* add some secret information */
    // Hash things to get some cryptographically strong pseudo-random numbers
    MD5Init(&md5);
    MD5Update(&md5, (unsigned char *)&tv, sizeof(tv));
    MD5Update(&md5, (unsigned char *)&tz, sizeof(tz));
    MD5Final(vector, &md5);
}

// MD5(packet header + packet data + secret)
static int RadiusVectorVerify(RadiusHeader *hdr, RadiusVector vector, char *secret)
{
    MD5_CTX md5;
    RadiusVector digest, reply;

    memcpy(reply, hdr->vector, RADIUS_VECTOR_LEN);
    memcpy(hdr->vector, vector, RADIUS_VECTOR_LEN);
    MD5Init(&md5);
    MD5Update(&md5, (unsigned char *)hdr, ntohs(hdr->length));
    MD5Update(&md5, (unsigned char *)secret, strlen(secret));
    MD5Final(digest, &md5);
    return memcmp(digest, reply, RADIUS_VECTOR_LEN);
}

static void RadiusPasswdDecrypt(RadiusAttr *attr, RadiusVector vector, char *secret, char *salt, int saltlen)
{
    RadiusVector digest;
    unsigned char *p = vector;
    unsigned char pw[RADIUS_STRING_LEN+1];
    unsigned char md5[RADIUS_STRING_LEN+1];
    unsigned int i, j, secretlen = strlen(secret);

    memset(pw, 0, RADIUS_STRING_LEN+1);
    memcpy(pw, attr->sval, attr->lval);
    memcpy(md5, secret, secretlen);
    for (i = 0;i < attr->lval;) {
        memcpy(&md5[secretlen], p, RADIUS_VECTOR_LEN);
        if (!i && saltlen) {
            memcpy(&md5[secretlen + RADIUS_VECTOR_LEN], salt, saltlen);
            MD5Calc(digest, md5, secretlen + RADIUS_VECTOR_LEN + saltlen);
        } else {
            MD5Calc(digest, md5, secretlen + RADIUS_VECTOR_LEN);
        }
        p = &attr->sval[i];
        for (j = 0;j < RADIUS_VECTOR_LEN;j++, i++) pw[i] ^= digest[j];
    }
    attr->lval = strlen((char*)pw);
    memcpy(attr->sval, pw, RADIUS_STRING_LEN);
}

static void RadiusPasswdEncrypt(RadiusAttr *attr, RadiusVector vector, char *secret, char *salt, int saltlen)
{
    RadiusVector digest;
    unsigned int chunks;
    unsigned char *p = vector;
    unsigned char pw[RADIUS_STRING_LEN+1];
    unsigned char md5[RADIUS_STRING_LEN+1];
    unsigned int i, j, secretlen = strlen(secret);

    memset(pw, 0, RADIUS_STRING_LEN+1);
    memcpy(pw, attr->sval, attr->lval);
    memcpy(md5, secret, secretlen);
    chunks = (attr->lval + RADIUS_VECTOR_LEN - 1) / RADIUS_VECTOR_LEN;
    for (i = 0;i < chunks * RADIUS_VECTOR_LEN; ) {
        memcpy(&md5[secretlen], p, RADIUS_VECTOR_LEN);
        if (i == 0 && saltlen) {
            memcpy(&md5[secretlen + RADIUS_VECTOR_LEN], salt, saltlen);
            MD5Calc(digest, md5,  secretlen + RADIUS_VECTOR_LEN + saltlen);
        } else {
            MD5Calc(digest, md5, secretlen + RADIUS_VECTOR_LEN);
        }
        p = &pw[i];
        for (j = 0; j < RADIUS_VECTOR_LEN; j++,  i++) {
            pw[i] ^= digest[j];
        }
    }
    attr->lval = chunks * RADIUS_VECTOR_LEN;
    memcpy(attr->sval, pw, RADIUS_STRING_LEN);
}

static RadiusAttr *RadiusAttrCreate(Server *server, char *name, int attr, int vendor, char *val, int len)
{
    RadiusAttr *vp;
    RadiusDict *dict;
    RadiusValue *value;

    dict = RadiusDictFind(server, name, attr, vendor, 0);
    if (!dict && attr <= 0) {
        Ns_Log(Error, "RadiusAttrCreate: unknown attr: %s %d %d", name, attr, vendor);
        return 0;
    }
    vp = (RadiusAttr*)ns_calloc(1, sizeof(RadiusAttr));
    vp->vendor = vendor;
    vp->attribute = attr;
    if (dict) {
        vp->type = dict->type;
        vp->attribute = dict->attribute;
        strcpy(vp->name, dict->name);
    } else {
        sprintf(vp->name, "A%d-V%d", attr, vendor);
        vp->type = RADIUS_TYPE_STRING;
    }
    switch(vp->type) {
     case RADIUS_TYPE_STRING:
         if (len <= 0) {
             len = strlen((const char*)val);
         }
         vp->lval = len < RADIUS_STRING_LEN ? len : RADIUS_STRING_LEN;
         memcpy(vp->sval, val, vp->lval);
         Ns_StrTrimRight((char*)vp->sval);
         break;
     case RADIUS_TYPE_FILTER_BINARY:
         if (len <= 0) {
             len = strlen((const char*)val);
         }
         vp->lval = len < RADIUS_STRING_LEN ? len : RADIUS_STRING_LEN;
         memcpy(vp->sval, val, vp->lval);
         break;
     case RADIUS_TYPE_INTEGER:
         // Try values for that attribute
         if (isalpha(val[0])) {
             for (value = dict->values;  value; value = value->next) {
                 if (!strcasecmp(value->name, val)) {
                     vp->lval = value->value;
                     return vp;
                 }
             }
         }
     case RADIUS_TYPE_DATE:
     case RADIUS_TYPE_IPADDR:
         if (len > 0) {
             vp->lval = ntohl(*(unsigned long *)val);
         } else
         if (len < 0) {
             vp->lval = atol((const char*)val);
         } else {
             memcpy(&vp->lval, val, sizeof(vp->lval));
         }
         break;
     default:
         ns_free(vp);
         vp = 0;
    }
    return vp;
}

static void RadiusAttrPrintf(RadiusAttr *vp, Ns_DString *ds, int printname, int printall)
{
    unsigned i;
    RadiusAttr *attr;

    for (attr = vp; attr; attr = attr->next) {
        if (attr != vp) {
            Ns_DStringAppend(ds, " ");
        }
        if (printname) {
            Ns_DStringPrintf(ds, "%s ", attr->name);
        }
        switch(attr->type) {
         case RADIUS_TYPE_DATE:
            char buf[64];
            strftime(buf, sizeof(buf), "%Y-%m-%d %T", ns_localtime((const time_t*)&attr->lval));
            Ns_DStringPrintf(ds, "%s%s%s", printname?"{":"", buf, printname?"}":"");
            break;
         case RADIUS_TYPE_INTEGER:
            Ns_DStringPrintf(ds, "%d", attr->lval);
            break;
         case RADIUS_TYPE_IPADDR:
            Ns_DStringPrintf(ds, "%s", ns_inet_ntoa(*((struct in_addr*)&attr->lval)));
            break;
         case RADIUS_TYPE_STRING:
         case RADIUS_TYPE_FILTER_BINARY:
            for (i = 0; i < attr->lval; i++) {
                 if (!isprint((int)attr->sval[i])) {
                     break;
                 }
            }
            if (i == attr->lval) {
                Ns_DStringPrintf(ds, "%s%s%s", printname?"{":"", attr->sval, printname?"}":"");
                break;
            }
         default:
            for (i = 0; i < attr->lval; i++) {
                Ns_DStringPrintf(ds, "%2.2X", attr->sval[i]);
            }
        }
        if (!printall) {
            break;
        }
      }
}

static void RadiusAttrLink(RadiusAttr **list, RadiusAttr *vp)
{
    for (;*list; list = &(*list)->next);
    *list = vp;
}

static RadiusAttr *RadiusAttrFind(RadiusAttr *vp, char *name, int attr, int vendor)
{
    for (;vp; vp = vp->next) {
        if (vendor == -1 || vp->vendor == vendor) {
            if (vp->attribute == attr || (name && !strcasecmp(vp->name, name))) {
                return vp;
            }
        }
    }
    return 0;
}

static void RadiusAttrFree(RadiusAttr **vp)
{
    while (*vp) {
        RadiusAttr *next = (*vp)->next;
        ns_free(*vp);
        *vp = next;
    }
}

static RadiusAttr *RadiusAttrParse(Server *server, RadiusHeader *auth, int len, char *secret)
{
    RadiusAttr *head = 0, *vp;
    int length, vendor, attr, attrlen;
    unsigned char *ptr, *p0 = (unsigned char*)auth;

    // Extract attribute-value pairs
    ptr = p0 + sizeof(RadiusHeader);
    length = ntohs(auth->length) - sizeof(RadiusHeader);
    while (length > 0) {
        if ((ptr - p0) + 2 >= RADIUS_BUFFER_LEN) {
            break;
        }
        vendor = 0;
        attr = *ptr++;
        attrlen = *ptr++;
        attrlen -= 2;
        if (attrlen < 0 ||
            attrlen > RADIUS_STRING_LEN ||
            (ptr - p0) + attrlen >= RADIUS_BUFFER_LEN) {
            break;
        }
        // Vendor specific attribute
        if (attr == RADIUS_VENDOR_SPECIFIC) {
            if (((ptr - p0)) + attrlen + 6 >= RADIUS_BUFFER_LEN) {
                break;
            }
            memcpy(&vendor, ptr, sizeof(unsigned int));
            vendor = ntohl(vendor);
            ptr += 4;
            attr = *ptr++;
            ptr++;
            attrlen -= 6;
        }
        if ((vp = RadiusAttrCreate(server, 0, attr, vendor, (char*)ptr, attrlen))) {
            RadiusAttrLink(&head, vp);
            /* Perform decryption if necessary */
            switch(vp->attribute) {
             case RADIUS_USER_PASSWORD:
                RadiusPasswdDecrypt(vp, auth->vector, secret, 0, 0);
                break;
            }
        }
        ptr += attrlen;
        length -= attrlen + 2;
    }
    return head;
}

static unsigned char *RadiusAttrPack(RadiusAttr *vp, unsigned char *ptr, short *length)
{
    unsigned char *p0 = ptr;
    unsigned int lvalue, len, vlen = 0;

    if (!ptr || !vp) {
        return ptr;
    }
    if (vp->vendor> 0) {
        vlen = 6;
        if (*length + vlen >= RADIUS_BUFFER_LEN) {
            return p0;
        }
        *ptr++ = RADIUS_VENDOR_SPECIFIC;
        *ptr++ = 6; /* Length of VS header (len/opt/oid) */
        lvalue = htonl(vp->vendor);
        memcpy(ptr,  &lvalue,  sizeof(unsigned int));
        ptr += 4;
    }
    switch (vp->type) {
     case RADIUS_TYPE_STRING:
     case RADIUS_TYPE_FILTER_BINARY:
         len = strlen((char*)vp->sval);
         if (*length + vlen+len+2 >= RADIUS_BUFFER_LEN) {
             return p0;
         }
         *ptr++ = vp->attribute;
         *ptr++ = len + 2;
         memcpy(ptr, vp->sval, len);
         ptr += len;
         *length += vlen + len + 2;
         break;
     case RADIUS_TYPE_DATE:
     case RADIUS_TYPE_IPADDR:
     case RADIUS_TYPE_INTEGER:
         len = sizeof(lvalue);
         if (*length + vlen+len+2 >= RADIUS_BUFFER_LEN) {
             return p0;
         }
         *ptr++ = vp->attribute;
         *ptr++ = sizeof(lvalue) + 2;
         lvalue = htonl(vp->lval);
         memcpy(ptr, (char *)&lvalue, sizeof(lvalue));
         ptr += len;
         *length += vlen + len + 2;
         break;
     default:
         return p0;
    }
    if (vp->vendor > 0) {
        *p0 += len+2;
    }
    return ptr;
}

static void RadiusHeaderPack(RadiusHeader *hdr, int id, int code, RadiusVector vector, RadiusAttr *vp, char *secret)
{
    MD5_CTX md5;
    unsigned char *ptr;
    RadiusVector digest;

    if (!hdr || !secret || !vector) {
        return;
    }
    // Generate random id
    if (!id) {
        srand(time(0) ^ getpid());
        id = (rand() ^ (int)hdr);
    }
    hdr->id = id;
    hdr->code = code;
    hdr->length = sizeof(RadiusHeader);
    ptr = ((unsigned char*)hdr) + hdr->length;
    memcpy(hdr->vector, vector, RADIUS_VECTOR_LEN);
    // Pack attributes into the packet
    for (;vp; vp = vp->next) {
        switch(vp->attribute) {
         case RADIUS_USER_PASSWORD:
            RadiusPasswdEncrypt(vp, hdr->vector, secret, 0, 0);
            break;
        }
        ptr = RadiusAttrPack(vp, ptr, (short*)&hdr->length);
    }
    hdr->length = htons(hdr->length);
    // Finish packing
    switch(code) {
     case RADIUS_ACCESS_REQUEST:
     case RADIUS_STATUS_SERVER:
        break;

     case RADIUS_ACCOUNTING_REQUEST:
        /* Calculate the md5 hash over the entire packet and put it in the vector. */
        memset(hdr->vector, 0, RADIUS_VECTOR_LEN);
        MD5Init(&md5);
        MD5Update(&md5, (unsigned char *)hdr, ntohs(hdr->length));
        MD5Update(&md5, (unsigned char *)secret, strlen(secret));
        MD5Final(digest, &md5);
        memcpy(hdr->vector, vector, RADIUS_VECTOR_LEN);
        break;

     case RADIUS_ACCESS_ACCEPT:
     case RADIUS_ACCESS_REJECT:
     case RADIUS_ACCOUNTING_RESPONSE:
     case RADIUS_ACCESS_CHALLENGE:
        MD5Init(&md5);
        MD5Update(&md5, (unsigned char *)hdr, ntohs(hdr->length));
        MD5Update(&md5, (unsigned char *)secret, strlen(secret));
        MD5Final(digest, &md5);
        memcpy(hdr->vector, digest, RADIUS_VECTOR_LEN);
        break;

     default:
        /* Calculate the response digest and store it in the vector */
        memset(hdr->vector, 0, RADIUS_VECTOR_LEN);
        MD5Init(&md5);
        MD5Update(&md5, (unsigned char *)hdr, ntohs(hdr->length));
        MD5Update(&md5, (unsigned char *)secret, strlen(secret));
        MD5Final(digest, &md5);
        memcpy(hdr->vector, digest, RADIUS_VECTOR_LEN);
        break;
    }
}

static void RadiusClientAdd(Server *server, char *host, char *secret)
{
    RadiusClient *client;
    struct sockaddr_in addr;

    if (Ns_GetSockAddr(&addr, host, 0) != NS_OK) {
        return;
    }
    client = (RadiusClient*)ns_calloc(1, sizeof(RadiusClient));
    client->addr = addr.sin_addr;
    strncpy(client->secret, secret, RADIUS_VECTOR_LEN);
    Ns_MutexLock(&server->radius.clientMutex);
    client->next = server->radius.clientList;
    if (client->next) {
        client->next->prev = client;
    }
    server->radius.clientList = client;
    Ns_MutexUnlock(&server->radius.clientMutex);
}

static void RadiusClientPrintf(Server *server, Ns_DString *ds)
{
    RadiusClient *client;

    Ns_MutexLock(&server->radius.clientMutex);
    for (client = server->radius.clientList; client; client = client->next) {
        Ns_DStringPrintf(ds, "%s %s ", ns_inet_ntoa(client->addr), client->secret);
    }
    Ns_MutexUnlock(&server->radius.clientMutex);
}

static RadiusClient *RadiusClientFind(Server *server, struct in_addr addr, int unlink)
{
    RadiusClient *client = 0;

    Ns_MutexLock(&server->radius.clientMutex);
    for (client = server->radius.clientList; client; client = client->next) {
        if (!memcmp(&client->addr, &addr, sizeof(struct in_addr))) {
            break;
        }
    }
    if (unlink && client) {
        if (client->prev) {
            client->prev->next = client->next;
        }
        if (client->next) {
            client->next->prev = client->prev;
        }
        if (client == server->radius.clientList) {
            server->radius.clientList = client->next;
        }
        client->next = client->prev = 0;
    }
    Ns_MutexUnlock(&server->radius.clientMutex);
    return client;
}

static RadiusUser *RadiusUserAdd(Server *server, char *user)
{
    int n;
    RadiusUser *rec;
    Tcl_HashEntry *entry;

    Ns_MutexLock(&server->radius.userMutex);
    entry = Tcl_CreateHashEntry(&server->radius.userList, user, &n);
    if (n) {
        rec = (RadiusUser*)ns_calloc(1, sizeof(RadiusUser));
        Tcl_SetHashValue(entry, (ClientData)rec);
    }
    rec = (RadiusUser*)Tcl_GetHashValue(entry);
    Ns_MutexUnlock(&server->radius.userMutex);
    return rec;
}

static void RadiusUserDel(Server *server, char *user)
{
    Tcl_HashEntry *entry;
    Tcl_HashSearch search;

    Ns_MutexLock(&server->radius.userMutex);
    entry = Tcl_FirstHashEntry(&server->radius.userList, &search);
    while (entry) {
      if (!user || Tcl_StringCaseMatch(Tcl_GetHashKey(&server->radius.userList, entry), user, 1)) {
          ns_free(Tcl_GetHashValue(entry));
          Tcl_DeleteHashEntry(entry);
      }
      entry = Tcl_NextHashEntry(&search);
    }
    Ns_MutexUnlock(&server->radius.userMutex);
}

static RadiusUser *RadiusUserFind(Server *server, char *user, Ns_DString *ds)
{
    RadiusUser *rec = 0;
    Tcl_HashEntry *entry;

    Ns_MutexLock(&server->radius.userMutex);
    entry = Tcl_FindHashEntry(&server->radius.userList, user);
    if (entry) {
        rec = (RadiusUser*)Tcl_GetHashValue(entry);
        Ns_DStringAppend(ds, "{");
        RadiusAttrPrintf(rec->config, ds, 1, 1);
        Ns_DStringAppend(ds, "} {");
        RadiusAttrPrintf(rec->reply, ds, 1, 1);
        Ns_DStringAppend(ds, "} ");
    }
    Ns_MutexUnlock(&server->radius.userMutex);
    return rec;
}

static int RadiusUserAttrFind(Server *server, char *user, Ns_DString *ds, char *name, int reply)
{
    int rc = 0;
    RadiusUser *rec;
    RadiusAttr *attr;
    Tcl_HashEntry *entry;

    Ns_MutexLock(&server->radius.userMutex);
    entry = Tcl_FindHashEntry(&server->radius.userList, user);
    if (entry) {
        rec = (RadiusUser*)Tcl_GetHashValue(entry);
        attr = RadiusAttrFind(reply ? rec->reply : rec->config, name, -1, -1);
        if (attr) {
            RadiusAttrPrintf(attr, ds, 0, 0);
            rc = 1;
        }
    }
    Ns_MutexUnlock(&server->radius.userMutex);
    return rc;
}

static void RadiusUserList(Server *server, char *user, Ns_DString *ds)
{
    RadiusUser *rec;
    Tcl_HashEntry *entry;
    Tcl_HashSearch search;

    Ns_MutexLock(&server->radius.userMutex);
    entry = Tcl_FirstHashEntry(&server->radius.userList, &search);
    while (entry) {
      if (!user || Tcl_StringCaseMatch(Tcl_GetHashKey(&server->radius.userList, entry), user, 1)) {
          rec = (RadiusUser*)Tcl_GetHashValue(entry);
          Ns_DStringPrintf(ds, "%s {", Tcl_GetHashKey(&server->radius.userList, entry));
          RadiusAttrPrintf(rec->config, ds, 1, 1);
          Ns_DStringAppend(ds, "} {");
          RadiusAttrPrintf(rec->reply, ds, 1, 1);
          Ns_DStringAppend(ds, "} ");
      }
      entry = Tcl_NextHashEntry(&search);
    }
    Ns_MutexUnlock(&server->radius.userMutex);
}

/*
 *----------------------------------------------------------------------
 *
 * RadiusCmd --
 *
 *	Send RADIUS request and wait for response
 *
 * Results:
 *      reply code and attributes list or error
 *
 * Side effects:
 *  	None
 *
 *----------------------------------------------------------------------
 */
static int RadiusCmd(ClientData arg,  Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    Server *server = (Server*)arg;
    fd_set rfds;
    Ns_DString ds;
    int retries = 3;
    int timeout = 2;
    struct timeval tm;
    int fd, id, len, port, n, vendor;
    struct sockaddr_in sa;
    socklen_t salen = sizeof(sa);
    int code = RADIUS_ACCESS_REQUEST;
    unsigned char buffer[RADIUS_BUFFER_LEN];
    RadiusHeader *hdr;
    RadiusVector vector;
    RadiusAttr *attr, *vp = 0;
    RadiusClient *client = 0;
    RadiusUser *user;
    RadiusDict *dict = 0;
    RadiusValue *value;
    RadiusRequest *req;
    enum commands {
        cmdSend, cmdReqGet, cmdReqSet, cmdReqList,
        cmdDictList, cmdDictGet, cmdDictDel, cmdDictAdd, cmdDictValue, cmdDictLabel,
        cmdClientAdd, cmdClientList, cmdClientDel, cmdClientGet,
        cmdUserAdd, cmdUserFind, cmdUserDel, cmdUserList, cmdUserAttrFind,
        cmdReset
    };
    static const char *sCmd[] = {
        "send", "reqget", "reqset", "reqlist",
        "dictlist", "dictget", "dictdel", "dictadd", "dictvalue", "dictlabel",
        "clientadd", "clientlist", "clientdel", "clientget",
        "useradd", "userfind", "userdel", "userlist", "userattrfind",
        "reset",
        0
    };
    int cmd;

    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "args");
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], sCmd, "command", TCL_EXACT, &cmd) != TCL_OK) {
        return TCL_ERROR;
    }

    switch (cmd) {
     case cmdSend:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "host port secret ?Code code? ?Retries retries? ?Timeout timeout? ?attr value? ...");
            return TCL_ERROR;
        }
        if (!(port = atoi(Tcl_GetString(objv[3])))) {
            port = RADIUS_AUTH_PORT;
        }
        if (Ns_GetSockAddr((sockaddr_in*)&sa, Tcl_GetString(objv[2]), port) != NS_OK) {
            Tcl_AppendResult(interp, "noHost: unknown host: ", Tcl_GetString(objv[2]), 0);
            return TCL_ERROR;
        }
        for (int i = 5;i < objc - 1;i += 2) {
            if (!strcasecmp(Tcl_GetString(objv[i]), "Code")) {
                code = atoi(Tcl_GetString(objv[i+1]));
            } else
            if (!strcasecmp(Tcl_GetString(objv[i]), "Retries")) {
                retries = atoi(Tcl_GetString(objv[i+1]));
            } else
            if (!strcasecmp(Tcl_GetString(objv[i]), "Timeout")) {
                timeout = atoi(Tcl_GetString(objv[i+1]));
            } else {
              if ((attr = RadiusAttrCreate(server, Tcl_GetString(objv[i]), -1, 0, Tcl_GetString(objv[i+1]), -1))) {
                RadiusAttrLink(&vp, attr);
              } else {
                Tcl_AppendResult(interp, "unknown attribute ", Tcl_GetString(objv[i]), " ", Tcl_GetString(objv[i+1]), 0);
                return TCL_ERROR;
              }
            }
        }
        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            Tcl_AppendResult(interp, "noResponse: ", strerror(errno), 0);
            RadiusAttrFree(&vp);
            return -1;
        }
        // Build an request
        hdr = (RadiusHeader *)buffer;
        RadiusVectorCreate(vector);
        RadiusHeaderPack(hdr, 0, code, vector, vp, (char*)Tcl_GetString(objv[4]));
        RadiusAttrFree(&vp);
        memcpy(vector, hdr->vector, RADIUS_VECTOR_LEN);
        id = hdr->id;
again:
        if (sendto(fd, (char *)hdr, ntohs(hdr->length), 0, (struct sockaddr *)&sa, sizeof(struct sockaddr_in)) <= 0) {
            Tcl_AppendResult(interp, "noResponse: ", strerror(errno), 0);
            close(fd);
            return TCL_ERROR;
        }
        tm.tv_usec = 0L;
        tm.tv_sec = timeout;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        if (select(fd + 1, &rfds, 0, 0, &tm) < 0) {
            if (errno == EINTR) goto again;
            Tcl_AppendResult(interp, "noResponse: ", strerror(errno), 0);
            close(fd);
            return TCL_ERROR;
        }
        if (!FD_ISSET(fd, &rfds)) {
            if (--retries > 0) goto again;
            Tcl_AppendResult(interp, "noResponse: timeout", 0);
            close(fd);
            return TCL_ERROR;
        }
        if ((len = recvfrom(fd, (char *)buffer, sizeof(buffer), 0, (struct sockaddr*)&sa, (socklen_t*)&salen)) <= 0) {
            Tcl_AppendResult(interp, "noResponse: ", strerror(errno), 0);
            close(fd);
            return TCL_ERROR;
        }
        close(fd);
        // Verify that id (seq. number) matches what we sent
        if (hdr->id != (u_char)id || len < ntohs(hdr->length)) {
            Tcl_AppendResult(interp, "noResponse: ID/length does not match", 0);
            return TCL_ERROR;
        }
        // Verify reply md5 digest
        if (RadiusVectorVerify(hdr, vector, Tcl_GetString(objv[4]))) {
            Tcl_AppendResult(interp, "noResponse: invalid reply digest", 0);
            return TCL_ERROR;
        }
        Ns_DStringInit(&ds);
        Ns_DStringPrintf(&ds, "code %d id %d ipaddr %s ", hdr->code, hdr->id, ns_inet_ntoa(sa.sin_addr));
        if ((vp = RadiusAttrParse(server, hdr, len, Tcl_GetString(objv[4])))) {
            RadiusAttrPrintf(vp, &ds, 1, 1);
            RadiusAttrFree(&vp);
        }
        Tcl_AppendResult(interp, ds.string, 0);
        Ns_DStringFree(&ds);
        break;

     case cmdDictList:
        Ns_DStringInit(&ds);
        RadiusDictPrintf(server, &ds);
        Tcl_AppendResult(interp, ds.string, 0);
        Ns_DStringFree(&ds);
        break;

     case cmdDictAdd:
        if (objc < 6) {
            Tcl_WrongNumArgs(interp, 2, objv, "name attr vendor type valname valnum ...");
            return TCL_ERROR;
        }
        if (!strcmp(Tcl_GetString(objv[5]), "string")) {
            n = RADIUS_TYPE_STRING;
        } else
        if (!strcmp(Tcl_GetString(objv[5]), "filter")) {
            n = RADIUS_TYPE_FILTER_BINARY;
        } else
        if (!strcmp(Tcl_GetString(objv[5]), "integer")) {
            n = RADIUS_TYPE_INTEGER;
        } else
        if (!strcmp(Tcl_GetString(objv[5]), "ipaddr")) {
            n = RADIUS_TYPE_IPADDR;
        } else
        if (!strcmp(Tcl_GetString(objv[5]), "date")) {
            n = RADIUS_TYPE_DATE;
        } else {
            n = atoi(Tcl_GetString(objv[5]));
        }
        dict = RadiusDictFind(server, 0, atoi(Tcl_GetString(objv[3])), atoi(Tcl_GetString(objv[4])), 0);
        if (!dict) {
            dict = RadiusDictAdd(server, Tcl_GetString(objv[2]), atoi(Tcl_GetString(objv[3])), atoi(Tcl_GetString(objv[4])), n);
        }
        if (dict) {
            for (int i = 6; i < objc - 1; i+= 2) {
                value = (RadiusValue*)ns_calloc(1, sizeof(RadiusValue));
                strncpy(value->name, Tcl_GetString(objv[i]), RADIUS_STRING_LEN);
                value->value = atoi(Tcl_GetString(objv[i+1]));
                value->next = dict->values;
                dict->values = value;
            }
        }
        break;

     case cmdDictValue:
        if (objc < 5) {
            Tcl_WrongNumArgs(interp, 2, objv, "name vendor label");
            return TCL_ERROR;
        }
        dict = RadiusDictFind(server, Tcl_GetString(objv[2]), -1, atoi(Tcl_GetString(objv[3])), 0);
        if (dict) {
            for (value = dict->values; value; value = value->next) {
                if (!strcasecmp(value->name, Tcl_GetString(objv[4]))) {
                    Tcl_SetObjResult(interp, Tcl_NewIntObj(value->value));
                    return TCL_OK;
                }
            }
        }
        Tcl_AppendResult(interp, Tcl_GetString(objv[4]), 0);
        break;

     case cmdDictLabel:
        if (objc < 5) {
            Tcl_WrongNumArgs(interp, 2, objv, "namr vendor num");
            return TCL_ERROR;
        }
        dict = RadiusDictFind(server, Tcl_GetString(objv[2]), -1, atoi(Tcl_GetString(objv[3])), 0);
        if (dict) {
            n = atoi(Tcl_GetString(objv[4]));
            for (value = dict->values; value; value = value->next) {
                if (value->value == n) {
                    Tcl_AppendResult(interp, value->name, 0);
                    return TCL_OK;
                }
            }
        }
        Tcl_AppendResult(interp, Tcl_GetString(objv[4]), 0);
        break;

     case cmdDictGet:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "name|attr ?vendor?");
            return TCL_ERROR;
        }
        dict = RadiusDictFind(server, Tcl_GetString(objv[2]), -1, objc > 3 ? atoi(Tcl_GetString(objv[3])) : -1, 0);
        if (dict) {
            char buffer[256];
            sprintf(buffer, "%s %d %d", dict->name, dict->vendor, dict->type);
            Tcl_AppendResult(interp, buffer, 0);
        }
        break;

     case cmdDictDel:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "del name|attr ?vendor?");
            return TCL_ERROR;
        }
        dict = RadiusDictFind(server, Tcl_GetString(objv[2]), -1, objc > 3 ? atoi(Tcl_GetString(objv[3])) : 0, 1);
        while (dict->values) {
            value = dict->values->next;
            ns_free(dict->values);
            dict->values = value;
        }
        ns_free(dict);
        break;

     case cmdClientGet:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "host");
            return TCL_ERROR;
        }
        if (Ns_GetSockAddr(&sa, (char*)Tcl_GetString(objv[2]), 0) == NS_OK && (client = RadiusClientFind(server, sa.sin_addr, 0))) {
            Tcl_AppendResult(interp, client->secret, 0);
        }
        break;

     case cmdClientAdd:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "host secret");
            return TCL_ERROR;
        }
        RadiusClientAdd(server, (char*)Tcl_GetString(objv[2]), (char*)Tcl_GetString(objv[3]));
        break;

     case cmdClientDel:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "host");
            return TCL_ERROR;
        }
        if (Ns_GetSockAddr(&sa, Tcl_GetString(objv[2]), 0) == NS_OK) {
            client = RadiusClientFind(server, sa.sin_addr, 1);
        }
        ns_free(client);
        break;

     case cmdClientList:
        Ns_DStringInit(&ds);
        RadiusClientPrintf(server, &ds);
        Tcl_AppendResult(interp, ds.string, 0);
        Ns_DStringFree(&ds);
        break;

     case cmdUserList:
        Ns_DStringInit(&ds);
        RadiusUserList(server, objc > 2 ? Tcl_GetString(objv[2]) : 0, &ds);
        Tcl_AppendResult(interp, ds.string, 0);
        Ns_DStringFree(&ds);
        break;

     case cmdUserFind:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "name");
            return TCL_ERROR;
        }
        Ns_DStringInit(&ds);
        if (RadiusUserFind(server, Tcl_GetString(objv[2]), &ds)) {
            Tcl_AppendResult(interp, ds.string, 0);
        }
        Ns_DStringFree(&ds);
        break;

     case cmdUserAttrFind:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "name attr ?inreply?");
            return TCL_ERROR;
        }
        Ns_DStringInit(&ds);
        if (RadiusUserAttrFind(server, Tcl_GetString(objv[2]), &ds, Tcl_GetString(objv[3]), objc > 4)) {
            Tcl_AppendResult(interp, ds.string, 0);
        }
        Ns_DStringFree(&ds);
        break;

     case cmdUserAdd:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "name checkattrs ?replyattrs?");
            return TCL_ERROR;
        }
        if ((user = RadiusUserAdd(server, Tcl_GetString(objv[2])))) {
            RadiusAttr *attr;
            Tcl_Obj *key, *val;
            Tcl_ListObjLength(0, objv[3], &len);
            for (int i = 0; i < len; i+= 2) {
                if (Tcl_ListObjIndex(0, objv[3], i, &key) == TCL_OK &&
                    Tcl_ListObjIndex(0, objv[3], i+1, &val) == TCL_OK && key && val) {
                    if ((attr = RadiusAttrCreate(server, Tcl_GetString(key), -1, -1, Tcl_GetString(val), -1))) {
                        RadiusAttrLink(&user->config, attr);
                    }
                }
            }
            if (objc > 4) {
                Tcl_ListObjLength(0, objv[4], &len);
                for (int i = 0; i < len; i+= 2) {
                    if (Tcl_ListObjIndex(0, objv[4], i, &key) == TCL_OK &&
                        Tcl_ListObjIndex(0, objv[4], i+1, &val) == TCL_OK && key && val) {
                        if ((attr = RadiusAttrCreate(server, Tcl_GetString(key), -1, -1, Tcl_GetString(val), -1))) {
                            RadiusAttrLink(&user->reply, attr);
                        }
                    }
                }
            }
        }
        break;

     case cmdUserDel:
        RadiusUserDel(server, objc > 2 ? Tcl_GetString(objv[2]) : 0);
        break;

     case cmdReqGet:
        req = (RadiusRequest*)Ns_TlsGet(&radiusTls);
        if (!req) {
            break;
        }
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "name ?vendor?");
            return TCL_ERROR;
        }
        vendor = -1;
        if (objc > 3) {
            vendor = atoi(Tcl_GetString(objv[3]));
        }
        Ns_DStringInit(&ds);
        if (!strcmp(Tcl_GetString(objv[2]), "code")) {
            Ns_DStringPrintf(&ds, "%d", req->req_code);
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "id")) {
            Ns_DStringPrintf(&ds, "%d", req->req_id);
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "ipaddr")) {
            Ns_DStringAppend(&ds, ns_inet_ntoa(req->addr.sin_addr));
        } else
        if ((attr = RadiusAttrFind(req->req, Tcl_GetString(objv[2]), -1, vendor))) {
            RadiusAttrPrintf(attr, &ds, 0, 0);
        }
        Tcl_AppendResult(interp, ds.string, 0);
        Ns_DStringFree(&ds);
        break;

     case cmdReqSet:
        req = (RadiusRequest*)Ns_TlsGet(&radiusTls);
        if (!req) {
            break;
        }
        for (int i = 2; i < objc - 1; i += 2) {
            if (!strcasecmp(Tcl_GetString(objv[i]), "code")) {
                req->reply_code = atoi(Tcl_GetString(objv[i+1]));
            } else
            if ((attr = RadiusAttrCreate(server, Tcl_GetString(objv[i]), -1, -1, Tcl_GetString(objv[i+1]), -1))) {
                RadiusAttrLink(&req->reply, attr);
            }
        }
        break;

     case cmdReqList:
        req = (RadiusRequest*)Ns_TlsGet(&radiusTls);
        if (!req) {
            break;
        }
        Ns_DStringInit(&ds);
        Ns_DStringPrintf(&ds, "code %d id %d ipaddr %s ", req->req_code, req->req_id, ns_inet_ntoa(req->addr.sin_addr));
        RadiusAttrPrintf(req->req, &ds, 1, 1);
        Tcl_AppendResult(interp, ds.string, 0);
        Ns_DStringFree(&ds);
        break;

     case cmdReset:
        server->radius.errors = 0;
        break;
    }
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * RadiusProc --
 *
 *	Socket callback to receive RADIUS requests
 *
 * Results:
 *	NS_TRUE
 *
 * Side effects:
 *  	New RadiusThread will be created.
 *
 *----------------------------------------------------------------------
 */

static int RadiusProc(SOCKET sock, void *arg, int when)
{
    int len, alen;
    RadiusAttr *attrs;
    RadiusRequest *req;
    RadiusClient *client;
    struct sockaddr_in addr;
    char buf[RADIUS_BUFFER_LEN];
    Server *server = (Server*)arg;
    RadiusHeader *hdr = (RadiusHeader*)buf;

    switch(when) {
     case NS_SOCK_READ:
         alen = sizeof(struct sockaddr_in);
         if ((len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&addr, (socklen_t*)&alen)) <= 0) {
             if (server->radius.errors >= 0 && server->radius.errors++ < 10) {
                 Ns_Log(Error, "RadiusProc: radius: recvfrom error: %s", strerror(errno));
             }
             return NS_TRUE;
         }
         if (!(client = RadiusClientFind(server, addr.sin_addr, 0))) {
             if (server->radius.errors >= 0 && server->radius.errors++ < 100) {
                 Ns_Log(Error, "RadiusRequestCreate: unknown request from %s", ns_inet_ntoa(addr.sin_addr));
             }
             return NS_TRUE;
         }
         if (len < ntohs(hdr->length)) {
             if (server->radius.errors >= 0 && server->radius.errors++ < 100) {
                 Ns_Log(Error, "RadiusRequestCreate: bad packet length from %s", ns_inet_ntoa(addr.sin_addr));
             }
             return NS_TRUE;
         }
         if (!(attrs = RadiusAttrParse(server, hdr, len, client->secret))) {
             if (server->radius.errors >= 0 && server->radius.errors++ < 100) {
                 Ns_Log(Error, "RadiusRequestCreate: invalid request from %s", ns_inet_ntoa(addr.sin_addr));
             }
             return NS_TRUE;
         }
         // Allocate request structure
         req = (RadiusRequest*)ns_calloc(1, sizeof(RadiusRequest));
         req->sock = sock;
         req->req = attrs;
         req->client = client;
         req->server = server;
         req->req_id = hdr->id;
         req->req_code = hdr->code;
         req->reply_code = RADIUS_ACCESS_REJECT;
         memcpy(&req->addr, &addr, sizeof(addr));
         memcpy(req->vector, hdr->vector, RADIUS_VECTOR_LEN);
         RadiusThread(req);
         RadiusHeaderPack(hdr, req->req_id, req->reply_code, req->vector, req->reply, req->client->secret);
         sendto(req->sock, buf, ntohs(hdr->length), 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
         RadiusAttrFree(&req->req);
         RadiusAttrFree(&req->reply);
         ns_free(req);
         return NS_TRUE;
    }
    close(sock);
    return NS_FALSE;
}

/*
 *----------------------------------------------------------------------
 *
 * RadiusThread --
 *
 *	Tcl handler for a radius requests
 *
 * Results:
 *	None.
 *
 * Side effects:
 *      None
 *----------------------------------------------------------------------
 */

static void RadiusThread(void *arg)
{
    RadiusRequest *req = (RadiusRequest *)arg;
    Tcl_Interp *interp = Ns_TclAllocateInterp(req->server->name);

    Ns_TlsSet(&radiusTls, req);
    if (Tcl_Eval(interp, req->server->radius.proc) != TCL_OK) {
        Ns_TclLogError(interp);
    }
    Ns_TclDeAllocateInterp(interp);
    Ns_TlsSet(&radiusTls, 0);
}

/*
 *----------------------------------------------------------------------
 *
 * RadiusInit --
 *
 *	Initializes RADIUS subsystem,  default dictionary
 *
 * Results:
 *	None
 *
 * Side effects:
 *  	None
 *
 *----------------------------------------------------------------------
 */


static void RadiusInit(Server *server)
{
   RadiusDictAdd(server, "User-Name", 1, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "User-Password", 2, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "CHAP-Password", 3, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "NAS-IP-Address", 4, 0, RADIUS_TYPE_IPADDR);
   RadiusDictAdd(server, "NAS-Port", 5, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Service-Type", 6, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Framed-Protocol", 7, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Framed-IP-Address", 8, 0, RADIUS_TYPE_IPADDR);
   RadiusDictAdd(server, "Framed-IP-Netmask", 9, 0, RADIUS_TYPE_IPADDR);
   RadiusDictAdd(server, "Framed-Routing", 10, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Filter-Id", 11, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Framed-MTU", 12, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Framed-Compression", 13, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Login-IP-Host",  14, 0, RADIUS_TYPE_IPADDR);
   RadiusDictAdd(server, "Login-Service",  15, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Login-Port", 16, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Old-Password", 17, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Reply-Message", 18, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Login-Callback-Number", 19, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Framed-Callback-Id", 20, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Framed-Route", 22, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Framed-IPX-Network", 23, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "State", 24, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Class", 25, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Vendor-Specific", 26, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Session-Timeout", 27, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Idle-Timeout", 28, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Termination-Action", 29, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Called-Station-Id", 30, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Calling-Station-Id", 31, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "NAS-Identifier", 32, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Proxy-State", 33, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Login-LAT-Service", 34, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Login-LAT-Node", 35, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Login-LAT-Group", 36, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Framed-AppleTalk-Link", 37, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Framed-AppleTalk-Network", 38, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Framed-AppleTalk-Zone", 39, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "CHAP-Challenge", 60, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "NAS-Port-Type", 61, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Port-Limit", 62, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Status-Type", 40, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Delay-Time", 41, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Input-Octets", 42, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Output-Octets", 43, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Session-Id", 44, 0, RADIUS_TYPE_STRING);
   RadiusDictAdd(server, "Acct-Authentic", 45, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Session-Time", 46, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Input-Packets", 47, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Output-Packets", 48, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "Acct-Terminate-Cause", 49, 0, RADIUS_TYPE_INTEGER);
   RadiusDictAdd(server, "User-Id", 99, 0, RADIUS_TYPE_STRING);
}

/*
 *----------------------------------------------------------------------
 *
 * SyslogProc --
 *
 *	Socket callback to receive syslog events
 *
 * Results:
 *	NS_TRUE
 *
 * Side effects:
 *  	None
 *
 *----------------------------------------------------------------------
 */

static int SyslogProc(SOCKET sock, void *arg, int why)
{
    struct sockaddr_in sa;
    Server *server = (Server*)arg;
    int rc, len, priority = -1, iFacility = 0, iSeverity = 0;
    char buf[1024], *ptr, *sFacility = 0, *sSeverity = 0;
    socklen_t salen = sizeof(struct sockaddr_in);

    if (why != NS_SOCK_READ) {
        close(sock);
        return NS_FALSE;
    }

    if (sock == server->syslog.udp_sock) {
        if ((len = recvfrom(sock, buf, sizeof(buf) - 1, 0, (struct sockaddr*)&sa, &salen)) <= 0) {
            if (server->syslog.errors >= 0 && server->syslog.errors++ < 10) {
                Ns_Log(Error, "SyslogProc: %d: recvfrom error: %s", sock, strerror(errno));
            }
            return NS_TRUE;
        }
    } else {
       if ((len = recv(sock, buf, sizeof(buf) - 1, 0)) <= 0) {
           if (server->syslog.errors >= 0 && server->syslog.errors++ < 10) {
               Ns_Log(Error, "SyslogProc: %d: recv error: %s", sock, strerror(errno));
           }
           return NS_TRUE;
       }
       sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    }
    buf[len] = 0;
    ptr = buf;
    /* Parse priority */
    if (*ptr == '<') {
        priority = atoi(++ptr);
        while (isdigit(*ptr)) {
            ptr++;
        }
        if (*ptr != '>') {
            return NS_TRUE;
        }
        ptr++;
    }
    iFacility = priority / 8;
    iSeverity = priority - iFacility * 8;
    /* Parse timestamp: Mon dd hh:mm:ss */
    while (*ptr && !isspace(*ptr++)) ;
    while (*ptr && !isspace(*ptr++)) ;
    while (*ptr && !isspace(*ptr++)) ;
    /* Bad line, ignore it */
    if (!*ptr) {
        return NS_TRUE;
    }
    /* Format the message*/
    switch (iFacility) {
     case 0:
        sFacility = "kern";
        break;
     case 1:
        sFacility = "user";
        break;
     case 2:
        sFacility = "mail";
        break;
     case 3:
        sFacility = "daemon";
        break;
     case 4:
        sFacility = "auth";
        break;
     case 5:
        sFacility = "intern";
        break;
     case 6:
        sFacility = "print";
        break;
     case 7:
        sFacility = "news";
        break;
     case 8:
        sFacility = "uucp";
        break;
     case 9:
        sFacility = "clock";
        break;
     case 10:
        sFacility = "security";
        break;
     case 11:
        sFacility = "ftp";
        break;
     case 12:
        sFacility = "ntp";
        break;
     case 13:
        sFacility = "audit";
        break;
     case 14:
        sFacility = "alert";
        break;
     case 15:
        sFacility = "clock";
        break;
     case 16:
        sFacility = "local0";
        break;
     case 17:
        sFacility = "local1";
        break;
     case 18:
        sFacility = "local2";
        break;
     case 19:
        sFacility = "local3";
        break;
     case 20:
        sFacility = "local4";
        break;
     case 21:
        sFacility = "local5";
        break;
     case 22:
        sFacility = "local6";
        break;
     case 23:
        sFacility = "local7";
        break;
     default:
        sFacility = "none";
    }
    switch (iSeverity) {
     case 0:
        sSeverity = "emergency";
        break;
     case 1:
        sSeverity = "alert";
        break;
     case 2:
        sSeverity = "critical";
        break;
     case 3:
        sSeverity = "error";
        break;
     case 4:
        sSeverity = "warning";
        break;
     case 5:
        sSeverity = "notice";
        break;
     case 6:
        sSeverity = "info";
        break;
     case 7:
        sSeverity = "debug";
        break;
     default:
        sSeverity = "none";
    }
    if (server->syslog.proc) {
        Tcl_Interp *interp = Ns_TclAllocateInterp(server->name);
        Ns_DStringPrintf(&server->syslog.buffer, "%s %s %s %s {%s}", server->syslog.proc, ns_inet_ntoa(sa.sin_addr), sSeverity, sFacility, ptr);
        rc = Tcl_Eval(interp, server->syslog.buffer.string);
        Ns_TclDeAllocateInterp(interp);
        if (rc != TCL_OK) {
            return NS_TRUE;
        }
    }
    Ns_Log(Notice, "%s/%s: %s", sSeverity, sFacility, ptr);
    return NS_TRUE;
}

