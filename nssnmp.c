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
    struct _icmpPort *next, *prev;
    int fd;
    int flag;
} IcmpPort;

class SnmpSession {
  public:
    SnmpSession(char *host, int port):snmp(0), addr(0), next(0), prev(0) {
        addr = new UdpAddress(host);
        addr->set_port(port);
        if (!addr->valid()) {
            free();
            return;
        }
        int status;
        snmp = new Snmp(status);
        if (status != SNMP_CLASS_SUCCESS) {
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
        if (snmp)
            delete snmp;
        if (addr)
            delete addr;
        snmp = 0;
        addr = 0;
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

class SnmpString:public OctetStr {
  public:
    char *get_printable();
    char *get_printable_hex();
     SnmpString & operator=(unsigned long val);
};

class SnmpVb:public Vb {
  public:
    char *get_printable_value();
    int get_exception_status() {
        return exception_status;
    } int SetValue(char *type, char *value);
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
} Server;

class TrapContext {
  public:
    SOCKET sock;
    struct sockaddr_in sa;
    Pdu pdu;
    SnmpTarget *target;
    Server *server;
     TrapContext(Server * srv):target(0), server(srv) {
    } ~TrapContext() {
        if (target)
            delete target;
    }
};

static Ns_SockProc TrapProc;
static Ns_ThreadProc TrapThread;

extern int receive_snmp_notification(int sock, Snmp & snmp_session, Pdu & pdu, SnmpTarget ** target);
static int SnmpCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[]);
static int TrapCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[]);
static int MibCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[]);
static int PingCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[]);
static int IcmpCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[]);
static void TrapDump(Server * server, Pdu & pdu, SnmpTarget & target);
static const char *SnmpError(SnmpSession * session, int status);
static int SnmpInterpInit(Tcl_Interp * interp, void *context);
static void FormatIntTC(Tcl_Interp * interp, char *bytes, char *fmt);
static void FormatStringTC(Tcl_Interp * interp, char *bytes, char *fmt);
static SnmpSession *SessionFind(Server * server, unsigned long id);
static void SessionLink(Server * server, SnmpSession * session);
static void SessionUnlink(Server * server, SnmpSession * session, int lock);
static void SessionGC(void *ctx);
static char *PduTypeStr(int type);
static char *SyntaxStr(int type);
static int SyntaxValid(int type);

extern "C" {

    static Ns_Tls trapTls;

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

    NS_EXPORT int Ns_ModuleInit(char *server, char *module) {
        char *path;
        SOCKET sock;
        Server *srvPtr;
        int status;
        static int initialized = 0;

        if (!initialized) {
            initialized = 1;
            Ns_TlsAlloc(&trapTls, 0);
        }

        Ns_Log(Notice, "nssnmp module version %s server: %s", SNMP_VERSION, server);

        path = Ns_ConfigGetPath(server, module, NULL);
        srvPtr = (Server *) ns_calloc(1, sizeof(Server));
        srvPtr->name = server;
        Tcl_InitHashTable(&srvPtr->mib, TCL_STRING_KEYS);
        if (!Ns_ConfigGetInt(path, "debug", &srvPtr->debug)) {
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

        srvPtr->trap.proc = Ns_ConfigGetValue(path, "trap_proc");
        if (!Ns_ConfigGetInt(path, "trap_port", &srvPtr->trap.port)) {
            srvPtr->trap.port = 162;
        }
        if (!(srvPtr->trap.address = Ns_ConfigGetValue(path, "trap_address"))) {
            srvPtr->trap.address = "0.0.0.0";
        }
        // Initialize ICMP system
        if (Ns_ConfigGetInt(path, "icmp_ports", &srvPtr->icmp.count) > 0) {
            IcmpPort *icmp;
            for (int i = 0; i < srvPtr->icmp.count; i++) {
                if ((sock = Ns_SockListenRaw(IPPROTO_ICMP)) == -1) {
                    Ns_Log(Error, "nssnmp: couldn't create icmp socket: %s", strerror(errno));
                    return NS_ERROR;
                }
                icmp = (IcmpPort *) ns_calloc(1, sizeof(IcmpPort));
                icmp->fd = sock;
                icmp->next = srvPtr->icmp.ports;
                if (icmp->next)
                    icmp->next->prev = icmp;
                srvPtr->icmp.ports = icmp;
            }
            Ns_Log(Notice, "nssnmp: allocated %d ICMP ports", srvPtr->icmp.count);
        }

        /* Configure SNMP trap listener */
        if (srvPtr->trap.proc) {
            srvPtr->trap.snmp = new Snmp(status);
            if (status != SNMP_CLASS_SUCCESS) {
                Ns_Log(Error, "nssnmp: snmp initialization failed: %s", srvPtr->trap.snmp->error_msg(status));
                return NS_ERROR;
            }
            if ((sock = Ns_SockListenUdp(srvPtr->trap.address, srvPtr->trap.port)) == -1) {
                Ns_Log(Error, "nssnmp: couldn't create socket: %s:%d: %s", srvPtr->trap.address, srvPtr->trap.port,
                       strerror(errno));
            } else {
                Ns_SockCallback(sock, TrapProc, srvPtr, NS_SOCK_READ | NS_SOCK_EXIT | NS_SOCK_EXCEPTION);
                Ns_Log(Notice, "nssnmp: listening on %s:%d by %s",
                       srvPtr->trap.address ? srvPtr->trap.address : "0.0.0.0", srvPtr->trap.port, srvPtr->trap.proc);
            }
        }

        /* Schedule garbage collection proc for automatic session close/cleanup */
        if (srvPtr->gc_interval > 0) {
            Ns_ScheduleProc(SessionGC, srvPtr, 1, srvPtr->gc_interval);
            Ns_Log(Notice, "ns_snmp: scheduling GC proc for every %d secs", srvPtr->gc_interval);
        }
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
static int SnmpInterpInit(Tcl_Interp * interp, void *arg)
{
    Tcl_CreateObjCommand(interp, "ns_snmp", SnmpCmd, arg, NULL);
    Tcl_CreateObjCommand(interp, "ns_mib", MibCmd, arg, NULL);
    Tcl_CreateObjCommand(interp, "ns_ping", PingCmd, arg, NULL);
    Tcl_CreateObjCommand(interp, "ns_icmp", IcmpCmd, arg, NULL);
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

static int TrapProc(SOCKET sock, void *arg, int why)
{
    if (why != NS_SOCK_READ) {
        close(sock);
        return NS_FALSE;
    }
    Server *server = (Server *) arg;
    TrapContext *ctx = new TrapContext(server);
    if (!receive_snmp_notification(sock, *server->trap.snmp, ctx->pdu, &ctx->target)) {
        if (server->debug) {
            TrapDump(server, ctx->pdu, *ctx->target);
        }
        /* SNMP inform trap requires response */
        if (ctx->pdu.get_type() == sNMP_PDU_INFORM) {
            Pdu pdu = ctx->pdu;
            server->trap.snmp->response(pdu, *ctx->target);
        }
        /* Call trap handler if configured */
        if (server->trap.proc) {
            Ns_ThreadCreate(TrapThread, (void *) ctx, 0, NULL);
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
    TrapContext *ctx = (TrapContext *) arg;
    Tcl_Interp *interp = Ns_TclAllocateInterp(((Server *) (ctx->server))->name);

    Ns_TlsSet(&trapTls, ctx);
    if (Tcl_Eval(interp, ((Server *) (ctx->server))->trap.proc) != TCL_OK) {
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

static int TrapCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
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
    if (Tcl_GetIndexFromObj(interp, objv[1], sCmd, "command", TCL_EXACT, (int *) &cmd) != TCL_OK) {
        return TCL_ERROR;
    }
    Oid id;
    TimeTicks tm;
    TrapContext *ctx = (TrapContext *) Ns_TlsGet(&trapTls);
    switch (cmd) {
    case cmdOid:
        ctx->pdu.get_notify_id(id);
        Tcl_AppendResult(interp, id.get_printable(), 0);
        break;

    case cmdType:
        Tcl_AppendResult(interp, PduTypeStr(ctx->pdu.get_type()), 0);
        break;

    case cmdUptime:
        ctx->pdu.get_notify_timestamp(tm);
        Tcl_AppendResult(interp, tm.get_printable(), 0);
        break;

    case cmdEnterprise:
        ctx->pdu.get_notify_enterprise(id);
        Tcl_AppendResult(interp, id.get_printable(), 0);
        break;

    case cmdAddress:{
            GenAddress addr;
            ctx->target->get_address(addr);
            char *s, *saddr = (char *) addr.get_printable();
            if ((s = strchr(saddr, '/')))
                *s = 0;
            Tcl_AppendResult(interp, saddr, 0);
            break;
        }

    case cmdVb:{
            Vb vb;
            Tcl_Obj *obj, *list = Tcl_NewListObj(0, 0);
            for (int i = 0; i < ctx->pdu.get_vb_count(); i++) {
                ctx->pdu.get_vb(vb, i);
                obj = Tcl_NewListObj(0, 0);
                Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj((char *) vb.get_printable_oid(), -1));
                Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(SyntaxStr(vb.get_syntax()), -1));
                Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj((char *) vb.get_printable_value(), -1));
                Tcl_ListObjAppendElement(interp, list, obj);
            }
            Tcl_SetObjResult(interp, list);
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

static void TrapDump(Server * server, Pdu & pdu, SnmpTarget & target)
{
    Vb vb;
    Oid id, eid;
    TimeTicks tm;
    Ns_DString ds;
    GenAddress addr;

    target.get_address(addr);
    pdu.get_notify_id(id);
    pdu.get_notify_enterprise(eid);
    pdu.get_notify_timestamp(tm);

    Ns_DStringInit(&ds);

    Ns_DStringPrintf(&ds, "Status %s From %s Uptime %s Enterprise {%s} ID {%s} Type {%s} ",
                     server->trap.snmp->error_msg(pdu.get_error_status()),
                     addr.get_printable(),
                     tm.get_printable(), eid.get_printable(), id.get_printable(), PduTypeStr(pdu.get_type()));
    for (int i = 0; i < pdu.get_vb_count(); i++) {
        pdu.get_vb(vb, i);
        Ns_DStringPrintf(&ds, "%s {%s} {%s} ", vb.get_printable_oid(), SyntaxStr(vb.get_syntax()), vb.get_printable_value());
    }
    Ns_Log(Debug, "nssnmp: %s", Ns_DStringValue(&ds));
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
    switch (type) {
    case GET_REQ_MSG:
        return "GET";
    case GETNEXT_REQ_MSG:
        return "GETNEXT";
    case GET_RSP_MSG:
        return "RESPONSE";
    case SET_REQ_MSG:
        return "SET";
    case GETBULK_REQ_MSG:
        return "GETBULK";
    case INFORM_REQ_MSG:
        return "INFORM";
    case TRP2_REQ_MSG:
        return "TRAP2";
    case TRP_REQ_MSG:
        return "TRAP";
    case REPORT_MSG:
        return "REPORT";
    default:
        return "UNKNOWN";
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
    switch (type) {
    case sNMP_SYNTAX_INT32:
        return "Integer32";
    case sNMP_SYNTAX_TIMETICKS:
        return "TimeTicks";
    case sNMP_SYNTAX_CNTR32:
        return "Counter32";
    case sNMP_SYNTAX_UINT32:
        return "Unsigned32";
    case sNMP_SYNTAX_CNTR64:
        return "Counter64";
    case sNMP_SYNTAX_OCTETS:
        return "OCTET STRING";
    case sNMP_SYNTAX_BITS:
        return "BITS";
    case sNMP_SYNTAX_OPAQUE:
        return "OPAQUE";
    case sNMP_SYNTAX_IPADDR:
        return "IpAddress";
    case sNMP_SYNTAX_OID:
        return "OBJECT IDENTIFIER";
    case sNMP_SYNTAX_NULL:
        return "NULL";
    case sNMP_SYNTAX_NOSUCHINSTANCE:
        return "noSuchName";
    case sNMP_SYNTAX_NOSUCHOBJECT:
        return "noSuchObject";
    case sNMP_SYNTAX_ENDOFMIBVIEW:
        return "endOfMibView";
    case sNMP_SYNTAX_SEQUENCE:
        return "SEQUENCE";
    default:
        return "UNKNOWN";
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

static SnmpSession *SessionFind(Server * server, unsigned long id)
{
    SnmpSession *session;
    Ns_MutexLock(&server->snmpMutex);
    for (session = (SnmpSession *) server->sessions; session; session = (SnmpSession *) session->next) {
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
    Server *server = (Server *) arg;
    SnmpSession *session;
    time_t now = time(0);

    Ns_MutexLock(&server->snmpMutex);
    for (session = (SnmpSession *) server->sessions; session;) {
        if (now - session->access_time > server->idle_timeout) {
            SnmpSession *next = (SnmpSession *) session->next;
            Ns_Log(Notice, "ns_snmp: GC: inactive session %ld: %s", session->id, session->addr->get_printable());
            SessionUnlink(server, session, 0);
            session = next;
            continue;
        }
        session = (SnmpSession *) session->next;
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

static void SessionLink(Server * server, SnmpSession * session)
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

static void SessionUnlink(Server * server, SnmpSession * session, int lock)
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
        server->sessions = (SnmpSession *) session->next;
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

static const char *SnmpError(SnmpSession * session, int status)
{
    switch (status) {
    case SNMP_CLASS_SUCCESS:
        return "";
    case SNMP_CLASS_TIMEOUT:
        return "noResponse";
    default:
        return session->snmp->error_msg(status);
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
    switch (syntax) {
    case sNMP_SYNTAX_ENDOFMIBVIEW:
    case sNMP_SYNTAX_NOSUCHINSTANCE:
    case sNMP_SYNTAX_NOSUCHOBJECT:
        return 0;
    default:
        return 1;
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

static int SnmpCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
    Server *server = (Server *) arg;
    int cmd, status, id;
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
    if (Tcl_GetIndexFromObj(interp, objv[1], sCmd, "command", TCL_EXACT, (int *) &cmd) != TCL_OK) {
        return TCL_ERROR;
    }
    switch (cmd) {
    case cmdGc:
        SessionGC(0);
        return TCL_OK;

    case cmdSessions:{
            // List opened sessions
            Tcl_Obj *list = Tcl_NewListObj(0, 0);
            Ns_MutexLock(&server->snmpMutex);
            for (session = server->sessions; session; session = session->next) {
                Tcl_ListObjAppendElement(interp, list, Tcl_NewIntObj(session->id));
                Tcl_ListObjAppendElement(interp, list, Tcl_NewIntObj(session->access_time));
                Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj((char *) session->addr->get_printable(), -1));
            }
            Ns_MutexUnlock(&server->snmpMutex);
            Tcl_SetObjResult(interp, list);
            return TCL_OK;
        }
    case cmdCreate:{
            int bulk = server->bulk;
            int port = server->port;
            int timeout = server->timeout;
            int retries = server->retries;
            int version = server->version;
            char *community = server->community;
            char *writecommunity = server->writecommunity;

            if (objc < 3) {
                Tcl_WrongNumArgs(interp, 2, objv,
                                 "host ?-port? ?-timeout? ?-retries? ?-version? ?-bulk? ?-community? ?-writecommunity?");
                return TCL_ERROR;
            }

            for (int i = 3; i < objc - 1; i = i + 2) {
                if (!strcmp(Tcl_GetStringFromObj(objv[i], 0), "-port")) {
                    Tcl_GetIntFromObj(interp, objv[i + 1], &port);
                } else if (!strcmp(Tcl_GetStringFromObj(objv[i], 0), "-timeout")) {
                    Tcl_GetIntFromObj(interp, objv[i + 1], &timeout);
                } else if (!strcmp(Tcl_GetStringFromObj(objv[i], 0), "-retries")) {
                    Tcl_GetIntFromObj(interp, objv[i + 1], &retries);
                } else if (!strcmp(Tcl_GetStringFromObj(objv[i], 0), "-version")) {
                    Tcl_GetIntFromObj(interp, objv[i + 1], &version);
                } else if (!strcmp(Tcl_GetStringFromObj(objv[i], 0), "-bulk")) {
                    Tcl_GetIntFromObj(interp, objv[i + 1], &bulk);
                } else if (!strcmp(Tcl_GetStringFromObj(objv[i], 0), "-community")) {
                    community = Tcl_GetString(objv[i + 1]);
                } else if (!strcmp(Tcl_GetStringFromObj(objv[i], 0), "-writecommunity")) {
                    writecommunity = Tcl_GetString(objv[i + 1]);
                }
            }
            session = new SnmpSession(Tcl_GetStringFromObj(objv[2], 0), port);
            if (!session->snmp) {
                delete session;
                Tcl_AppendResult(interp, "noHost: wrong host or port: ", Tcl_GetStringFromObj(objv[2], 0), 0);
                return TCL_ERROR;
            }
            session->bulk = bulk;
            session->target.set_version(version == 1 ? version1 : version2c);
            session->target.set_retry(retries);
            session->target.set_timeout(timeout * 100);
            session->target.set_readcommunity(community);
            session->target.set_writecommunity(writecommunity ? writecommunity : community);
            SessionLink(server, session);
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
    if (!(session = SessionFind(server, id))) {
        Tcl_AppendResult(interp, "wrong session #s", 0);
        return TCL_ERROR;
    }
    session->access_time = time(0);

    switch (cmd) {
    case cmdGc:
    case cmdSessions:
    case cmdCreate:
        break;
    case cmdConfig:
        if (objc < 4) {
            Tcl_AppendResult(interp, "wrong # args: should be ns_snmp config #s name", 0);
            return TCL_ERROR;
        }
        if (!strcmp(Tcl_GetStringFromObj(objv[3], 0), "-address")) {
            IpAddress ipaddr = *session->addr;
            Tcl_AppendResult(interp, ipaddr.get_printable(), 0);
        } else if (!strcmp(Tcl_GetStringFromObj(objv[3], 0), "-port")) {
            char tmp[32];
            sprintf(tmp, "%d", session->addr->get_port());
            Tcl_AppendResult(interp, tmp, 0);
        } else if (!strcmp(Tcl_GetStringFromObj(objv[3], 0), "-community")) {
            OctetStr community;
            session->target.get_readcommunity(community);
            Tcl_AppendResult(interp, community.get_printable(), 0);
        } else if (!strcmp(Tcl_GetStringFromObj(objv[3], 0), "-writecommunity")) {
            OctetStr community;
            session->target.get_writecommunity(community);
            Tcl_AppendResult(interp, community.get_printable(), 0);
        } else if (!strcmp(Tcl_GetStringFromObj(objv[3], 0), "-timeout")) {
            char tmp[32];
            sprintf(tmp, "%ld", session->target.get_timeout());
            Tcl_AppendResult(interp, tmp, 0);
        } else if (!strcmp(Tcl_GetStringFromObj(objv[3], 0), "-version")) {
            char tmp[32];
            sprintf(tmp, "%d", session->target.get_version() + 1);
            Tcl_AppendResult(interp, tmp, 0);
        } else if (!strcmp(Tcl_GetStringFromObj(objv[3], 0), "-retries")) {
            char tmp[32];
            sprintf(tmp, "%d", session->target.get_retry());
            Tcl_AppendResult(interp, tmp, 0);
        }
        break;

    case cmdGet:{
            if (objc < 4) {
                Tcl_AppendResult(interp, "wrong # args: should be ns_snmp get #s vb ...", 0);
                return TCL_ERROR;
            }
            SnmpVb vb;
            Oid oid;
            session->pdu.set_vblist(&vb, 0);
            for (int i = 3; i < objc; i++) {
                oid = Tcl_GetStringFromObj(objv[i], 0);
                if (!oid.valid()) {
                    Tcl_AppendResult(interp, "invalid OID ", Tcl_GetStringFromObj(objv[i], 0), 0);
                    return TCL_ERROR;
                }
                vb.set_oid(oid);
                session->pdu += vb;
            }
            if ((status = session->snmp->get(session->pdu, session->target)) != SNMP_CLASS_SUCCESS) {
                Tcl_AppendResult(interp, SnmpError(session, status), 0);
                return TCL_ERROR;
            }
            Tcl_Obj *obj, *list = Tcl_NewListObj(0, 0);
            for (int i = 0; i < session->pdu.get_vb_count(); i++) {
                session->pdu.get_vb(vb, i);
                if (!SyntaxValid(vb.get_syntax())) {
                    continue;
                }
                obj = Tcl_NewListObj(0, 0);
                Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj((char *) vb.get_printable_oid(), -1));
                Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(SyntaxStr(vb.get_syntax()), -1));
                Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj((char *) vb.get_printable_value(), -1));
                Tcl_ListObjAppendElement(interp, list, obj);
            }
            Tcl_SetObjResult(interp, list);
            break;
        }
    case cmdWalk:{
            if (objc < 6) {
                Tcl_AppendResult(interp, "wrong # args: should be ns_snmp walk #s OID var script", 0);
                return TCL_ERROR;
            }
            SnmpVb vb;
            Tcl_Obj *obj;
            Oid oid(Tcl_GetStringFromObj(objv[3], 0));
            if (!oid.valid()) {
                Tcl_AppendResult(interp, "invalid OID ", Tcl_GetStringFromObj(objv[3], 0), 0);
                return TCL_ERROR;
            }
            char *oidStr = (char *) oid.get_printable();
            vb.set_oid(oid);
            session->pdu.set_vblist(&vb, 1);
            while ((status = session->snmp->get_bulk(session->pdu, session->target, 0, session->bulk)) == SNMP_CLASS_SUCCESS) {
                for (int i = 0; i < session->pdu.get_vb_count(); i++) {
                    session->pdu.get_vb(vb, i);
                    if (!SyntaxValid(vb.get_syntax()) || strncmp(vb.get_printable_oid(), oidStr, strlen(oidStr))) {
                        goto done;
                    }
                    obj = Tcl_NewListObj(0, 0);
                    Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj((char *) vb.get_printable_oid(), -1));
                    Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(SyntaxStr(vb.get_syntax()), -1));
                    Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(vb.get_printable_value(), -1));
                    if (Tcl_SetVar2Ex(interp, Tcl_GetStringFromObj(objv[4], 0), NULL, obj, TCL_LEAVE_ERR_MSG) == NULL) {
                        return TCL_ERROR;
                    }
                    switch (Tcl_Eval(interp, Tcl_GetStringFromObj(objv[5], 0))) {
                    case TCL_OK:
                    case TCL_CONTINUE:
                        break;
                    case TCL_BREAK:
                        goto done;
                    case TCL_ERROR:{
                            char msg[100];
                            sprintf(msg, "\n\t(\"ns_snmp walk\" body line %d)", interp->errorLine);
                            Tcl_AddErrorInfo(interp, msg);
                            goto done;
                        }
                    }
                }
                session->pdu.set_vblist(&vb, 1);
            }
          done:
            if (status != SNMP_CLASS_SUCCESS && status != SNMP_ERROR_NO_SUCH_NAME && status != SNMP_ERROR_GENERAL_VB_ERR) {
                Tcl_SetObjResult(interp, Tcl_NewStringObj((char *) SnmpError(session, status), -1));
                return TCL_ERROR;
            }
            break;
        }
    case cmdSet:{
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
            session->pdu.set_vblist(&vb, 1);
            if ((status = session->snmp->set(session->pdu, session->target)) != SNMP_CLASS_SUCCESS) {
                Tcl_AppendResult(interp, SnmpError(session, status), 0);
                return TCL_ERROR;
            }
            break;
        }
    case cmdTrap:
    case cmdInform:{
            if (objc < 5) {
                Tcl_AppendResult(interp,
                                 "wrong # args: should be ns_snmp trap #s ID EnterpriseID ?oid type value oid type value ...?",
                                 0);
                return TCL_ERROR;
            }
            Oid tid(Tcl_GetString(objv[3]));
            Oid eid(Tcl_GetString(objv[4]));
            for (int i = 5; i < objc - 2; i += 3) {
                SnmpVb vb;
                Oid oid(Tcl_GetString(objv[i]));
                char *type = Tcl_GetString(objv[i + 1]);
                char *value = Tcl_GetString(objv[i + 2]);
                vb.set_oid(oid);
                if (vb.SetValue(type, value) != TCL_OK) {
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
    for (unsigned long i = 0; i < smival.value.string.len; i++) {
        if ((smival.value.string.ptr[i] != '\r') &&
            (smival.value.string.ptr[i] != '\n') && (isprint((int) (smival.value.string.ptr[i])) == 0)) {
            return (get_printable_hex());
        }
    }
    if (output_buffer) {
        delete[]output_buffer;
    }
    output_buffer = new char[smival.value.string.len + 1];
    if (smival.value.string.len) {
        memcpy(output_buffer, smival.value.string.ptr, (unsigned int) smival.value.string.len);
    }
    output_buffer[smival.value.string.len] = '\0';
    return (output_buffer);
}

char *SnmpString::get_printable_hex()
{
    int local_len = (int) smival.value.string.len;
    unsigned char *bytes = smival.value.string.ptr;
    char *ptr;

    if (output_buffer) {
        delete[]output_buffer;
    }
    ptr = output_buffer = new char[smival.value.string.len * 3 + 1];
    while (local_len > 0) {
        sprintf(ptr, "%2.2X ", *bytes++);
        ptr += 3;
        local_len--;
    }
    return output_buffer;
}

SnmpString & SnmpString::operator=(unsigned long val)
{
    delete[]smival.value.string.ptr;
    smival.value.string.len = 32;
    smival.value.string.ptr = new unsigned char[33];
    sprintf((char *) smival.value.string.ptr, "%lu", val);
    return *this;
}

char *SnmpVb::get_printable_value()
{
    /* Take care about hex printable format for strings */
    switch (get_syntax()) {
    case sNMP_SYNTAX_TIMETICKS:{
            unsigned long val;
            get_value(val);
            str = val;
            value = (char *) str.data();
            break;
        }
    case sNMP_SYNTAX_BITS:
    case sNMP_SYNTAX_OPAQUE:
    case sNMP_SYNTAX_OCTETS:
        get_value(str);
        value = str.get_printable();
        break;
    default:
        value = (char *) Vb::get_printable_value();
    }
    return value;
}

int SnmpVb::SetValue(char *type, char *value)
{
    switch (type[0]) {
    case 'i':
        set_value((long) atol(value));
        break;
    case 'u':
        set_value((unsigned long) atol(value));
        break;
    case 't':{
            TimeTicks tm(atol(value));
            if (tm.valid()) {
                set_value(tm);
            } else {
                return TCL_ERROR;
            }
            break;
        }
    case 'a':{
            IpAddress ipaddr(value);
            if (ipaddr.valid()) {
                set_value(ipaddr);
            } else {
                return TCL_ERROR;
            }
            break;
        }
    case 'o':{
            Oid oid(value);
            if (oid.valid()) {
                set_value(oid);
            } else {
                return TCL_ERROR;
            }
            break;
        }
    case 's':{
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

static int MibCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
    Server *server = (Server *) arg;
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
    if (Tcl_GetIndexFromObj(interp, objv[1], sCmd, "command", TCL_EXACT, (int *) &cmd) != TCL_OK) {
        return TCL_ERROR;
    }
    switch (cmd) {
    case cmdLabels:{
            char *pattern = (objc > 2 ? Tcl_GetString(objv[2]) : 0);
            char *syntax = (objc > 3 ? Tcl_GetString(objv[3]) : 0);
            Tcl_HashSearch search;

            Ns_MutexLock(&server->mibMutex);
            entry = Tcl_FirstHashEntry(&server->mib, &search);
            while (entry) {
                if ((mib = (MibEntry *) Tcl_GetHashValue(entry))) {
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
        entry = Tcl_CreateHashEntry(&server->mib, Tcl_GetString(objv[2]), &flag);
        if (flag) {
            mib = (MibEntry *) ns_calloc(1, sizeof(MibEntry));
            mib->oid = strdup(Tcl_GetString(objv[2]));
            mib->module = strdup(Tcl_GetString(objv[3]));
            mib->label = strdup(Tcl_GetString(objv[4]));
            mib->syntax = strdup(Tcl_GetString(objv[5]));
            /* Enumeration for integer type, hint can be skipped */
            if (!strcmp(Tcl_GetString(objv[5]), "Integer32")) {
                if (objc > 6 && Tcl_GetString(objv[6])[0]) {
                    if (strchr(Tcl_GetString(objv[6]), '(')) {
                        enumidx = 6;
                    } else {
                        mib->hint = strdup(Tcl_GetString(objv[6]));
                    }
                }
                for (int i = enumidx; i < objc; i++) {
                    char *s = strchr(Tcl_GetString(objv[i]), '(');
                    if (!s)
                        break;
                    char *e = strchr(s, ')');
                    if (!e)
                        break;
                    *s++ = 0;
                    *e = 0;
                    mib->Enum.count++;
                    mib->Enum.names = (char **) ns_realloc(mib->Enum.names, sizeof(char **) * mib->Enum.count);
                    mib->Enum.values = (short *) ns_realloc(mib->Enum.values, sizeof(short) * mib->Enum.count);
                    mib->Enum.names[mib->Enum.count - 1] = ns_strdup(Tcl_GetString(objv[i]));
                    mib->Enum.values[mib->Enum.count - 1] = atoi(s);
                }
            } else if (objc > 6 && Tcl_GetString(objv[6])[0]) {
                mib->hint = strdup(Tcl_GetString(objv[6]));
            }
            Tcl_SetHashValue(entry, mib);
            entry = Tcl_CreateHashEntry(&server->mib, Tcl_GetString(objv[4]), &flag);
            Tcl_SetHashValue(entry, mib);
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
        mib = (MibEntry *) Tcl_GetHashValue(entry);
    }
    Ns_MutexUnlock(&server->mibMutex);
    if (!entry) {
        Tcl_AppendResult(interp, Tcl_GetString(objv[2]), 0);
        return TCL_OK;
    }

    switch (cmd) {
    case cmdInfo:{
            Tcl_Obj *obj = Tcl_NewListObj(0, 0);
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(mib->oid, -1));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(mib->module, -1));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(mib->label, -1));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(mib->syntax, -1));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(mib->hint, -1));
            if (mib->Enum.count) {
                Tcl_Obj *Enum = Tcl_NewListObj(0, 0);
                for (int i = 0; i < mib->Enum.count; i++) {
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
                (mib = (MibEntry *) Tcl_GetHashValue(entry))) {
                Tcl_AppendResult(interp, mib->label, 0);
            } else {
                Tcl_AppendResult(interp, Tcl_GetString(objv[3]), 0);
            }
            Ns_MutexUnlock(&server->mibMutex);
            return TCL_OK;
        } else if (!strcmp(mib->syntax, "Integer32")) {
            if (mib->Enum.count) {
                int val = atoi(Tcl_GetString(objv[3]));
                for (int i = 0; i < mib->Enum.count; i++)
                    if (val == mib->Enum.values[i]) {
                        Tcl_AppendResult(interp, mib->Enum.names[i], 0);
                        return TCL_OK;
                    }
            } else if (mib->hint) {
                FormatIntTC(interp, Tcl_GetString(objv[3]), mib->hint);
                return TCL_OK;
            }
        } else if (!strcmp(mib->syntax, "OCTET STRING") && mib->hint) {
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
static int IcmpChksum(u_short * p, int n)
{
    register u_short answer;
    register long sum = 0;
    u_short odd_byte = 0;

    while (n > 1) {
        sum += *p++;
        n -= 2;
    }
    if (n == 1) {
        *(u_char *) (&odd_byte) = *(u_char *) p;
        sum += odd_byte;
    }
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* ones-complement,  truncate */
    return (answer);
}

static int IcmpLock(Server * server)
{
    int fd = -1, count = 3;
    IcmpPort *icmp;

    // Get next available socket
    Ns_MutexLock(&server->icmp.mutex);
    while (--count && fd == -1) {
        for (icmp = server->icmp.ports; icmp; icmp = icmp->next) {
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

static void IcmpUnlock(Server * server, int fd)
{
    IcmpPort *icmp, *tail;

    Ns_MutexLock(&server->icmp.mutex);
    for (icmp = server->icmp.ports; icmp; icmp = icmp->next) {
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
static int IcmpCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
    Server *server = (Server *) arg;
    IcmpPort *icmp;

    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "args");
        return TCL_ERROR;
    }
    if (!strcmp(Tcl_GetString(objv[1]), "sockets")) {
        Tcl_Obj *list = Tcl_NewListObj(0, 0);
        Ns_MutexLock(&server->icmp.mutex);
        for (icmp = server->icmp.ports; icmp; icmp = icmp->next) {
            Tcl_ListObjAppendElement(interp, list, Tcl_NewIntObj(icmp->fd));
            Tcl_ListObjAppendElement(interp, list, Tcl_NewIntObj(icmp->flag));
        }
        Ns_MutexUnlock(&server->icmp.mutex);
        Tcl_SetObjResult(interp, list);
    }
    return TCL_OK;
}

// Check host availability by simulating PING
static int PingCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
    Server *server = (Server *) arg;
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
    for (i = 2; i < objc - 1; i = i + 2) {
        if (!strcmp(Tcl_GetString(objv[i]), "-timeout")) {
            timeout = atoi(Tcl_GetString(objv[i + 1]));
        } else if (!strcmp(Tcl_GetString(objv[i]), "-debug")) {
            debug = atoi(Tcl_GetString(objv[i + 1]));
        } else if (!strcmp(Tcl_GetString(objv[i]), "-count")) {
            count = atoi(Tcl_GetString(objv[i + 1]));
        } else if (!strcmp(Tcl_GetString(objv[i]), "-size")) {
            if ((size = atoi(Tcl_GetString(objv[i + 1]))) < 56 || size > (int) sizeof(buf) - 8) {
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

    for (i = 0; i < count; i++) {
        icp = (struct icmp *) buf;
        icp->icmp_type = ICMP_ECHO;
        icp->icmp_code = 0;
        icp->icmp_cksum = 0;
        icp->icmp_seq = sent;
        icp->icmp_id = id;
        gettimeofday((struct timeval *) &buf[8], 0);
        len = size + 8;
        icp->icmp_cksum = IcmpChksum((u_short *) icp, len);

        if (sendto(fd, buf, len, 0, (struct sockaddr *) &addr, sizeof(addr)) != len) {
            Tcl_AppendResult(interp, "noResponse: ", host, " sendto error: ", strerror(errno), 0);
            Ns_Log(Error, "ns_ping: %d/%d: %s: sendto error: %s", id, fd, host, strerror(errno));
            IcmpUnlock(server, fd);
            return TCL_ERROR;
        }
        sent++;
        retry_count = 0;
      again:
        // Check the total time we spent pinging
        if (time(0) - start_time > timeout)
            break;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        t2.tv_usec = 0;
        t2.tv_sec = timeout;
        switch (select(fd + 1, &fds, 0, 0, &t2)) {
        case 1:
            if ((len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *) &addr2, &slen)) <= 0) {
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
        icp = (struct icmp *) (buf + hlen);
        /* Wrong packet */
        if (icp->icmp_type != ICMP_ECHOREPLY || icp->icmp_id != id) {
            if (debug) {
                Ns_Log(Debug, "ns_ping: %d/%d: %s: invalid type %d or id %d", id, fd, host, icp->icmp_type, icp->icmp_id);
            }
            goto again;
        }
        received++;
        memcpy(&t1, &buf[hlen + 8], sizeof(struct timeval));
        delay = (double) (t2.tv_sec - t1.tv_sec) * 1000.0 + (double) (t2.tv_usec - t1.tv_usec) / 1000.0;
        if (!rtt_min || delay < rtt_min) {
            rtt_min = delay;
        }
        if (!rtt_max || delay > rtt_max) {
            rtt_max = delay;
        }
        rtt_avg = (rtt_avg * (received - 1) / received) + (delay / received);
    }
    IcmpUnlock(server, fd);
    if (!received) {
        Tcl_AppendResult(interp, "noConnectivity: no reply from ", host, 0);
        return TCL_ERROR;
    }
    // Calculate statistics
    loss = received > 0 ? 100 - ((received * 100) / sent) : !sent ? 0 : 100;

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
static void FormatStringTC(Tcl_Interp * interp, char *bytes, char *fmt)
{
    int i = 0, len = strlen(bytes), pfx, have_pfx;
    char *last_fmt;
    Ns_DString ds;

    Ns_DStringInit(&ds);

    while (*fmt && i < len) {
        last_fmt = fmt;         /* save for loops */
        have_pfx = pfx = 0;     /* scan prefix: */
        while (*fmt && isdigit((int) *fmt)) {
            pfx = pfx * 10 + *fmt - '0', have_pfx = 1, fmt++;
        }
        if (!have_pfx) {
            pfx = 1;
        }
        switch (*fmt) {
        case 'a':{
                int n = (pfx < (len - i)) ? pfx : len - i;
                Ns_DStringNAppend(&ds, bytes + i, n);
                i += n;
                break;
            }
        case 'b':
        case 'd':
        case 'o':
        case 'x':{
                long vv;
                for (vv = 0; pfx > 0 && i < len; i++, pfx--)
                    vv = vv * 256 + (bytes[i] & 0xff);
                switch (*fmt) {
                case 'd':
                    Ns_DStringPrintf(&ds, "%ld", vv);
                    break;
                case 'o':
                    Ns_DStringPrintf(&ds, "%lo", vv);
                    break;
                case 'x':
                    Ns_DStringPrintf(&ds, "%.*lX", pfx * 2, vv);
                    break;
                case 'b':{
                        int i, j;
                        char buf[32];
                        for (i = (sizeof(int) * 8 - 1); i >= 0 && !(vv & (1 << i)); i--);
                        for (j = 0; i >= 0; i--, j++) {
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

static void FormatIntTC(Tcl_Interp * interp, char *bytes, char *fmt)
{
    char buffer[32];

    switch (fmt[0]) {
    case 'd':{
            int dot = 0;
            float value = atof(bytes);
            if (fmt[1] == '-' && isdigit((int) fmt[2])) {
                if ((dot = atoi(&fmt[2]))) {
                    value = value / (10 * dot);
                }
            }
            snprintf(buffer, 31, "%.*f", dot, value);
            Tcl_AppendResult(interp, buffer, 0);
            break;
        }
    case 'x':{
            sprintf(buffer, "%lx", atol(bytes));
            Tcl_AppendResult(interp, buffer, 0);
            break;
        }
    case 'o':{
            sprintf(buffer, "%lo", atol(bytes));
            Tcl_AppendResult(interp, buffer, 0);
            break;
        }
    case 'b':{
            long i, j = 0, value = atol(bytes);
            if (value < 0)
                buffer[j++] = '-', value *= -1;
            for (i = (sizeof(long) * 8 - 1); i > 0 && !(value & (1 << i)); i--);
            for (; i >= 0; i--, j++)
                buffer[j] = value & (1 << i) ? '1' : '0';
            buffer[j] = 0;
            Tcl_AppendResult(interp, buffer, 0);
            break;
        }
    }
}
