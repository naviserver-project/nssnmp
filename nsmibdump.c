/*
 * nsmibdump.c --
 *
 * Copyright (c) 2004 Vlad Seryakov vlad@crystalballinc.com
 *
 * Based on smidump from libsmi
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#define INT64_FORMAT "%lld"
#define UINT64_FORMAT "%llu"

#include "smi.h"

static char *smiStringNodekind(SmiNodekind nodekind)
{
    return
        (nodekind == SMI_NODEKIND_UNKNOWN)      ? "UNKNOWN" :
        (nodekind == SMI_NODEKIND_NODE)         ? "VALUE-ASSIGNEMENT" :
        (nodekind == SMI_NODEKIND_SCALAR)       ? "SCALAR" :
        (nodekind == SMI_NODEKIND_TABLE)        ? "SEQUENCE OF" :
        (nodekind == SMI_NODEKIND_ROW)          ? "SEQUENCE" :
        (nodekind == SMI_NODEKIND_COLUMN)       ? "COLUMN" :
        (nodekind == SMI_NODEKIND_NOTIFICATION) ? "NOTIFICATION-TYPE" :
        (nodekind == SMI_NODEKIND_GROUP)        ? "OBJECT-GROUP" :
        (nodekind == SMI_NODEKIND_COMPLIANCE)   ? "MODULE-COMPLIANCE" :
        (nodekind == SMI_NODEKIND_CAPABILITIES) ? "CAPS" : "UNDEFINED";
}

static char *getStringBasetype(SmiBasetype basetype)
{
    return
        (basetype == SMI_BASETYPE_UNKNOWN)           ? "UNKNOWN" :
        (basetype == SMI_BASETYPE_OCTETSTRING)       ? "OCTET STRING" :
        (basetype == SMI_BASETYPE_OBJECTIDENTIFIER)  ? "OBJECT IDENTIFIER" :
        (basetype == SMI_BASETYPE_UNSIGNED32)        ? "Unsigned32" :
        (basetype == SMI_BASETYPE_INTEGER32)         ? "Integer32" :
        (basetype == SMI_BASETYPE_UNSIGNED64)        ? "Unsigned64" :
        (basetype == SMI_BASETYPE_INTEGER64)         ? "Integer64" :
        (basetype == SMI_BASETYPE_FLOAT32)           ? "Float32" :
        (basetype == SMI_BASETYPE_FLOAT64)           ? "Float64" :
        (basetype == SMI_BASETYPE_FLOAT128)          ? "Float128" :
        (basetype == SMI_BASETYPE_ENUM)              ? "Integer32" :
        (basetype == SMI_BASETYPE_BITS)              ? "Bits" : "UNDEFINED";
}

static char *getValueString(SmiValue *valuePtr, SmiType *typePtr)
{
    int n;
    char ss[9];
    unsigned int i;
    static char s[100];
    SmiNamedNumber *nn;

    s[0] = 0;
    switch (valuePtr->basetype) {
    case SMI_BASETYPE_UNSIGNED32:
        sprintf(s, "%lu", valuePtr->value.unsigned32);
        break;
    case SMI_BASETYPE_INTEGER32:
        sprintf(s, "%ld", valuePtr->value.integer32);
        break;
    case SMI_BASETYPE_UNSIGNED64:
        sprintf(s, UINT64_FORMAT, valuePtr->value.unsigned64);
        break;
    case SMI_BASETYPE_INTEGER64:
        sprintf(s, INT64_FORMAT, valuePtr->value.integer64);
        break;
    case SMI_BASETYPE_FLOAT32:
    case SMI_BASETYPE_FLOAT64:
    case SMI_BASETYPE_FLOAT128:
        break;
    case SMI_BASETYPE_ENUM:
        for(nn = smiGetFirstNamedNumber(typePtr); nn;nn = smiGetNextNamedNumber(nn))
           if(nn->value.value.unsigned32 == valuePtr->value.unsigned32) break;
        if(nn) sprintf(s, "%s", nn->name); else sprintf(s, "%ld", valuePtr->value.integer32);
        break;
    case SMI_BASETYPE_OCTETSTRING:
        for(i = 0; i < valuePtr->len; i++) if (!isprint((int)valuePtr->value.ptr[i])) break;
        if(i == valuePtr->len) {
          sprintf(s, "%s", valuePtr->value.ptr);
        } else {
          sprintf(s, "0x%*s", 2 * valuePtr->len, "");
          for(i=0; i < valuePtr->len; i++) {
            sprintf(ss, "%02x", valuePtr->value.ptr[i]);
            strncpy(&s[2+2*i], ss, 2);
          }
        }
        break;
    case SMI_BASETYPE_BITS:
        sprintf(s, "(");
        for(i = 0, n = 0; i < valuePtr->len * 8; i++) {
          if(valuePtr->value.ptr[i/8] & (1 << (7-(i%8)))) {
            if(n) sprintf(&s[strlen(s)], ", ");
            n++;
            for(nn = smiGetFirstNamedNumber(typePtr); nn;nn = smiGetNextNamedNumber(nn))
              if(nn->value.value.unsigned32 == i) break;
            if(nn) sprintf(&s[strlen(s)], "%s", nn->name); else sprintf(s, "%d", i);
          }
        }
        sprintf(&s[strlen(s)], ")");
        break;
    case SMI_BASETYPE_UNKNOWN:
        break;
    case SMI_BASETYPE_OBJECTIDENTIFIER:
        for(i = 0; i < valuePtr->len; i++)
          sprintf(&s[strlen(s)], i ? ".%u" : "%u", valuePtr->value.oid[i]);
        break;
    }
    return s;
}

static void fprintNodeNsmib(FILE *f,SmiModule *mod)
{
    int i;
    unsigned int j;
    SmiNode *smiNode;
    SmiType *smiType;
    SmiNamedNumber *nn;

    if(!mod) return;
    for(smiNode = smiGetFirstNode(mod,SMI_NODEKIND_ANY);smiNode;smiNode = smiGetNextNode(smiNode,SMI_NODEKIND_ANY)) {
      if(!smiNode->name) continue;
      smiType = smiGetNodeType(smiNode);
      fprintf(f,"ns_mib set ");
      for(j = 0;j < smiNode->oidlen;j++) fprintf(f,j ? ".%u" : "%u",smiNode->oid[j]);
      fprintf(f," %s %s {%s}",mod->name,smiNode->name,smiType ? getStringBasetype(smiType->basetype) : smiStringNodekind(smiNode->nodekind));
      if(smiType) {
        switch(smiType->basetype) {
         case SMI_BASETYPE_ENUM:
            for(nn = smiGetFirstNamedNumber(smiType);nn;nn = smiGetNextNamedNumber(nn))
              fprintf(f," %s(%s)", nn->name,getValueString(&nn->value,smiType));
            break;
         case SMI_BASETYPE_OCTETSTRING:
            if(smiType->format) fprintf(f," %s", smiType->format);
            break;
        }
      }
      fprintf(f,"\n");
    }
}

int main(int argc, char *argv[])
{
    int i;
    char *name;

    if(argc <= 1) {
      fprintf(stderr,"Usage: nsmibdump [module or path ...]\n");
      return 0;
    }
    smiInit(NULL);
   
    for(i = 1; i < argc; i++) {
      name = smiLoadModule(argv[i]);
      fprintNodeNsmib(stdout,name ? smiGetModule(name) : NULL);
    }
    smiExit();
    return 0;
}
