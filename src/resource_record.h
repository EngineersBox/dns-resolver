#pragma once

#ifndef _DNS_RESOLVER_RESOURCE_RECORD_H_
#define _DNS_RESOLVER_RESOURCE_RECORD_H_

#include <arpa/inet.h>
#include <stdint.h>

typedef struct RR_CNAME {
    char name[256];
} RR_CNAME;

typedef struct RR_HINFO {
    char cpu[256];
    char os[256];
} RR_HINFO;

typedef struct RR_MB {
    char madname[256];
} RR_MB;

typedef struct RR_MD {
    char madname[256];
} RR_MD;

typedef struct RR_MF {
    char madname[256];
} RR_MF;

typedef struct RR_MG {
    char mgmname[256];
} RR_MG;

typedef struct RR_MINFO {
    char rmailbx[256];
    char emailbx[256];
} RR_MINFO;

typedef struct RR_MR {
    char newname[256];
} RR_MR;

typedef struct RR_MX {
    uint16_t preference;
    char exchange[256];
} RR_MX;

typedef struct RR_NULL {
    uint8_t data[65535];
} RR_NULL;

typedef struct RR_NS {
    char nsdname[256];
} RR_NS;

typedef struct RR_PTR {
    char ptrdname[256];
} RR_PTR;

typedef struct RR_SOA {
    char mname[256];
    char rname[256];
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
} RR_SOA;

typedef struct RR_TXT {
    char text[256];
} RR_TXT;

typedef struct RR_A {
    struct in_addr address;
} RR_A;

typedef struct RR_WKS {
    uint32_t address;
    uint8_t protocol;
    uint8_t bitmap[];
} RR_WKS;

typedef struct RR_AAAA {
    struct in6_addr address;
} RR_AAAA;

#endif // _DNS_RESOLVER_RESOURCE_RECORD_H_
