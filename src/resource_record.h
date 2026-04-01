#pragma once

#ifndef _DNS_RESOLVER_RESOURCE_RECORD_H_
#define _DNS_RESOLVER_RESOURCE_RECORD_H_

#include <arpa/inet.h>
#include <stdint.h>

typedef struct RR_CNAME {
    char name[256];
} RR_CNAME;

int parseRRCNAME(char* buf, size_t buf_len, uint16_t rd_len, struct RR_CNAME* cname);

typedef struct RR_HINFO {
    char cpu[256];
    char os[256];
} RR_HINFO;

int parseRRHINFO(char* buf, size_t buf_len, uint16_t rd_len, struct RR_HINFO* hinfo);

typedef struct RR_MB {
    char madname[256];
} RR_MB;

int parseRRMB(char* buf, size_t buf_len, uint16_t rd_len, struct RR_MB* mb);

typedef struct RR_MD {
    char madname[256];
} RR_MD;

int parseRRMD(char* buf, size_t buf_len, uint16_t rd_len, struct RR_MD* md);

typedef struct RR_MF {
    char madname[256];
} RR_MF;

int parseRRMF(char* buf, size_t buf_len, uint16_t rd_len, struct RR_MF* mf);

typedef struct RR_MG {
    char mgmname[256];
} RR_MG;

int parseRRMG(char* buf, size_t buf_len, uint16_t rd_len, struct RR_MG* mg);

typedef struct RR_MINFO {
    char rmailbx[256];
    char emailbx[256];
} RR_MINFO;

int parseRRMINFO(char* buf, size_t buf_len, uint16_t rd_len, struct RR_MINFO* minfo);

typedef struct RR_MR {
    char newname[256];
} RR_MR;

int parseRRMR(char* buf, size_t buf_len, uint16_t rd_len, struct RR_MR* mr);

typedef struct RR_MX {
    uint16_t preference;
    char exchange[256];
} RR_MX;

int parseRRMX(char* buf, size_t buf_len, uint16_t rd_len, struct RR_MX* mx);

typedef struct RR_NULL {
    uint8_t data[65535];
} RR_NULL;

int parseRRNULL(char* buf, size_t buf_len, uint16_t rd_len, struct RR_NULL* nul);

typedef struct RR_NS {
    char nsdname[256];
} RR_NS;

int parseRRNS(char* buf, size_t buf_len, uint16_t rd_len, struct RR_NS* ns);

typedef struct RR_PTR {
    char ptrdname[256];
} RR_PTR;

int parseRRPTR(char* buf, size_t buf_len, uint16_t rd_len, struct RR_PTR* ptr);

typedef struct RR_SOA {
    char mname[256];
    char rname[256];
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
} RR_SOA;

int parseRRSOA(char* buf, size_t buf_len, uint16_t rd_len, struct RR_SOA* soa);

typedef struct RR_TXT {
    char text[256];
} RR_TXT;

int parseRRTXT(char* buf, size_t buf_len, uint16_t rd_len, struct RR_TXT* txt);

typedef struct RR_A {
    struct in_addr address;
} RR_A;

int parseRRA(char* buf, size_t buf_len, uint16_t rd_len, struct RR_A* a);

typedef struct RR_WKS {
    uint32_t address;
    uint8_t protocol;
    uint8_t bitmap[];
} RR_WKS;

int parseRRWKS(char* buf, size_t buf_len, uint16_t rd_len, struct RR_WKS* wks);

typedef struct RR_AAAA {
    struct in6_addr address;
} RR_AAAA;

int parseRRAAAA(char* buf, size_t buf_len, uint16_t rd_len, struct RR_AAAA* aaaa);

typedef union RR {
    struct RR_CNAME* cname;
    struct RR_HINFO* hinfo;
    struct RR_MB* mb;
    struct RR_MD* md;
    struct RR_MF* mf;
    struct RR_MG* mg;
    struct RR_MINFO* minfo;
    struct RR_MR* mr;
    struct RR_MX* mx;
    struct RR_NULL* nul;
    struct RR_NS* ns;
    struct RR_PTR* ptr;
    struct RR_SOA* soa;
    struct RR_TXT* txt;
    struct RR_A* a;
    struct RR_WKS* wks;
    struct RR_AAAA* aaaa;
    void* raw_ptr;
} RR;

#endif // _DNS_RESOLVER_RESOURCE_RECORD_H_
