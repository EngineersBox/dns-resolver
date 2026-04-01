#include "resource_record.h"

#include "domain.h"

__attribute__((always_inline)) inline int parseRRCNAME(char* buf, size_t buf_len, char* base_addr, uint16_t _, struct RR_CNAME* cname) {
    return parseDomainName(buf, buf_len, base_addr, (uint8_t*) cname->name);
}

int parseRRHINFO(char* buf, size_t buf_len, char* base_addr, uint16_t rd_len, struct RR_HINFO* hinfo);

int parseRRMB(char* buf, size_t buf_len, char* base_addr, uint16_t _, struct RR_MB* mb) {
    return parseDomainName(buf, buf_len, base_addr, (uint8_t*) mb->madname);
}

int parseRRMD(char* buf, size_t buf_len, char* base_addr, uint16_t _, struct RR_MD* md) {
    return parseDomainName(buf, buf_len, base_addr, (uint8_t*) md->madname);
}

int parseRRMF(char* buf, size_t buf_len, char* base_addr, uint16_t _, struct RR_MF* mf) {
    return parseDomainName(buf, buf_len, base_addr, (uint8_t*) mf->madname);
}

int parseRRMG(char* buf, size_t buf_len, char* base_addr, uint16_t _, struct RR_MG* mg) {
    return parseDomainName(buf, buf_len, base_addr, (uint8_t*) mg->mgmname);
}

int parseRRMINFO(char* buf, size_t buf_len, char* base_addr, uint16_t rd_len, struct RR_MINFO* minfo);

int parseRRMR(char* buf, size_t buf_len, char* base_addr, uint16_t _, struct RR_MR* mr) {
    return parseDomainName(buf, buf_len, base_addr, (uint8_t*) mr->newname);
}

int parseRRMX(char* buf, size_t buf_len, char* base_addr, uint16_t rd_len, struct RR_MX* mx);

int parseRRNULL(char* buf, size_t buf_len, char* base_addr, uint16_t rd_len, struct RR_NULL* nul);

int parseRRNS(char* buf, size_t buf_len, char* base_addr, uint16_t _, struct RR_NS* ns) {
    return parseDomainName(buf, buf_len, base_addr, (uint8_t*) ns->nsdname);
}

int parseRRPTR(char* buf, size_t buf_len, char* base_addr, uint16_t rd_len, struct RR_PTR* ptr);

int parseRRSOA(char* buf, size_t buf_len, char* base_addr, uint16_t rd_len, struct RR_SOA* soa);

int parseRRTXT(char* buf, size_t buf_len, char* base_addr, uint16_t rd_len, struct RR_TXT* txt);

int parseRRA(char* buf, size_t buf_len, char* base_addr, uint16_t rd_len, struct RR_A* a);

int parseRRWKS(char* buf, size_t buf_len, char* base_addr, uint16_t rd_len, struct RR_WKS* wks);

int parseRRAAAA(char* buf, size_t buf_len, char* base_addr, uint16_t rd_len, struct RR_AAAA* aaaa);
