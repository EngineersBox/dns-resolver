#include "message.h"

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "domain.h"
#include "resource_record.h"

const char* opcode_names[] = {
    [OPCODE_QUERY] = "OPCODE_QUERY",
    [OPCODE_IQUERY] = "OPCODE_IQUERY",
    [OPCODE_STATUS] = "OPCODE_STATUS",
    [OPCODE_RESERVED0] = "OPCODE_RESERVED0",
    [OPCODE_RESERVED1] = "OPCODE_RESERVED1",
    [OPCODE_RESERVED2] = "OPCODE_RESERVED2",
    [OPCODE_RESERVED3] = "OPCODE_RESERVED3",
    [OPCODE_RESERVED4] = "OPCODE_RESERVED4",
    [OPCODE_RESERVED5] = "OPCODE_RESERVED5",
    [OPCODE_RESERVED6] = "OPCODE_RESERVED6",
    [OPCODE_RESERVED7] = "OPCODE_RESERVED7",
    [OPCODE_RESERVED8] = "OPCODE_RESERVED8",
    [OPCODE_RESERVED9] = "OPCODE_RESERVED9",
    [OPCODE_RESERVED10] = "OPCODE_RESERVED10",
    [OPCODE_RESERVED11] = "OPCODE_RESERVED11",
    [OPCODE_RESERVED12] = "OPCODE_RESERVED12",
};

const char* rcode_names[] = {
    [RCODE_NO_ERROR] = "RCODE_NO_ERROR",
    [RCODE_FORMAT_ERROR] = "RCODE_FORMAT_ERROR",
    [RCODE_SERVER_FAILURE] = "RCODE_SERVER_FAILURE",
    [RCODE_NAME_ERROR] = "RCODE_NAME_ERROR",
    [RCODE_NOT_IMPLEMENTED] = "RCODE_NOT_IMPLEMENTED",
    [RCODE_REFUSED] = "RCODE_REFUSED",
    [RCODE_RESERVED0] = "RCODE_RESERVED0",
    [RCODE_RESERVED1] = "RCODE_RESERVED1",
    [RCODE_RESERVED2] = "RCODE_RESERVED2",
    [RCODE_RESERVED3] = "RCODE_RESERVED3",
    [RCODE_RESERVED4] = "RCODE_RESERVED4",
    [RCODE_RESERVED5] = "RCODE_RESERVED5",
    [RCODE_RESERVED6] = "RCODE_RESERVED6",
    [RCODE_RESERVED7] = "RCODE_RESERVED7",
    [RCODE_RESERVED8] = "RCODE_RESERVED8",
    [RCODE_RESERVED9] = "RCODE_RESERVED9",
};

const char* type_names[] = {
    [0] = "INVALID",
    [TYPE_A] = "A",
    [TYPE_NS] = "NS",
    [TYPE_MD] = "MD",
    [TYPE_MF] = "MF",
    [TYPE_CNAME] = "CNAME",
    [TYPE_SOA] = "SOA",
    [TYPE_MB] = "MB",
    [TYPE_MG] = "MG",
    [TYPE_MR] = "MR",
    [TYPE_NULL] = "NULL",
    [TYPE_WKS] = "WKS",
    [TYPE_PTR] = "PTR",
    [TYPE_HINFO] = "HINFO",
    [TYPE_MINFO] = "MINFO",
    [TYPE_MX] = "MX",
    [TYPE_TXT] = "TXT",
    [TYPE_AAAA] = "AAAA"
};

const char* qtype_names[] = {
    [0] = "INVALID",
    [QTYPE_A] = "A",
    [QTYPE_NS] = "NS",
    [QTYPE_MD] = "MD",
    [QTYPE_MF] = "MF",
    [QTYPE_CNAME] = "CNAME",
    [QTYPE_SOA] = "SOA",
    [QTYPE_MB] = "MB",
    [QTYPE_MG] = "MG",
    [QTYPE_MR] = "MR",
    [QTYPE_NULL] = "NULL",
    [QTYPE_WKS] = "WKS",
    [QTYPE_PTR] = "PTR",
    [QTYPE_HINFO] = "HINFO",
    [QTYPE_MINFO] = "MINFO",
    [QTYPE_MX] = "MX",
    [QTYPE_TXT] = "TXT",
    [QTYPE_AAAA] = "AAAA",
    [QTYPE_AXFR] = "AXFR",
    [QTYPE_MAILB] = "MAILB",
    [QTYPE_MAILA] = "MAILA",
    [QTYPE_STAR] = "*"
};

const char* class_names[] = {
    [0] = "INVALID",
    [CLASS_IN] = "IN",
    [CLASS_CS] = "CS",
    [CLASS_CH] = "CH",
    [CLASS_HS] = "HS"
};

int parseMessage(char* buf, size_t buf_len, Message* message) {
    char* original_buf = buf;
    Header header = {0};
    if (buf_len < sizeof(Header)) {
        return -1;
    }
    char* msg_base = buf;
    header.id = ntohs(((uint16_t*) buf)[0]);
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    header.flags = ntohs(((uint16_t*) buf)[0]);
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    header.qd_count = ntohs(((uint16_t*) buf)[0]);
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    header.an_count = ntohs(((uint16_t*) buf)[0]);
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    header.ns_count = ntohs(((uint16_t*) buf)[0]);
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    header.ar_count = ntohs(((uint16_t*) buf)[0]);
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    // printf("[Message] Parsed header\n");
    // printf("[Message] Id: %d\n", header.id);
    // printf("[Message] Flags: 0x%x\n", header.flags);
    // printf(
    //     " - QR: %d\n"
    //     " - Opcode: %d\n"
    //     " - AA: %d\n"
    //     " - TC: %d\n"
    //     " - RD: %d\n"
    //     " - RA: %d\n"
    //     " - Z: %d\n"
    //     " - AD: %d\n"
    //     " - CD: %d\n"
    //     " - RCode: %d\n",
    //     header.qr,
    //     header.opcode,
    //     header.aa,
    //     header.tc,
    //     header.rd,
    //     header.ra,
    //     header.z,
    //     header.ad,
    //     header.cd,
    //     header.rcode
    // );
    // printf("[Message] Question count: %d\n", header.qd_count);
    // printf("[Message] Answer count: %d\n", header.an_count);
    // printf("[Message] Authority count: %d\n", header.ns_count);
    // printf("[Message] Additional count: %d\n", header.ar_count);
    Question* question = NULL;
    if (header.qd_count > 0) {
        question = calloc(header.qd_count, sizeof(Question));
        if (question == NULL) {
            return -1;
        }
        for (int i = 0; i < header.qd_count; i++) {
            int bytes = parseQuestion(buf, buf_len, msg_base, &question[i]);
            if (bytes < 0) {
                fprintf(stderr, "[Message] Failed to parse question\n");
                free(question);
                return bytes;
            }
            // printf("[Message] Parsed question %d\n", i);
            buf += bytes;
            buf_len -= bytes;
        }
    }
    ResourceRecord* answer = NULL;
    if (header.an_count > 0) {
        answer = calloc(header.an_count, sizeof(ResourceRecord));
        if (answer == NULL) {
            return -1;
        }
        for (int i = 0; i < header.an_count; i++) {
            int bytes = parseResourceRecord(buf, buf_len, msg_base, &answer[i]);
            if (bytes < 0) {
                fprintf(stderr, "[Message] Failed to parse answer\n");
                free(answer);
                if (question) free(question);
                return bytes;
            }
            // printf("[Message] Parsed answer %d\n", i);
            buf += bytes;
            buf_len -= bytes;
        }
    }
    ResourceRecord* authority = NULL;
    if (header.ns_count > 0) {
        authority = calloc(header.ns_count, sizeof(ResourceRecord));
        if (authority == NULL) {
            return -1;
        }
        for (int i = 0; i < header.ns_count; i++) {
            int bytes = parseResourceRecord(buf, buf_len, msg_base, &authority[i]);
            if (bytes < 0) {
                fprintf(stderr, "[Message] Failed to parse authority\n");
                free(authority);
                if (answer) free(answer);
                if (question) free(question);
                return bytes;
            }
            // printf("[Message] Parsed authority %d\n", i);
            buf += bytes;
            buf_len -= bytes;
        }
    }
    ResourceRecord* additional = NULL;
    if (header.ar_count > 0) {
        additional = calloc(header.ar_count, sizeof(ResourceRecord));
        if (additional == NULL) {
            return -1;
        }
        for (int i = 0; i < header.ar_count; i++) {
            int bytes = parseResourceRecord(buf, buf_len, msg_base, &additional[i]);
            if (bytes < 0) {
                fprintf(stderr, "[Message] Failed to parse additional\n");
                free(additional);
                if (authority) free(authority);
                if (answer) free(answer);
                if (question) free(question);
                return bytes;
            }
            // printf("[Message] Parsed additional %d\n", i);
            buf += bytes;
            buf_len -= bytes;
        }
    }
    message->header = header;
    message->question = question;
    message->answer = answer;
    message->authority = authority;
    message->additional = additional;
    return buf - original_buf;
}

int parseQuestion(char* buf, size_t buf_len, char* base_addr, Question* question) {
    if (buf_len < sizeof(uint8_t) + (2 * sizeof(uint16_t))) {
        fprintf(stderr, "[Question] Unexpected end of buffer\n");
        return -1;
    }
    char* original_buf = buf;
    int result = parseDomainName(buf, buf_len, base_addr, question->qname);
    if (result <= 0) {
        fprintf(stderr, "[Question] Failed to parse domain name\n");
        return -1;
    }
    buf += result;
    buf_len -= result;
    question->qtype = ntohs(((uint16_t*) buf)[0]);
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    question->qclass = ntohs(((uint16_t*) buf)[0]);
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    return buf - original_buf;
}

int parseResourceRecord(char* buf, size_t buf_len, char* base_addr, ResourceRecord* rr) {
    if (buf_len < sizeof(uint8_t) + (3 * sizeof(uint16_t)) + sizeof(uint32_t)) {
        fprintf(stderr, "[RR] Unexpected end of buffer\n");
        return -1;
    }
    char* original_buf = buf;
    int bytes_parsed = parseDomainName(buf, buf_len, base_addr, (uint8_t*) rr->name);
    if (bytes_parsed <= 0) {
        fprintf(stderr, "[RR] Failed to parse domain name\n");
        return -1;
    }
    buf += bytes_parsed;
    buf_len -= bytes_parsed;
    rr->type = ntohs(((uint16_t*) buf)[0]);
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    rr->clas = ntohs(((uint16_t*) buf)[0]);
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    rr->ttl = ntohl(((uint32_t*) buf)[0]);
    buf += sizeof(uint32_t);
    buf_len -= sizeof(uint32_t);
    uint16_t rd_length = ntohs(((uint16_t*) buf)[0]);
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    bytes_parsed = 0;
#define invokeParse(field, type_suffix) \
    rr->data.field = malloc(sizeof(struct RR_##type_suffix)); \
    if (rr->data.field == NULL) { \
        bytes_parsed = -1; \
        break; \
    } \
    bytes_parsed = parseRR##type_suffix(buf, buf_len, rd_length, rr->data.field)
    switch (rr->type) {
        case TYPE_A: invokeParse(a, A); break;
        case TYPE_NS: invokeParse(ns, NS); break;
        case TYPE_MD: invokeParse(md, MD); break;
        case TYPE_MF: invokeParse(mf, MF); break;
        case TYPE_CNAME: invokeParse(cname, CNAME); break;
        case TYPE_SOA: invokeParse(soa, SOA); break;
        case TYPE_MB: invokeParse(mb, MB); break;
        case TYPE_MG: invokeParse(mg, MG); break;
        case TYPE_MR: invokeParse(mr, MR); break;
        case TYPE_NULL: invokeParse(nul, NULL); break;
        case TYPE_WKS: invokeParse(wks, WKS); break;
        case TYPE_PTR: invokeParse(ptr, PTR); break;
        case TYPE_HINFO: invokeParse(hinfo, HINFO); break;
        case TYPE_MINFO: invokeParse(minfo, MINFO); break;
        case TYPE_MX: invokeParse(mx, MX); break;
        case TYPE_TXT: invokeParse(txt, TXT); break;
        case TYPE_AAAA: invokeParse(aaaa, AAAA); break;
        default:
            fprintf(stderr, "[RR] Unknown resource record type: %d\n", rr->type);
            return -1;
    }
#undef invokeParse
    if (bytes_parsed < 0) {
        fprintf(stderr, "[RR] Failed to parse %s record\n", type_names[rr->type]);
        return bytes_parsed;
    }
    buf += bytes_parsed;
    buf_len -= bytes_parsed;
    return buf - original_buf;
}

void messageFree(Message* message) {
    for (int i = 0; i < message->header.qd_count; i++) {
        questionFree(message->question);
    }
    for (int i = 0; i < message->header.an_count; i++) {
        resourceRecordFree(message->answer);
    }
    for (int i = 0; i < message->header.ns_count; i++) {
        resourceRecordFree(message->authority);
    }
    for (int i = 0; i < message->header.ar_count; i++) {
        resourceRecordFree(message->additional);
    }
    free(message);
}

void questionFree(Question* question) {
    free(question);
}

void resourceRecordFree(ResourceRecord* rr) {
    switch (rr->type) {
        default:
            free(rr->data.raw_ptr);
    }
    free(rr);
}
