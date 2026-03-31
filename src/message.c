#include "message.h"

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char* opcode_names[16] = {
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

const char* rcode_names[16] = {
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

#define bufPtr(buf, type) ((type*)(buf))
#define bufValue(buf, type) (bufPtr(buf, type)[0])

int parseMessage(char* buf, size_t buf_len, Message* message) {
    char* original_buf = buf;
    Header header = {0};
    if (buf_len < sizeof(Header)) {
        return -1;
    }
    char* msg_base = buf;
    header.id = ntohs(bufValue(buf, uint16_t));
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    header.flags = ntohs(bufValue(buf, uint16_t));
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    header.qd_count = ntohs(bufValue(buf, uint16_t));
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    header.an_count = ntohs(bufValue(buf, uint16_t));
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    header.ns_count = ntohs(bufValue(buf, uint16_t));
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    header.ar_count = ntohs(bufValue(buf, uint16_t));
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    printf("[Message] Parsed header\n");
    printf("[Message] Id: %d\n", header.id);
    printf("[Message] Flags: 0x%x\n", header.flags);
    printf(
        " - QR: %d\n"
        " - Opcode: %d\n"
        " - AA: %d\n"
        " - TC: %d\n"
        " - RD: %d\n"
        " - RA: %d\n"
        " - Z: %d\n"
        " - AD: %d\n"
        " - CD: %d\n"
        " - RCode: %d\n",
        header.qr,
        header.opcode,
        header.aa,
        header.tc,
        header.rd,
        header.ra,
        header.z,
        header.ad,
        header.cd,
        header.rcode
    );
    printf("[Message] Question count: %d\n", header.qd_count);
    printf("[Message] Answer count: %d\n", header.an_count);
    printf("[Message] Authority count: %d\n", header.ns_count);
    printf("[Message] Additional count: %d\n", header.ar_count);
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
            printf("[Message] Parsed question %d\n", i);
            buf += bytes;
            buf_len -= bytes;
        }
    }
    printf("[Message] Parsed questions\n");
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
            printf("[Message] Parsed answer %d\n", i);
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
            printf("[Message] Parsed authority %d\n", i);
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
            printf("[Message] Parsed additional %d\n", i);
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

static int parseDomainName(char* buf, size_t buf_len, char* base_addr, uint8_t* name) {
    memset(name, 0, MAX_DOMAIN_NAME_LENGTH);
    uint8_t name_offset = 0;
    uint8_t parsed_bytes = 0;
    bool encountered_ptr = true;
    while (name_offset < MAX_DOMAIN_NAME_LENGTH - 1) {
        if (buf_len < sizeof(uint8_t)) {
            fprintf(stderr, "[Domain] Unexpected end of buffer\n");
            return -1;
        }
        uint16_t ptr = bufValue(buf, uint16_t);
        printf("Ptr: %d\n", ptr);
        if (ptr == 0) {
            break;
        } else if ((ptr >> 14) == 0b11) {
            // Pointer
            ptr &= ~(0b11 << 14);
            char* new_buf_ptr = (char*) (bufPtr(base_addr, uint8_t) + ptr);
            buf_len += (ptrdiff_t) buf - (ptrdiff_t) new_buf_ptr;
            buf = new_buf_ptr;
            if (!encountered_ptr) {
                parsed_bytes += sizeof(uint16_t);
                encountered_ptr = true;
            }
            continue;
        }
        uint8_t label_len = bufValue(buf, uint8_t);
        buf += sizeof(uint8_t);
        buf_len -= sizeof(uint8_t);
        if (!encountered_ptr) {
            parsed_bytes += sizeof(uint8_t);
        }
        printf("Label len: %d\n", label_len);
        if (name_offset + label_len > MAX_DOMAIN_NAME_LENGTH - 1) {
            fprintf(
                stderr,
                "[Domain] Domain name too long: %d > %d\n",
                name_offset + label_len,
                MAX_DOMAIN_NAME_LENGTH - 1
            );
            return -1;
        }
        memcpy(name + name_offset, buf, sizeof(uint8_t) * label_len);
        buf += sizeof(uint8_t) * label_len;
        buf_len -= sizeof(uint8_t) * label_len;
        if (encountered_ptr) {
            parsed_bytes += sizeof(uint8_t) * label_len;
        }
        name_offset += label_len;
        name[name_offset++] = (uint8_t) '.';
        printf("Name: '%s'\n", name);
    }
    if (name_offset > 0 && (char) name[name_offset - 1] == '.') {
        name[name_offset - 1] = 0;
    }
    printf("Data: '%s'\n", name);
    return parsed_bytes;
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
    question->qtype = ntohs(bufValue(buf, uint16_t));
    printf("QType: %d\n", question->qtype);
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    question->qclass = ntohs(bufValue(buf, uint16_t));
    printf("QClass: %d\n", question->qclass);
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
    int result = parseDomainName(buf, buf_len, base_addr, (uint8_t*) rr->name);
    if (result <= 0) {
        fprintf(stderr, "[RR] Failed to parse domain name\n");
        return -1;
    }
    buf += result;
    buf_len -= result;
    rr->type = ntohs(bufValue(buf, uint16_t));
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    rr->clas = ntohs(bufValue(buf, uint16_t));
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    rr->ttl = ntohl(bufValue(buf, uint32_t));
    buf += sizeof(uint32_t);
    buf_len -= sizeof(uint32_t);
    rr->rd_length = ntohs(bufValue(buf, uint16_t));
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);
    size_t bytes = rr->rd_length * sizeof(uint8_t);
    rr->rdata = malloc(bytes);
    memcpy(rr->rdata, buf, bytes);
    buf += bytes;
    buf_len -= bytes;
    return buf - original_buf;
}

void messageFree(Message* message) {
    if (message->question) {
        questionFree(message->question);
    }
    if (message->answer) {
        resourceRecordFree(message->answer);
    }
    if (message->authority) {
        resourceRecordFree(message->authority);
    }
    if (message->additional) {
        resourceRecordFree(message->additional);
    }
    free(message);
}

void questionFree(Question* question) {
    free(question);
}

void resourceRecordFree(ResourceRecord* rr) {
    free(rr);
}
