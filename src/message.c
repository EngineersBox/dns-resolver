#include "message.h"

#include <arpa/inet.h>
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
    Header header = {0};
    if (buf_len < sizeof(Header)) {
        return -1;
    }
    char* base_addr = buf;
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
    Question* question = NULL;
    if (header.qd_count > 0) {
        question = calloc(header.qd_count, sizeof(Question));
        if (question == NULL) {
            return -1;
        }
        for (int i = 0; i < header.qd_count; i++) {
            int bytes = parseQuestion(buf, buf_len, base_addr, &question[i]);
            if (bytes < 0) {
                free(question);
                return bytes;
            }
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
            int bytes = parseResourceRecord(buf, buf_len, base_addr, &answer[i]);
            if (bytes < 0) {
                free(answer);
                if (question) free(question);
                return bytes;
            }
            buf += bytes;
            buf_len -= bytes;
        }
    }
    ResourceRecord* authority = NULL;
    if (header.an_count > 0) {
        authority = calloc(header.ar_count, sizeof(ResourceRecord));
        if (authority == NULL) {
            return -1;
        }
        for (int i = 0; i < header.an_count; i++) {
            int bytes = parseResourceRecord(buf, buf_len, base_addr, &authority[i]);
            if (bytes < 0) {
                free(authority);
                if (answer) free(answer);
                if (question) free(question);
                return bytes;
            }
            buf += bytes;
            buf_len -= bytes;
        }
    }
    ResourceRecord* additional = NULL;
    if (header.an_count > 0) {
        additional = calloc(header.ar_count, sizeof(ResourceRecord));
        if (additional == NULL) {
            return -1;
        }
        for (int i = 0; i < header.an_count; i++) {
            int bytes = parseResourceRecord(buf, buf_len, base_addr, &additional[i]);
            if (bytes < 0) {
                free(additional);
                if (authority) free(authority);
                if (answer) free(answer);
                if (question) free(question);
                return bytes;
            }
            buf += bytes;
            buf_len -= bytes;
        }
    }
    message->header = header;
    message->question = question;
    message->answer = answer;
    message->authority = authority;
    message->additional = additional;
    return 0;
}

static int parseDomainName(char* buf, size_t buf_len, char* base_addr, uint8_t* name) {
    char* original_buf = buf;
    memset(name, 0, 255);
    uint8_t name_offset = 0;
    while (true) {
        uint8_t label_len = bufValue(buf, uint8_t);
        buf += sizeof(uint8_t);
        buf_len -= sizeof(uint8_t);
        if (label_len == 0) {
            if (name_offset > 0 && (char) name[name_offset - 1] == '.') {
                name[name_offset - 1] = 0;
            }
            break;
        }
        uint8_t* buf_ref = bufPtr(buf, uint8_t);
        if ((label_len >> 6) == 0b11) {
            // Pointer
            buf_ref = bufPtr(base_addr, uint8_t) + (label_len & 0b111111);
            label_len = ntohs(bufValue(buf_len, uint8_t));
            memcpy(name + name_offset, buf_ref, label_len);
            name_offset += label_len;
            printf("Data: %s\n", name);
            continue;
        }
        memcpy(name + name_offset, buf_ref, label_len);
        buf += sizeof(uint8_t) * label_len;
        buf_len -= sizeof(uint8_t) * label_len;
        name_offset += label_len;
        name[++name_offset] = (uint8_t) '.';
        name_offset++;
        printf("Data 1: %s\n", name);
    }
    return buf - original_buf;
}

int parseQuestion(char* buf, size_t buf_len, char* base_addr, Question* question) {
    if (buf_len < sizeof(uint8_t) + (2 * sizeof(uint16_t))) {
        return -1;
    }
    char* original_buf = buf;
    int result = parseDomainName(buf, buf_len, base_addr, question->qname);
    if (result < 0) {
        return result;
    }
    buf += result;
    buf_len -= result;
    question->qtype = ntohs(bufValue(buf, uint16_t));
    question->qclass = ntohs(bufValue(buf, uint16_t));
    return buf - original_buf;
}

int parseResourceRecord(char* buf, size_t buf_len, char* base_addr, ResourceRecord* rr) {
    if (buf_len < sizeof(uint8_t) + (3 * sizeof(uint16_t)) + sizeof(uint32_t)) {
        return -1;
    }
    char* original_buf = buf;
    int result = parseDomainName(buf, buf_len, base_addr, (uint8_t*) rr->name);
    if (result < 0) {
        return result;
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
