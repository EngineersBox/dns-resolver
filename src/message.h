#pragma once

#ifndef _DNS_RESOLVER_MESSAGE_H_
#define _DNS_RESOLVER_MESSAGE_H_

#include <stddef.h>
#include <stdint.h>

typedef enum Opcode: uint8_t {
    OPCODE_QUERY = 0,
    OPCODE_IQUERY = 1,
    OPCODE_STATUS = 2,
    // Future use
    OPCODE_RESERVED0 = 3,
    OPCODE_RESERVED1 = 4,
    OPCODE_RESERVED2 = 5,
    OPCODE_RESERVED3 = 6,
    OPCODE_RESERVED4 = 7,
    OPCODE_RESERVED5 = 8,
    OPCODE_RESERVED6 = 9,
    OPCODE_RESERVED7 = 10,
    OPCODE_RESERVED8 = 11,
    OPCODE_RESERVED9 = 12,
    OPCODE_RESERVED10 = 13,
    OPCODE_RESERVED11 = 14,
    OPCODE_RESERVED12 = 15,
} Opcode;

extern const char* opcode_names[16];

typedef enum RCode: uint8_t {
    RCODE_NO_ERROR = 0,
    RCODE_FORMAT_ERROR = 1,
    RCODE_SERVER_FAILURE = 2,
    RCODE_NAME_ERROR = 3,
    RCODE_NOT_IMPLEMENTED = 4,
    RCODE_REFUSED = 5,
    RCODE_RESERVED0 = 6,
    RCODE_RESERVED1 = 7,
    RCODE_RESERVED2 = 8,
    RCODE_RESERVED3 = 9,
    RCODE_RESERVED4 = 10,
    RCODE_RESERVED5 = 11,
    RCODE_RESERVED6 = 12,
    RCODE_RESERVED7 = 13,
    RCODE_RESERVED8 = 14,
    RCODE_RESERVED9 = 15,
} RCode;

extern const char* rcode_names[16];

typedef struct Header {
    uint16_t id; // Program assigned ID for query, returned for response
    union {
        uint16_t qr: 1, // Query = 0, Response = 1
                 opcode: 4, // Message kind
                 aa: 1, // Authoritative Answer
                 tc: 1, // TrunCation
                 rd: 1, // Recursion Desired
                 ra: 1, // Recursion Available
                 z: 3,  // Reserved for future use
                 rcode: 4;
        uint16_t flags;
    };
    uint16_t qd_count; // Number of entires in question section
    uint16_t an_count; // Number of resource records in answer section
    uint16_t ns_count; // Number of name servers resource records in authority records section
    uint16_t ar_count; // Number of resource records in additional records section
} Header;

#define MAX_DOMAIN_NAME_LENGTH 256

typedef struct Question {
    uint8_t qname[MAX_DOMAIN_NAME_LENGTH];
    uint16_t qtype; // Query type
    uint16_t qclass; // Query class
} Question;

typedef struct ResourceRecord {
    char name[MAX_DOMAIN_NAME_LENGTH];
    uint16_t type; // RR type, specifying the meaning ofd data in rdata
    uint16_t clas; // Class of data in rdata
    uint32_t ttl; // Time interval in seconds that this RR can be cached for, 0 indicates no caching
    uint16_t rd_length; // Length of rdata
    uint8_t* rdata;
} ResourceRecord;

typedef struct Message {
    Header header;
    Question* question;
    ResourceRecord* answer;
    ResourceRecord* authority;
    ResourceRecord* additional;
} Message;

// Returns bytes parsed or error if negative
int parseMessage(char* buf, size_t buf_len, Message* message);
void messageFree(Message* message);
// Returns bytes parsed or error if negative
int parseQuestion(char* buf, size_t buf_len, char* base_addr, Question* question);
void questionFree(Question* question);
// Returns bytes parsed or error if negative
int parseResourceRecord(char* buf, size_t buf_len, char* base_addr, ResourceRecord* rr);
void resourceRecordFree(ResourceRecord* rr);

#endif // _DNS_RESOLVER_MESSAGE_H_
