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
        struct {
        // uint16_t rd: 1, // recursion desired
        //          tc :1, // truncated message
        //          aa :1, // authoritive answer
        //          opcode :4, // purpose of message
        //          qr :1, // query/response flag
        //
        //          rcode :4, // response code
        //          cd :1, // checking disabled
        //          ad :1, // authenticated data
        //          z :1, // its z! reserved
        //          ra :1; // recursion available
            uint16_t qr: 1, // Query = 0, Response = 1
                     opcode: 4, // Message kind
                     aa: 1, // Authoritative Answer
                     tc: 1, // TrunCation
                     rd: 1, // Recursion Desired
                     ra: 1, // Recursion Available
                     z: 1,  // Reserved for future use
                     ad: 1, // Authenticated Data
                     cd: 1, // Checking disabled
                     rcode: 4;
        };
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

typedef enum Type: uint16_t {
    TYPE_A = 1, // Host address IPv4
    TYPE_NS = 2, // Authoritative name server
    TYPE_MD = 3, // Mail destination (obselete - use MX)
    TYPE_MF = 4, // Mail forwarder (obselete - use MX)
    TYPE_CNAME = 5, // Canonical name for an alias
    TYPE_SOA = 6, // Marks the start of a zone of authority
    TYPE_MB = 7, // Mailbox domain name
    TYPE_MG = 8, // Mail group member
    TYPE_MR = 9, // Mail rename domain name
    TYPE_NULL = 10, // Null RR
    TYPE_WKS = 11, // Well known service description
    TYPE_PTR = 12, // Domain name pointer
    TYPE_HINFO = 13, // Host information
    TYPE_MINFO = 14, // Mailbox or mail list information
    TYPE_MX = 15, // Mail exchange
    TYPE_TXT = 16, // Text strings
    TYPE_AAAA = 28 // Host address IPv6
} Type;

extern const char* type_names[29];

typedef enum QType: uint16_t {
    QTYPE_A = 1, // Host address IPv4
    QTYPE_NS = 2, // Authoritative name server
    QTYPE_MD = 3, // Mail destination (obselete - use MX)
    QTYPE_MF = 4, // Mail forwarder (obselete - use MX)
    QTYPE_CNAME = 5, // Canonical name for an alias
    QTYPE_SOA = 6, // Marks the start of a zone of authority
    QTYPE_MB = 7, // Mailbox domain name
    QTYPE_MG = 8, // Mail group member
    QTYPE_MR = 9, // Mail rename domain name
    QTYPE_NULL = 10, // Null RR
    QTYPE_WKS = 11, // Well known service description
    QTYPE_PTR = 12, // Domain name pointer
    QTYPE_HINFO = 13, // Host information
    QTYPE_MINFO = 14, // Mailbox or mail list information
    QTYPE_MX = 15, // Mail exchange
    QTYPE_TXT = 16, // Text strings
    QTYPE_AAAA = 28, // Host address IPv6
    QTYPE_AXFR = 252, // Request for transfer of an entire zone
    QTYPE_MAILB = 253, // Request for mailbox-related records (MB, MG or MR)
    QTYPE_MAILA = 254, // Request for mail agent PRs (Obselete - see MX)
    QTYPE_STAR = 255 // Request for all records
} QType;

extern const char* qtype_names[256];

typedef enum Class: uint16_t {
    CLASS_IN = 1, // Internet
    CLASS_CS = 2, // CSNET
    CLASS_CH = 3, // CHAOS
    CLASS_HS = 4  // Hesoid
} Class;

extern const char* class_names[5];

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
