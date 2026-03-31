#include <stdio.h>
#include <stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<unistd.h>

#include "message.h"

struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};
 
//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 
//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};
 
//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;

void changetoDnsNameFormat(unsigned char* dns, char* host) {
    size_t lock = strlen(host);
    dns[lock] = '\0';
    for (int i = lock - 1; i >= 0; i--) {
        if (host[i] != '.') {
            continue;
        }
        memcpy(&(dns[i + 1]), &(host[i + 1]), lock - 1 - i);
        dns[i] = lock - 1 - i;
        lock = i;
    }
}

int print_rr(const ResourceRecord* rr) {
    printf("Name: %s ", rr->name);
    printf("Type: %s ", type_names[rr->type]);
    printf("Class: %s ", class_names[rr->clas]);
    printf("TTL: %d ", rr->ttl);
    printf("RD Len: %d ", rr->rd_length);
    switch (rr->type) {
        case TYPE_A:
            char ipv4_addr[INET_ADDRSTRLEN] = {0};
             if (inet_ntop(AF_INET, rr->rdata, ipv4_addr, INET_ADDRSTRLEN) == NULL) {
                perror("Failed to convert IPv4 address");
                return 1;
             }
            printf("Address: %s", ipv4_addr); 
            break;
        case TYPE_AAAA:
            char ipv6_addr[INET6_ADDRSTRLEN] = {0};
             if (inet_ntop(AF_INET6, rr->rdata, ipv6_addr, INET6_ADDRSTRLEN) == NULL) {
                perror("Failed to convert IPv6 address");
                return 1;
             }
            printf("Address: %s", ipv6_addr); 
            break;
        default:
            break;
    }
    printf("\n");
    return 0;
}

int main(const int argc, const char** argv) {
    // TODO: Format query ourselves
    unsigned char buf[65536],*qname;
 
    struct sockaddr_in dest;
 
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
 
    int s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
 
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr("1.1.1.1");
 
    //Set the DNS structure to standard queries
    dns = (struct DNS_HEADER *)&buf;
 
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;
 
    //point to the query portion
    qname = (unsigned char*) &buf[sizeof(struct DNS_HEADER)];
 
    changetoDnsNameFormat(qname , ".www.instaclustr.com");
    qinfo = (struct QUESTION*) &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it
 
    qinfo->qtype = htons(TYPE_AAAA);
    qinfo->qclass = htons(CLASS_IN);
 
    printf("Sending Packet...\n");
    if (sendto(
        s,
        (char*) buf,
        sizeof(struct DNS_HEADER)
            + (strlen((const char*) qname) + 1)
            + sizeof(struct QUESTION),
        0,
        (struct sockaddr*) &dest,
        sizeof(dest)
    ) < 0) {
        perror("sendto failed");
        return 1;
    }
    printf("Done\n");
     
    //Receive the answer
    int i = sizeof(dest);
    printf("Receiving answer...\n");
    size_t buf_len = 0;
    if ((buf_len = recvfrom(
        s,
        (char*) buf,
        65536,
        MSG_WAITALL,
        (struct sockaddr*) &dest,
        (socklen_t*) &i
    )) < 0) {
        perror("recvfrom failed");
        return 1;
    }
    printf("Done\n");

    Message* message = malloc(sizeof(Message));
    *message = (Message) {0};
    int result = parseMessage((char*) buf, buf_len, message);
    if (result <= 0) {
        fprintf(stderr, "Failed to parse message\n");
        messageFree(message);
        return 1;
    }
    for (int i = 0; i < message->header.an_count; i++) {
        const ResourceRecord* rr = &message->answer[i];
        printf("[Answer %d] ", i);
        if (print_rr(rr)) {
            return 1;
        }
    }
    for (int i = 0; i < message->header.ns_count; i++) {
        const ResourceRecord* rr = &message->authority[i];
        printf("[Authority %d] ", i);
        if (print_rr(rr)) {
            return 1;
        }
    }
    for (int i = 0; i < message->header.ar_count; i++) {
        const ResourceRecord* rr = &message->additional[i];
        printf("[Additional %d] ", i);
        if (print_rr(rr)) {
            return 1;
        }
    }
    messageFree(message);
    return 0;
}
