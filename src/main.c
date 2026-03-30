#include <stdio.h>
#include <stdlib.h>
#include<string.h>    //strlen
#include<sys/socket.h>    //you know what this is for
#include<arpa/inet.h> //inet_addr , inet_ntoa , ntohs etc
#include<netinet/in.h>
#include<unistd.h>    //getpid

#include "message.h"

int readFile(const char* file_path, char** out) {
    FILE *fp = fopen(file_path, "r");
    if (fp == NULL) {
        fprintf(stderr, "Cannot open file\n");
        return -1;
    }
    /* Go to the end of the file. */
    if (fseek(fp, 0L, SEEK_END) != 0) {
        fprintf(stderr, "Failed to seek\n");
        return -1;
    }
    /* Get the size of the file. */
    const long bufsize = ftell(fp);
    if (bufsize == -1) {
        fprintf(stderr, "Cannot get file size\n");
        return -1;
    }
    /* Allocate our buffer to that size. */
    char* source = malloc(sizeof(char) * (bufsize + 1));
    /* Go back to the start of the file. */
    if (fseek(fp, 0L, SEEK_SET) != 0) {
        free(source);
        fprintf(stderr, "Failed to seek\n");
        return -1;
    }
    /* Read the entire file into memory. */
    size_t new_len = fread(
        source,
        sizeof(char),
        bufsize,
        fp
    );
    if (ferror( fp ) != 0) {
        fprintf(stderr, "Error reading file\n", stderr);
    } else {
        source[new_len++] = '\0'; /* Just to be safe. */
    }
    fclose(fp);
    *out = source;
    return new_len;
}

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server
 
//DNS header structure
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

void changetoDnsNameFormat(unsigned char* dns, unsigned char* host) {
    int lock = 0;
    for(int i = 0 ; i < strlen((char*)host) ; i++) {
        if(host[i] != '.') {
            continue;
        }
        *dns++ = i-lock;
        for(;lock<i;lock++) {
            *dns++ = host[lock];
        }
        lock++; //or lock=i+1;
    }
    *dns++='\0';
}

int main(const int argc, const char** argv) {
    // char* data = NULL;
    // const int len = readFile("dig.raw", &data);
    // if (data == NULL) {
    //     return 1;
    // }
    unsigned char buf[65536],*qname;
 
    struct sockaddr_in dest;
 
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
 
    int s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
 
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr("8.8.8.8");
 
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
 
    changetoDnsNameFormat(qname , (unsigned char*) ".www.google.com");
    qinfo = (struct QUESTION*) &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it
 
    qinfo->qtype = htons(T_A);
    qinfo->qclass = htons(1);
 
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
    const ResourceRecord* rr = &message->authority[0];
    printf("Name: %s\n", rr->name);
    printf("Len: %d\n", rr->rd_length);
    messageFree(message);
    return 0;
}
