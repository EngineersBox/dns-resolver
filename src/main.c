#include <stdio.h>
#include <stdlib.h>

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

int main(const int argc, const char** argv) {
    char* data = NULL;
    const int len = readFile("dig.raw", &data);
    if (data == NULL) {
        return 1;
    }
    Message* message = malloc(sizeof(Message));
    *message = (Message) {0};
    int result = parseMessage(data, len, message);
    if (result <= 0) {
        messageFree(message);
        return 1;
    }
    printf("Id: %d\n", message->header.id);
    printf("Flags: %b\n", message->header.flags);
    printf("Questions: %d\n", message->header.qd_count);
    printf("Answer count: %d\n", message->header.an_count);
    printf("Name servers count: %d\n", message->header.ns_count);
    printf("Additional count: %d\n", message->header.ar_count);
    messageFree(message);
    return 0;
}
