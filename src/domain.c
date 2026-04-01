#include "domain.h"

#include <stdio.h>
#include <string.h>
#include <sys/endian.h>

int parseDomainName(char* buf, size_t buf_len, char* base_addr, uint8_t* name) {
    memset(name, 0, DOMAIN_NAME_MAX_LEN);
    uint8_t name_offset = 0;
    uint8_t parsed_bytes = 0;
    bool encountered_ptr = false;
    while (name_offset < DOMAIN_NAME_MAX_LEN - 1) {
        if (buf_len < sizeof(uint8_t)) {
            fprintf(stderr, "[Domain] Unexpected end of buffer\n");
            return -1;
        }
        uint8_t label_len = ((uint8_t*) buf)[0];
        if ((label_len >> 6) == 0b11) {
            // Pointer
            uint16_t ptr = ntohs(((uint16_t*) buf)[0]);
            ptr &= ~(0b11 << 14);
            char* new_buf_ptr = (char*) (((uint8_t*) base_addr) + ptr);
            buf_len += (ptrdiff_t) buf - (ptrdiff_t) new_buf_ptr;
            buf = new_buf_ptr;
            if (!encountered_ptr) {
                parsed_bytes += sizeof(uint16_t);
                encountered_ptr = true;
            }
            continue;
        } else if (label_len == 0) {
            name[name_offset] = '\0';
            if (!encountered_ptr) {
                parsed_bytes += sizeof(uint8_t);
            }
            break;
        } else if (label_len > 63) {
            fprintf(stderr, "[Domain] Label is longer than maximum: %d > 63\n", label_len);
            return -1;
        }
        buf += sizeof(uint8_t);
        buf_len -= sizeof(uint8_t);
        if (!encountered_ptr) {
            parsed_bytes += sizeof(uint8_t);
        }
        if (name_offset + label_len > DOMAIN_NAME_MAX_LEN - 1) {
            fprintf(
                stderr,
                "[Domain] Domain name too long: %d > %d\n",
                name_offset + label_len,
                DOMAIN_NAME_MAX_LEN - 1
            );
            return -1;
        }
        memcpy(name + name_offset, buf, sizeof(uint8_t) * label_len);
        buf += sizeof(uint8_t) * label_len;
        buf_len -= sizeof(uint8_t) * label_len;
        if (!encountered_ptr) {
            parsed_bytes += sizeof(uint8_t) * label_len;
        }
        name_offset += label_len;
        name[name_offset++] = (uint8_t) '.';
    }
    if (name_offset > 0 && (char) name[name_offset - 1] == '.') {
        name[name_offset - 1] = '\0';
    }
    return parsed_bytes;
}

