#pragma once

#ifndef _DNS_RESOLVER_DOMAIN_H_
#define _DNS_RESOLVER_DOMAIN_H_

#include <stddef.h>
#include <stdint.h>

#define DOMAIN_NAME_MAX_LEN 256

int parseDomainName(char* buf, size_t buf_len, char* base_addr, uint8_t* name);

#endif // _DNS_RESOLVER_DOMAIN_H_
