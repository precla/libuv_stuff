#pragma once

#include "npd.h"

char *ipv4_data_within_packet(char *packet, size_t packetsize);
void print_ipv4_data(char *ipv4packet, size_t size);
void ipv4_address(char *ipv4packet, uChar *dest);
void print_ipv4_address(uChar *ipv4packet);
uInt ipv4_checksum(uChar *ipv4packet);
void ipv4_header(char *p, uChar *h);
uInt calc_ipv4_header_checksum(uChar *h);
