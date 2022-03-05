#pragma once

#include "npd.h"

void print_mac_address(char *mac);

void mac_address(char *packet, char *dest);
size_t length_or_ethertype(char *packet);
uLong crc_within_packet(char *packet);

/*
 * concat two 8bit hex values, example: 0x08 and 0x00 -> 0x0800
 * supports only TWO hex values NEXT TO EACH OTHER
 * return as size_t: 0x0800 -> 2048
 */
size_t concat_hex_val(char *src);
