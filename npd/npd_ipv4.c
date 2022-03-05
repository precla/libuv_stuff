#include "npd_ipv4.h"

#define IP_LENGTH       4
#define SRC_IP_OFFSET   12
#define DEST_IP_OFFSET  (SRC_IP_OFFSET + 4)

/*
 *                    IPv4 Package format
 *  ____________________________________________________________
 * | Version |  IHL   | Type of service |     Total length      |
 * | 4 bits  | 4 bits |     1 byte      |        2 bytes        |
 * |_________|________|_________________|_______________________|
 * |           Identification           | Flags | Fragment Offs.|
 * |               2 byte               | 3 bit |    13 bits    |
 * |____________________________________|_______|_______________|
 * |         TTL      |    Protocol     |    Header checksum    |
 * |        1 byte    |     1 byte      |       2 bytes         |
 * |__________________|_________________|_______________________|
 * |                     Source IP address                      |
 * |                          4 bytes                           |
 * |____________________________________________________________|
 * |                  Destination IP address                    |
 * |                          4 bytes                           |
 * |____________________________________________________________|
 * |                    Options             |     Padding       |
 * |                 variable size          |   variable size   |
 * |________________________________________|___________________|
 */

void print_ipv4_data(char *ipv4packet, size_t size) {
    printf("\n%20s\t%lu bytes", "L3 IPv4 packet size:", size);

    uChar ipv4srcadr[4] = {0};
    uChar ipv4destadr[4] = {0};

    ipv4_address(ipv4packet + SRC_IP_OFFSET, ipv4srcadr);
    ipv4_address(ipv4packet + DEST_IP_OFFSET, ipv4destadr);

    printf("\n%20s\t", "IPv4 source address:");
    print_ipv4_address(ipv4srcadr);
    printf("\n%20s\t", "IPv4 source address:");
    print_ipv4_address(ipv4destadr);
}

char *ipv4_data_within_packet(char *packet, size_t packetsize) {
    char *ipv4packet = calloc(sizeof(char), packetsize);
    if (!ipv4packet) {
        printf("\ncalloc() for ipv4packet returned NULL. No free memory?");
        return NULL;
    }
    memcpy(ipv4packet, packet, packetsize);
    return ipv4packet;
}

void ipv4_address(char *ipv4packet, uChar *dest) {
    memcpy(dest, ipv4packet, IP_LENGTH);
    for (uShort i = 0; i < IP_LENGTH; ++i) {
        dest[i] = (uShort)dest[i];
    }
}

void print_ipv4_address(uChar *ipv4addr) {
    for(uShort i = 0; i < IP_LENGTH; ++i) {
        printf("%u", ipv4addr[i]);
        if(i < (IP_LENGTH - 1)) {
            printf(".");
        }
    }
}
