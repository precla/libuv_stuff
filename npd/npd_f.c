#include "npd_f.h"

void print_mac_address(char *mac) {
    for(uShort i = 0; i < MAC_LENGTH; ++i) {
        printf("%.2x", (uChar)mac[i]);
        if(i < (MAC_LENGTH - 1)) {
            printf(":");
        }
    }
}

void mac_address(char *packet, char *dest) {
    memcpy(dest, packet, MAC_LENGTH);
}

size_t length_or_ethertype(char *packet) {
    return concat_hex_val(packet);
}

uLong crc_within_packet(char *packet) {
    /*
     * double call to concat_hex_val, first one takes first two bytes of CRC
     * moves them by 2 bytes to left, 'concats' last two bytes of CRC
     */
    return ( concat_hex_val(packet) << 16 | concat_hex_val(packet + 2) );
}

size_t concat_hex_val(char *src) {
    return ( (src[0]<<8) | src[1] );
}
