/*
 * Network packet dissector
 */

#include "npd.h"
#include "npd_f.h"
#include "npd_ipv4.h"

int main(int argc, char *argv[]) {

    /*
     * Layer 2 ethernet frame/network package.
     *
     * no 7 byte preamble (alternative 0s and 1s)
     * no 1 byte SFD - 10101011 (0xAB)
     *
     *  ______________________________________________________________
     * | Dest MAC | Src MAC | Length or Ethertype |  Data   |   CRC   |
     * |  6 bytes | 6 bytes |       2 bytes       | x bytes | 4 bytes |
     * |__________|_________|_____________________|_________|_________|
     */
    char packet_bytes[] = { 0x00, 0x13, 0x3b, 0x0c, 0x80, 0x0b, 0x00, 0x90,
                            0x4c, 0x2c, 0x30, 0x02, 0x08, 0x00, 0x45, 0x00,
                            0x00, 0x51, 0xdc, 0xd6, 0x40, 0x00, 0x40, 0x06,
                            0xd9, 0xc4, 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8,
                            0x01, 0xba, 0x13, 0xae, 0xc2, 0xca, 0x7e, 0x02,
                            0xe0, 0xd3, 0xff, 0x3a, 0x15, 0x07, 0x80, 0x18,
                            0x01, 0xc5, 0x38, 0x89, 0x00, 0x00, 0x01, 0x01,
                            0x08, 0x0a, 0x00, 0x00, 0x3c, 0x05, 0x3e, 0x7c,
                            0x34, 0xed, 0x41, 0x73, 0x74, 0x65, 0x72, 0x69,
                            0x73, 0x6b, 0x20, 0x43, 0x61, 0x6c, 0x6c, 0x20,
                            0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2f,
                            0x35, 0x2e, 0x30, 0x2e, 0x31, 0x0d, 0x0a        };

    if(argc < 2 || !argv[1]) {
        printf("No argument/data passed, using example packet.\n");
    } else {
       // TODO: do some magic by converting the string in argv[1] to byte array
    }

    char destmac[MAC_LENGTH] = {0x0};
    char srcmac[MAC_LENGTH] = {0x0};
    char *ipv4packet = NULL;
    uLong crcread = 0;
    uLong crccalc = 0;
    size_t l2packetsize = sizeof(packet_bytes);
    size_t l3packetsize = l2packetsize - DATA_OFFSET - CRC_LENGTH;

    size_t predata = length_or_ethertype(packet_bytes + LENGTH_OR_ETHERTYPE_OFFSET);

    if (predata >= 46) {
        if (predata >= 1536) {
                // it's an ethertype - let's focus only on IPv4: 0x0800 (dec.: 2048)
                if (predata == IPV4) {
                    printf("\nEthernet package contains IPv4 data. Ethertype: 0x%zx\n", predata);
                } else {
                    printf("\nnpd can't handle ethertype: 0x%zx\nOnly IPv4 is supported.\n", predata);
                    exit(EXIT_FAILURE);
                }
        }
        // else: it's length of data, nothing special to do
    } else {
        // it's a joke?
        printf("\nPacket does not seem valid. Contains neither ethertype nor data length.\n");
        exit(EXIT_FAILURE);
    }

    printf("\n%20s\t%lu bytes\n", "L2 Packet size:", l2packetsize);

    // npd assumes that data within the L2 is always ipv4 data
    ipv4packet = ipv4_data_within_packet(packet_bytes + DATA_OFFSET, l3packetsize);
    if (!ipv4packet) {
        printf("\ndata_within_packet returned NULL\n");
        return(EXIT_FAILURE);
    }

    mac_address(packet_bytes, destmac);
    mac_address(packet_bytes + MAC_LENGTH, srcmac);
    crcread = crc_within_packet(packet_bytes + l2packetsize - CRC_LENGTH);

    // print all the data of the package:
    printf("%20s\t", "Dest. MAC:");
    print_mac_address(destmac);

    printf("\n%20s\t", "Source MAC:");
    print_mac_address(srcmac);

    printf("\n%20s\t0x%.8zx", "read CRC:", crcread);
    // TODO: CRC Mismatch!?
    printf("\n%20s\t0x%.8zx", "calculated CRC:", crc32_z(crccalc, (const Bytef *)packet_bytes, l2packetsize - CRC_LENGTH));
    if (crccalc != crcread) {
        printf("\n%20s\t%s\n", "CRC:", "Mismatch!");
    } else {
        printf("\n%20s\t%s\n", "CRC:", "Match!");
    }

    if (predata >= 1536) {
        print_ipv4_data(ipv4packet, l3packetsize);
    } else {
        printf("\n%20s\t%zu bytes", "Data length:", predata);
        printf("\n%20s\t%s", "Data type:", "unknown");
    }

    free(ipv4packet);
    printf("\n\nSuccesfully executed. Closing npd.");
    return 0;
}
