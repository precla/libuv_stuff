#pragma once

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define MAC_LENGTH                  6
#define LENGTH_OR_ETHERTYPE_OFFSET  (MAC_LENGTH * 2)                    // length or ethertype
#define DATA_OFFSET                 (LENGTH_OR_ETHERTYPE_OFFSET + 2)
#define CRC_LENGTH                  4
#define IPV4                        0x0800

typedef unsigned char uChar;
typedef unsigned short uShort;
