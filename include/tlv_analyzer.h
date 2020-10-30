#ifndef TLV_ANALYZER_H
#define TLV_ANALYZER_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include "utilities.h"

struct tlv {
	uint type;
	uint length;
	uint8_t *value;
};

/**
 * @brief Get the next TLV structure in the packet
 * 
 * @param packet: the packet to analyze
 * @return a structure with all the informations given by the packet
 */
struct tlv tlv_translate(uint8_t *packet);

#endif //TLV_ANALYZER_H