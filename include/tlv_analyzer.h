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
} __attribute__((packed));

/**
 * @brief Get the next TLV structure in the tcp packet
 * 
 * @param packet: the packet to analyze
 * @return a structure with all the informations given by the packet
 */
struct tlv tlv_translate_tcp(uint8_t *packet);

/**
 * @brief Get the next TLV structure in the bootp packet
 * 
 * @param packet: the packet to analyze
 * @return a structure with all the informations given by the packet
 */
struct tlv tlv_translate_bootp(uint8_t *packet);

/**
 * @brief Print the value if it's an integer.
 * 
 * @param length: the length of the value.
 * @param value: the value that will be printed as an integer.
 */
void print_value_nb(uint length, u_char *value);

/**
 * @brief Print the value if it's an string.
 * 
 * @param length: the length of the value.
 * @param value: the value that will be printed as an integer.
 */
void print_value_str(uint length, u_char *value);

#endif //TLV_ANALYZER_H