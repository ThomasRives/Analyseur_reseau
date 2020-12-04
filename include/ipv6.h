#ifndef IPV6_H
#define IPV6_H
#include "network_layout.h"

/**
 * @brief A structure that contains the parsed first 32 bits
 * of an IPv6 header.
 */
struct ipv6_f32_parse
{
	short version; /**< Version used */
	short tc;	   /**< Traffic Class */
	uint id;	   /**< ID of the packet */
};

/**
 * @brief analyze the IPV6 header of a packet.
 *
 * @param packet: the packet you want to analyze.
 * @param length: the packet length.
 */
void ipv6_header_analyze(const u_char *packet, uint length);

/**
 * @brief Parse the first 32 bits of IPv6 header.
 * 
 * @param first32_bits: the first 32 bits of IPv6 header.
 */
struct ipv6_f32_parse parse_f32_ipv6(uint32_t first32_bits);

#endif //IPV6_H