#ifndef IPV6_H
#define IPV6_H
#include "network_layout.h"

#define IPV6_HOP_BY_HOP 0
#define IPV6_TCP 6
#define IPV6_UDP 17
#define IPV6_ENCAPS_V6_HEADER 41
#define IPV6_ROUTING_HEADER 43
#define IPV6_FRAG_HEADER 44
#define IPV6_RES_RSV 46
#define IPV6_SEC_PAYL 50
#define IPV6_AUTH_HEADER 51
#define IPV6_ICMPV6 58
#define IPV6_NO 59
#define IPV6_DEST_OPT_HEADER 60

/**
 * @brief A structure that contains the parsed first 32 bits
 * of an IPv6 header.
 */
struct ipv6_f32_parse
{
	short version; /**< Version used */
	short tc;	   /**< Traffic Class */
	uint id;	   /**< ID of the packet */
} __attribute__((packed));

/**
 * @brief analyze the IPV6 header of a packet.
 *
 * @param packet: the packet you want to analyze.
 * @param length: the packet length.
 * @param verbose: the verbose given by the user.
 */
void ipv6_header_analyze(const u_char *packet, uint length, int verbose);

/**
 * @brief Analyze the next header of the packet.
 * 
 * @param packet: the packet (begin at the next protocol).
 * @param len: the length of the packet.
 * @param nxt_head: the next header type.
 * @param verbose: the verbose given by the user.
 */
void ipv6_analyze_next_header(const u_char *packet, uint len, uint8_t nxt_head,
	int verbose);

/**
 * @brief Parse the first 32 bits of IPv6 header.
 * 
 * @param first32_bits: the first 32 bits of IPv6 header.
 */
struct ipv6_f32_parse parse_f32_ipv6(uint32_t first32_bits);

#endif //IPV6_H