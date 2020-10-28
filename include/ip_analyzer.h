#include <stdio.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>

struct ipv6_f32_parse {
	short version;
	short tc;
	uint id;
};

/**
 * @brief analyze the IPV4 header of a packet.
 *
 * @param packet: the packet you want to analyze.
 */
void ipv4_header_analyze(const u_char *packet);

/**
 * @brief analyze the IPV6 header of a packet.
 *
 * @param packet: the packet you want to analyze.
 */
void ipv6_header_analyze(const u_char *packet);

/**
 * @brief Parse the first 32 bits of IPv6 header.
 * 
 * @param first32_bits: the first 32 bits of IPv6 header.
 */
struct ipv6_f32_parse parse_f32_ipv6(uint32_t first32_bits);

