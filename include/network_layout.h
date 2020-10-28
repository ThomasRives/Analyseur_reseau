#include <stdio.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <net/if_arp.h>
#include <netinet/ether.h>

//IPv6 OK
//IPv4 OK
//ARP
//RARP

/**
 * @brief A structure that contains the parsed first 32 bits
 * of an IPv6 header.
 */
struct ipv6_f32_parse {
	short version; /**< Version used */
	short tc; /**< Traffic Class */
	uint id; /**< ID of the packet */
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

/**
 * @brief analyze the ARP header of the packet.
 * 
 * @param packet: the packet that will be analyzed.
 */
void arp_header_analyze(const u_char *packet);

/**
 * @brief Print the hardware address in an ARP header.
 * 
 * @param hlen: the hardware address length.
 * @param beg_addr: the pointer to the beginning of the address.
 * @param sender: indicates if it's the sender address or the receiver address.
 */
void print_arp_hard_addr(unsigned int hlen, uint32_t *beg_addr, short sender);

/**
 * @brief Print the protocol address in an ARP header.
 * 
 * @param hlen: the protocol address length.
 * @param beg_addr: the pointer to the beginning of the address.
 * @param sender: indicates if it's the sender address or the receiver address.
 */
void print_arp_pro_addr(unsigned int hlen, uint32_t *beg_addr, short sender);