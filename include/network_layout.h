#ifndef NETWORK_LAYOUT_H
#define NETWORK_LAYOUT_H

#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include "transport_layout.h"

#define VERS_MASK 0xf0000000
#define TRAF_CLASS_MASK 0x0ff00000
#define ID_MASK 0x000fffff

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
 * @param length: the packet length.
 */
void ipv4_header_analyze(const u_char *packet, uint length);

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

/**
 * @brief analyze the ARP header of the packet.
 * 
 * @param packet: the packet that will be analyzed.
 */
void arp_header_analyze(const u_char *packet);

/**
 * @brief analyze the RARP header of the packet.
 * 
 * It's the same function as arp_header_analyze.
 * It's just named differently to clarify the code.
 * 
 * @param packet: the packet that will be analyzed.
 */
void rarp_header_analyze(const u_char *packet);

/**
 * @brief Print the hardware address in an ARP header.
 * 
 * @param hlen: the hardware address length.
 * @param beg_addr: the pointer to the beginning of the address.
 * @param sender: indicates if it's the sender address or the receiver address.
 */
void print_arp_hard_addr(unsigned int hlen, uint8_t *beg_addr, short sender);

/**
 * @brief Print the protocol address in an ARP header.
 * 
 * @param hlen: the protocol address length.
 * @param beg_addr: the pointer to the beginning of the address.
 * @param sender: indicates if it's the sender address or the receiver address.
 */
void print_arp_pro_addr(unsigned int hlen, uint8_t *beg_addr, short sender);

#endif //NETWORK_LAYOUT_H