#ifndef IPV4_H
#define IPV4_H
#include "network_layout.h"

#define IPV4_FLAGS 0xe0
#define IPV4_FRAG_OFF 0x1f
#define IPV4_FLAG_DO_NOT_FRAG 0x40
#define IPV4_FLAG_MORE_FRAG 0x20

/**
 * @brief analyze the IPV4 header of a packet.
 *
 * @param packet: the packet you want to analyze.
 * @param length: the packet length.
 */
void ipv4_header_analyze(const u_char *packet, uint length);

/**
 * @brief Print the IPv4 flags.
 * 
 * @param flags: flags of the packet.
 */
void ipv4_print_flags(uint8_t flags);

/**
 * @brief Print the protocol used and analyze it.
 * 
 * @param packet: the packet (begin at the protocol).
 * @param len: the length of the packet.
 * @param prot: the protocol used.
 */
void ipv4_demult_prot(const u_char *packet, uint len, uint8_t prot);

#endif //IPV4_H