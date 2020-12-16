#ifndef ARP_H
#define ARP_H
#include "network_layout.h"

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
void arp_print_hard_addr(unsigned int hlen, uint8_t *beg_addr, short sender);

/**
 * @brief Print the protocol address in an ARP header.
 * 
 * @param hlen: the protocol address length.
 * @param beg_addr: the pointer to the beginning of the address.
 * @param sender: indicates if it's the sender address or the receiver address.
 */
void arp_print_pro_addr(unsigned int hlen, uint8_t *beg_addr, short sender);

#endif //ARP_H
