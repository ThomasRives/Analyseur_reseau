#ifndef ETHER_H
#define ETHER_H
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "analyze_packet.h"

/**
 * @brief Analyze the ethernet header.
 * 
 * @param packet: the packet himself.
 * @param len: the length of the packet.
 */
void analyze_ethernet_hearder(const u_char *packet, uint len);

/**
 * @brief Analyze the protocol used and analyze it.
 * 
 * @param packet: the packet (begin at the protocol).
 * @param len: the length of the packet.
 * @param prot: the protocol used.
 */
void ethernet_demult_prot(const u_char *packet, uint len, uint16_t prot);

#endif //ETHER_H