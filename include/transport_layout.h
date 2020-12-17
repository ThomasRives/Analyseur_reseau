#ifndef TRANSPORT_LAYOUT_H
#define TRANSPORT_LAYOUT_H

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>
#include "application_layout.h"
#include "tlv_analyzer.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "icmpv6.h"

/**
 * @brief Demultiplex the port used.
 * 
 * @param port_src: the source port used in the communication.
 * @param port: the destination port used in the communication.
 * @param packet: the packet himself.
 * @param length: the length of the packet.
 */
void demult_port(uint16_t port_src, uint16_t port_dst, const u_char *packet, uint length);

#endif //TRANSPORT_LAYOUT_H