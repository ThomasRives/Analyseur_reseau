#ifndef UDP_H
#define UDP_H
#include "transport_layout.h"

/**
 * @brief Analyze the UDP header of the packet.
 * 
 * @param packet: the packet himself.
 * @param length: the packet length.
 */
void udp_header_analyze(const u_char *packet, uint length);

#endif //UDP_H