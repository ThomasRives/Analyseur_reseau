#ifndef IPV4_H
#define IPV4_H
#include "network_layout.h"

/**
 * @brief analyze the IPV4 header of a packet.
 *
 * @param packet: the packet you want to analyze.
 * @param length: the packet length.
 */
void ipv4_header_analyze(const u_char *packet, uint length);

#endif //IPV4_H