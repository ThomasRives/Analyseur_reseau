#ifndef RARP_H
#define RARP_H
#include "network_layout.h"

/**
 * @brief analyze the RARP header of the packet.
 * 
 * It's the same function as arp_header_analyze.
 * It's just named differently to clarify the code.
 * 
 * @param packet: the packet that will be analyzed.
 * @param verbose: the verbose given by the user.
 */
void rarp_header_analyze(const u_char *packet, int verbose);

#endif //RARP_H