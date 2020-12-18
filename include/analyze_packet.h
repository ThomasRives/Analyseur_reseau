#ifndef H_ANALYZE_PACK
#define H_ANALYZE_PACK

#include <pcap.h>


/**
 * @brief When a packet is detected, this function is called.
 *
 * @param args: user's optionnal parameters.
 * @param header: a struct that contains informations about the packet.
 * @param packet: the packet himself.
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

/**
 * @brief Print the received packet.
 * 
 * @param pack_length: the length of the packet.
 * @param packet: the packet himself.
 */
void print_packet(uint pack_length, const u_char *packet);

#endif
