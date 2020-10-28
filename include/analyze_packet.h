#ifndef H_ANALYZE_PACK
#define H_ANALYZE_PACK
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

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
    void
    print_packet(uint pack_length, uint16_t *packet);

#endif
