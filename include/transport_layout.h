#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
//TCP
//UDP
//ICMP
//ICMPv6

/**
 * @brief Analyze the TCP header of the packet.
 * 
 * @param packet: the packet himself.
 */
void tcp_header_analyze(const u_char *packet);