#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

//ICMP
//ICMPv6

/**
 * @brief Analyze the TCP header of the packet.
 * 
 * @param packet: the packet himself.
 */
void tcp_header_analyze(const u_char *packet);

/**
 * @brief Print TCP options.
 * 
 * @param read_header: the number of bytes already read.
 * @param off: the data offset.
 * @param tcp_options: a pointer to the beginning of the options.
 */
void print_tcp_options(uint8_t read_header, uint8_t off, uint8_t *tcp_options);

/**
 * @brief Analyze the UDP header of the packet.
 * 
 * @param packet: the packet himself.
 */
void udp_header_analyze(const u_char *packet);

/**
 * @brief Analyze the ICMP header of the packet.
 * 
 * @param packet: the packet himself.
 */
void icmp_header_analyze(const u_char *packet);