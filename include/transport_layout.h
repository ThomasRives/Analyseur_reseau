#ifndef TRANSPORT_LAYOUT_H
#define TRANSPORT_LAYOUT_H

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include "application_layout.h"

#define PORT_SMTP 25
#define PORT_TELNET 23
#define PORT_FTP 21
#define PORT_HTTP 80
#define PORT_DNS 53
#define PORT_POP 110

/**
 * @brief Analyze the TCP header of the packet.
 * 
 * @param packet: the packet himself.
 * @param length: the packet length.
 */
void tcp_header_analyze(const u_char *packet, uint length);

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
 * @param length: the packet length.
 */
void udp_header_analyze(const u_char *packet, uint length);

/**
 * @brief Analyze the ICMP header of the packet.
 * 
 * @param packet: the packet himself.
 */
void icmp_header_analyze(const u_char *packet);

/**
 * @brief Print the type/code informations for icmp.
 * 
 * @param type: the type of the icmp packet.
 * @param code: the code of the icmp packet.
 */
void print_icmp_type_code(uint8_t type, uint8_t code);

/**
 * @brief Print the icmp code if the type is "Destination Unreachable"
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmp_dest_unreach_code(uint8_t code);

/**
 * @brief Print the icmp code if the type is "Redirect"
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmp_redirect_code(uint8_t code);

/**
 * @brief Print the icmp code if the type is "Router Advertisement"
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmp_rout_ad_code(uint8_t code);

/**
 * @brief Print the icmp code if the type is "Time Exceeded"
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmp_time_exc_code(uint8_t code);

/**
 * @brief Print the icmp code if the type is "Parameter Problem"
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmp_par_prob_code(uint8_t code);

/**
 * @brief Print the icmp code if the type is "Photuris"
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmp_photuris_code(uint8_t code);

/**
 * @brief Print the icmp code if the type is "Extended Echo Reply"
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmp_ext_ech_rep_code(uint8_t code);

/**
 * @brief Analyze the ICMPv6 header of the packet.
 * 
 * @param packet: the packet himself.
 */
void icmpv6_header_analyze(const u_char *packet);

/**
 * @brief Print the icmpv6 code if the type is "Destination Unreachable"
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmp6_dest_unreach_code(uint8_t code);

/**
 * @brief Print the icmpv6 code if the type is "Time Exceeded"
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmp6_time_exc_code(uint8_t code);

/**
 * @brief Print the icmpv6 code if the type is "Parameter Problem"
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmpv6_par_prob_code(uint8_t code);

/**
 * @brief Print the icmpv6 code if the type is "Router Renumbering"
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmpv6_rout_rem_code(uint8_t code);

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