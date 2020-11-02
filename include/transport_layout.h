#ifndef TRANSPORT_LAYOUT_H
#define TRANSPORT_LAYOUT_H

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

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

/**
 * @brief Print the type/code informations for icmp.
 * 
 * @param type: the type of the icmp packet.
 * @param code: the code of the icmp packet.
 */
void print_icmp_type_code(uint8_t type, uint8_t code);

/**
 * @brief Print the code if the type is "Destination Unreachable"
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmp_dest_unreach_code(uint8_t code);

/**
 * @brief Print the code if the type is "Redirect"
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmp_redirect_code(uint8_t code);

/**
 * @brief Print the code if the type is "Router Advertisement"
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmp_rout_ad_code(uint8_t code);

/**
 * @brief Print the code if the type is "Time Exceeded"
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmp_time_exc_code(uint8_t code);

/**
 * @brief Print the code if the type is "Parameter Problem"
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmp_par_prob_code(uint8_t code);

/**
 * @brief Print the code if the type is "Photuris"
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmp_photuris_code(uint8_t code);

/**
 * @brief Print the code if the type is "Extended Echo Reply"
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

#endif //TRANSPORT_LAYOUT_H