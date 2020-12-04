#ifndef ICMPV6_H
#define ICMPV6_H
#include "transport_layout.h"

/**
 * @brief Analyze the ICMPv6 header of the packet.
 * 
 * @param packet: the packet himself.
 */
void icmpv6_header_analyze(const u_char *packet, uint length);

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
 * @brief Print the icmpv6 options.
 * 
 * @param code: the code of the icmp packet.
 */
void print_icmpv6_option(const u_char *packet, uint length);

#endif //ICMPV6_H