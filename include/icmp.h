#ifndef ICMP_H
#define ICMP_H
#include "transport_layout.h"

/**
 * @brief Analyze the ICMP header of the packet.
 * 
 * @param packet: the packet himself.
 * @param length: the packet length.
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

#endif //ICMP_H