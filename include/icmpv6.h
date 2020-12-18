#ifndef ICMPV6_H
#define ICMPV6_H
#include "transport_layout.h"

#define ICMP6_SRC_ADDR_FAIL 5
#define ICMP6_REJ_ROUTE_DST 6
#define ICMP6_ERR_SRC_ROUT 7
#define ICMP6_HEADER_TOO_LONG 8


/* Code */
#define ICMP6_PARAMPROB_INC 3
#define ICMP6_PARAMPROB_UP_LAY 4
#define ICMP6_PARAMPROB_UNREC_NXT_HEAD 5
#define ICMP6_PARAMPROB_EXT_TOO_BIG 6
#define ICMP6_PARAMPROB_EXT_CHAIN_TL 7
#define ICMP6_PARAMPROB_TOO_MNY_EXT 8
#define ICMP6_PARAMPROB_TOO_MNY_OPT 9
#define ICMP6_PARAMPROB_OPT_TOO_BIG 10
#define ICMP6_ROUTREM_RENUMB_COMM 0
#define ICMP6_ROUTREM_RENUMB_RES 1
#define ICMP6_ROUTREM_SEQ_NUM_RES 255

/**
 * @brief Analyze the ICMPv6 header of the packet.
 * 
 * @param packet: the packet himself.
 * @param verbose: the verbose given by the user.
 */
void icmpv6_header_analyze(const u_char *packet, int verbose);

/**
 * @brief Print the type (and the code) of the ICMPv6 packet.
 * 
 * @param type: the type of the packet.
 * @param code: the code associated to the type.
 * @param packet: the packet himself.
 * @param verbose: the verbose given by the user.
 */
void print_icmpv6_type_code(uint8_t type, uint8_t code, const u_char *packet,
	int verbose);

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

#endif //ICMPV6_H