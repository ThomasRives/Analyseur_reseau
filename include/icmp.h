#ifndef ICMP_H
#define ICMP_H
#include "transport_layout.h"

#define ICMP_ALTER_HOST_ADDR 6
#define ICMP_ROUTER_ADV 9
#define ICMP_ROUT_SOLICI 10
#define ICMP_PHOTURIS 40
#define ICMP_EXP 41
#define ICMP_EXT_ECHO 42
#define ICMP_EXT_ECHO_REP 43

#define ICMP_NORM_ROUT_ADV 0
#define ICMP_NOT_ROUT_COMMON_TRAF 16

#define ICMP_PARAMPROB_POINT_ERR 0
#define ICMP_PARAMPROB_BADLEN 2

#define ICMP_PHOT_BAD_PSI 0
#define ICMP_PHOT_AUTH_FAIL 1
#define ICMP_PHOT_DECOMP_FAIL 2
#define ICMP_PHOT_DECRYP_FAIL 3
#define ICMP_PHOT_NEED_AUTHENT 4
#define ICMP_PHOT_NEED_AUTHORIZ 5

#define ICMP_EER_MALFORMED_REQ 1
#define ICMP_EER_NO_INT 2
#define ICMP_EER_NO_TABLE 3
#define ICMP_EER_MULT_INT 4


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