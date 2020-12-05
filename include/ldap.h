#ifndef LDAP_H
#define LDAP_H
#include "application_layout.h"

#define BIND_REQUEST 0
#define BIND_RESP 1
#define UNBIND_REQUEST 2
#define SEARCH_REQ 3
#define SEARCH_RES_ENTR 4
#define SEARCH_RES_DONE 5
#define MODIFY_REQ 6
#define MODIFY_RES 7
#define ADD_REQ 8
#define ADD_RESP 9
#define DEL_REQ 10
#define DEL_RESP 11
#define MODIFY_DN_REQ 12
#define MODIFY_DN_RESP 13
#define COMP_REQ 14
#define COMP_RESP 15
#define ABANDON_REQ 16
#define SEARCH_RES_REF 19
#define EXTENDED_REQ 23
#define EXTENDED_RESP 24

/**
 * @brief This structure contain all the informations of a LDAP Tag Length Value
 */
struct ldap_tlv {
	uint8_t data_type;
	uint8_t constr_val;
	uint8_t data_synt;
	uint8_t long_not;
	uint8_t length;
	uint8_t *value;
};

#define DATA_TYPE 0xc0
#define DATA_TYPE_DEC 6

#define CONSTR_VAL 0x20
#define CONSTR_VAL_DEC 5

#define DATA_SYNT 0x1f

#define LONG_NOT 0x80
#define LONG_NOT_DEC 7

#define LEN 0x7f

/**
 * @brief Analyze LDAP packet.
 * 
 * @param packet: the packet himself.
 * @param length: the length of the packet.
 */
void ldap_analyzer(const u_char *packet, uint length);

/**
 * @brief Get the next tlv and parse it.
 * 
 * @param next_tlv: a pointer to the beginning of the next_tlv.
 * @return struct ldap_tlv that contains all the informations.
 */
struct ldap_tlv parse_tlv(const u_char *next_tlv);

#endif //LDAP_H