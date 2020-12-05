#include "ldap.h"

void
ldap_analyzer(const u_char *packet, uint length)
{
	uint byte_read = 0;
	while(byte_read < length)
	{
		struct ldap_tlv tlv = parse_tlv(packet + byte_read);
		byte_read += sizeof(uint16_t) + tlv.length;
	}
}

struct ldap_tlv
parse_tlv(const u_char *next_tlv)
{
	struct ldap_tlv tlv;
	uint16_t host_tlv = ntohs(*(uint16_t *)next_tlv);
	tlv.data_type = (host_tlv & DATA_TYPE) >> DATA_TYPE_DEC;
	tlv.constr_val = (host_tlv & CONSTR_VAL) >> CONSTR_VAL_DEC;
	tlv.data_synt = host_tlv & DATA_SYNT;
	tlv.long_not = (host_tlv & LONG_NOT) >> LONG_NOT_DEC;
	tlv.length = host_tlv & LEN;
	NULL_CHECK(tlv.value = malloc(tlv.length + 1));
	tlv.value[tlv.length] = '\0';
	return tlv;
}