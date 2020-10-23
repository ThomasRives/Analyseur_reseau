#include "tlv_analyzer.h"

struct tlv 
tlv_translate(u_int8_t *packet)
{
	struct tlv next_tlv;
	next_tlv.type = packet[0];
	next_tlv.length = packet[1];
	next_tlv.value = malloc(next_tlv.length * sizeof(u_int8_t));
	return next_tlv;
}