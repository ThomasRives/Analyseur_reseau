#include "tlv_analyzer.h"

struct tlv 
tlv_translate(uint8_t *packet)
{
	struct tlv next_tlv;
	next_tlv.type = packet[0];
	if (next_tlv.type == 1 || next_tlv.type == 0)
		return next_tlv;
	next_tlv.length = packet[1];
	next_tlv.value = malloc(next_tlv.length * (sizeof(uint8_t) + 1));
	NULL_CHECK(memcpy(next_tlv.value, packet, next_tlv.length));
	return next_tlv;
}