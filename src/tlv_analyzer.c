#include "tlv_analyzer.h"

struct tlv 
tlv_translate_tcp(uint8_t *packet)
{
	struct tlv next_tlv;
	next_tlv.type = packet[0];
	if (next_tlv.type == 1 || next_tlv.type == 0)
		return next_tlv;
	next_tlv.length = packet[1];
	next_tlv.value = malloc((next_tlv.length + 1) * sizeof(uint8_t));
	NULL_CHECK(next_tlv.value);
	NULL_CHECK(memcpy(next_tlv.value, &packet[2], next_tlv.length));
	return next_tlv;
}

struct tlv 
tlv_translate_bootp(uint8_t *packet)
{
	struct tlv next_tlv;
	next_tlv.type = packet[0];
	if (next_tlv.type == 255)
		return next_tlv;
	next_tlv.length = packet[1];
	next_tlv.value = malloc((next_tlv.length + 1) * sizeof(uint8_t));
	NULL_CHECK(next_tlv.value);
	NULL_CHECK(memcpy(next_tlv.value, &packet[2], next_tlv.length));
	return next_tlv;
}

void print_value_nb(uint length, u_char *value)
{
	u_char value_nb[sizeof(uint64_t)] = {0};
	for(uint i = 0; i < length; i++)
		value_nb[i] = value[length - i - 1];

	printf("%llu", *(unsigned long long *)value_nb);
}