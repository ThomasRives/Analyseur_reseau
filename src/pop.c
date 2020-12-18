#include "pop.h"

void
pop_analyze(const u_char *packet, uint length)
{
	print_as_str(packet, length);
	puts("");
}