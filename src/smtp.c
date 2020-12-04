#include "smtp.h"

void
smtp_analyze(const u_char *packet, uint length)
{
	printf_as_str(packet, length);
	puts("");
}