#include "utilities.h"

noreturn void
err_n_die(int syserr, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	fprintf(stderr, "\n");
	va_end(ap);

	if (syserr == 1)
		perror("");

	exit(EXIT_FAILURE);
}

void
print_hex(const u_char *data, uint length)
{
	for(uint i = 0; i < length; i++)
		printf("%x", *(data + i));
	puts("");
}

void
print_as_str(const u_char *data, uint length)
{
	for (uint i = 0; i < length; i++)
		switch(data[i])
		{
			case '\r':
				printf("\\r");
				break;
			case '\n':
				printf("\\n\n");
				break;
			default:
				printf("%c", data[i]);
				break;
		}
}
void
print_with_s(int numb, char* str)
{
	if(numb > 1)
		printf(" (%u %ss)\n", numb, str);
	else
		printf(" (%u %s)\n", numb, str);
}