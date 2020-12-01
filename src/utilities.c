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
printf_as_str(const u_char *data, uint length)
{
	printf("%.*s", length, data);
}

void
print_with_s(int numb, char* str)
{
	if(numb > 1)
		printf(" (%u %ss)\n", numb, str);
	else
		printf(" (%u %s)\n", numb, str);
}