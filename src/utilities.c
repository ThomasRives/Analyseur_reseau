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
	u_char *content = malloc(sizeof(u_char) * (length + 1));
	NULL_CHECK(content);
	NULL_CHECK(memcpy(content, data, length));
	content[length] = '\0';
	printf("%s", content);
	free(content);
}