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

void
print_hms(char *msg, uint time)
{
	printf("%s %us", msg, time);
	uint days = time / 86400;
	time = time % 86400;
	uint hours = time / 3600;
	time = time % 3600;
	uint mins = time / 60;
	uint secs = time % 60;

	if(days > 0)
	{
		printf("(%u day", days);
		if(days > 1)
			printf("s");
		if(hours == 0 && mins == 0 && secs == 0)
		{
			puts(")");
			return;
		}
		printf(", ");
	}

	if(days == 0 && hours != 0)
		printf("(");

	if(hours > 0)
	{
		printf("%u hour", hours);

		if(hours > 1)
			printf("s");
		if (mins == 0 && secs == 0)
		{
			puts(")");
			return;
		}
		printf(", ");
	}

	if (days == 0 && hours == 0 && mins != 0)
		printf("(");
	
	if(mins > 0)
	{
		printf("%u minute", mins);
		if(mins > 1)
			printf("s");
		if (secs == 0)
		{
			puts(")");
			return;
		}
		printf(", ");
	}

	if (days == 0 && hours == 0 && mins == 0 && secs != 0)
		printf("(");

	if (secs > 1)
		printf("%u secondes)\n", secs);
	else
		printf("%u seconde)\n", secs);
}