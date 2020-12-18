#include <stdio.h>
#include "color.h"

void
print_b_blue(char *txt, int new_line)
{
	printf(B_BLUE "%s" COLOR_OFF, txt);
	if(new_line)
		puts("");
}

void
print_bg_red(char *txt, int new_line)
{
	printf(BG_RED "%s" COLOR_BG_OFF, txt);
	if(new_line)
		puts("");
}

void
print_bg_green(char *txt, int new_line)
{
	printf(BG_GREEN "%s" COLOR_BG_OFF, txt);
	if(new_line)
		puts("");
}

void
print_bg_yellow(char *txt, int new_line)
{
	printf(BG_YELLOW "%s" COLOR_BG_OFF, txt);
	if(new_line)
		puts("");
}

void
print_bg_blue(char *txt, int new_line)
{
	printf(BG_BLUE "%s" COLOR_BG_OFF, txt);
	if(new_line)
		puts("");
}

void
print_bg_purple(char *txt, int new_line)
{
	printf(BG_PURPLE "%s" COLOR_BG_OFF, txt);
	if(new_line)
		puts("");
}

void
print_bg_cyan(char *txt, int new_line)
{
	printf(BG_CYAN "%s" COLOR_BG_OFF, txt);
	if(new_line)
		puts("");
}

void
print_bg_white(char *txt, int new_line)
{
	printf(BG_WHITE "%s" COLOR_BG_OFF, txt);
	if(new_line)
		puts("");
}

void
print_i_bg_black(char *txt, int new_line)
{
	printf(BG_I_BLACK WHITE "%s" COLOR_BG_OFF COLOR_OFF, txt);
	if(new_line)
		puts("");
}

void
print_i_bg_red(char *txt, int new_line)
{
	printf(BG_I_RED "%s" COLOR_BG_OFF, txt);
	if(new_line)
		puts("");
}

void
print_i_bg_green(char *txt, int new_line)
{
	printf(BG_I_GREEN "%s" COLOR_BG_OFF, txt);
	if(new_line)
		puts("");
}

void
print_i_bg_yellow(char *txt, int new_line)
{
	printf(BG_I_YELLOW "%s" COLOR_BG_OFF, txt);
	if(new_line)
		puts("");
}

void
print_i_bg_blue(char *txt, int new_line)
{
	printf(BG_I_BLUE "%s" COLOR_BG_OFF, txt);
	if(new_line)
		puts("");
}

void
print_i_bg_purple(char *txt, int new_line)
{
	printf(BG_I_PURPLE "%s" COLOR_BG_OFF, txt);
	if(new_line)
		puts("");
}

void
print_i_bg_cyan(char *txt, int new_line)
{
	printf(BG_I_CYAN "%s" COLOR_BG_OFF, txt);
	if(new_line)
		puts("");
}

void
print_b_green(char *txt, int new_line)
{
	printf(B_GREEN "%s" COLOR_OFF, txt);
	if(new_line)
		puts("");
}