#ifndef UTILITIES_H
#define UTILITIES_H

#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#define NULL_CHECK(op) do{if((op) == NULL) err_n_die(1, #op);}while(0)
#define CHECK(op) do{if((op) == -1) err_n_die(1, #op);}while(0)

/**
 * @brief If an error occur, the programm will stop and print an error message.
 *
 * @param syserr: indicates if "perror" should be called.
 * @param msg: the message that will be printed.
 */
noreturn void err_n_die(int syserr, const char *msg, ...);

/**
 * @brief print the datas as a string.
 * 
 * @param data: the data to print.
 * @param length: the length of the data to print.
 */
void printf_as_str(const u_char *data, uint length);

/**
 * @brief print a message with or without an "s" depending on the number given.
 * 
 * @param numb: the number that will decide if an "s" will be printed.
 * @param str: the str without an "s".
 */
void print_with_s(int numb, char *str);

#endif //UTILITIES_H
