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
#include <arpa/inet.h>
#include "color.h"

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
 * @brief Print the content in hexa.
 * 
 * @param data: the data to print.
 * @param length: the length of the data.
 */
void print_hex(const u_char *data, uint length);

/**
 * @brief print the datas as a string.
 * 
 * @param data: the data to print.
 * @param length: the length of the data to print.
 */
void print_as_str(const u_char *data, uint length);

/**
 * @brief print a message with or without an "s" depending on the number given.
 * 
 * @param numb: the number that will decide if an "s" will be printed.
 * @param str: the str without an "s".
 */
void print_with_s(int numb, char *str);

/**
 * @brief Print the given time (in s) as (x hour(s), y minute(s), z seconde(s)).
 * 
 * @param msg: message to print before the translation.
 * @param time: time to translate in secondes.
 */
void print_hms(char *msg, uint time);

#endif //UTILITIES_H
