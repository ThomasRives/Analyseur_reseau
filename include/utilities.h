#ifndef UTILITIES_H
#define UTILITIES_H

#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>

#define NULL_CHECK(op) do{if((op) == NULL) err_n_die(1, #op);}while(0)
#define CHECK(op) do{if((op) == -1) err_n_die(1, #op);}while(0)

/**
 * @brief If an error occur, the programm will stop and print an error message.
 *
 * @param syserr: indicates if "perror" should be called.
 * @param msg: the message that will be printed.
 */
noreturn void err_n_die(int syserr, const char *msg, ...);

#endif //UTILITIES_H
