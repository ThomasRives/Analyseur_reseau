#ifndef ARGS_H
#define ARGS_H

#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#define ERROR_ARGS 1

/**
 * @brief Struct to store the user's options.
 */
typedef struct argsOptions
{
  char *interface;
  char *offline_file;
  char *filter_exp;
  int verbose;
} Options;

/**
 * @brief Parse the arguments given in command line.
 *
 * It also check if all the required arguments are given, if not, the programm
 * will stop and print the help.
 *
 * @param argc: the number of arguments.
 * @param argv: the arguments given by the users.
 * @param options: the structur that will store the arguments given.
 */
void parseArgs(int argc, char **argv, Options *options);

/**
 * @brief Print help and all interfaces found on the device.
 */
void printHelp(void);

#endif
