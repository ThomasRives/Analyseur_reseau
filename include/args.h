#ifndef ARGS_H
#define ARGS_H

#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#define ERROR_ARGS 1

/**
 * Store the options of the users
 **/
typedef struct argsOptions
{
  char *interface;
  char *offline_file;
  char *filter_exp;
  int verbose;
} Options;

/**
 * Parse les arguments et vérifie quels
 * options ont été indiquées en ligne de commande.
 * argc : nombre d'arguments en ligne de commande
 * argv : tableau de char* contenant les options
**/
void parseArgs(int argc, char **argv, Options *options);

/**
 * Affiche l'aide pour utiliser le programme
**/
void printHelp(void);

#endif
