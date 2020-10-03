#include <stdnoreturn.h>
#include "args.h"
#include "utilities.h"
#include "interfaces.h"

void parseArgs(int argc, char **argv, Options *options)
{
  if(argc < 7)
    printHelp();

  int opt= 0;
  options->interface = NULL;
  options->offline_file = NULL;
  options->filter_exp = NULL;
  options->verbose = 0;

  static struct option long_options[] =
  {
    {"interface",      required_argument, 0,  'i' },
    {"offline_file", required_argument, 0,  'o' },
    {"filter", required_argument, 0,  'f' },
    {"verbose", required_argument, 0,  'v' },
    {"help",   no_argument, 0,  'h' },
    {0, 0, 0, 0}
  };

  int long_index = 0;
  while ((opt = getopt_long_only(argc, argv,"",
                long_options, &long_index )) != -1)
  switch (opt)
  {
    case 'i':
      options->interface = optarg;
      break;
    case 'o':
      options->offline_file = optarg;
      break;
    case 'f':
      options->filter_exp = optarg;
      break;
    case 'v':
      options->verbose = atoi(optarg);
      break;
    case 'h':
    default:
      printHelp();
      exit(ERROR_ARGS);
  }

  if(options->interface == NULL ||
     options->offline_file == NULL ||
     options->verbose == 0)
  {
    printHelp();
    exit(ERROR_ARGS);
  }
}

noreturn void
printHelp(void) {
  fputs(
    "Usage:\n"
    "  ./bin/main: -i <interface> -v <int> -o <offline file> (-f <filter>)\n"
    "  -i interface_name     the name of the interface that will be listen\n"
    "  -f filter             the filter that will be used for package search\n"
    "  -v verbose            the level of details that will be printed\n"
    "                        (1,2 or 3)\n"
    "  -o offline_file       the file you want to read in offline mode\n"
    "  -h                    print help\n",
    stderr
  );
  print_all_interfaces();
  exit(ERROR_ARGS);
}
