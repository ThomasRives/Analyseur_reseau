#include "args.h"
#include "utilities.h"

void parseArgs(int argc, char **argv, Options *options)
{
  if(argc < 7)
    err_n_die(0, "Usage: %s: -i <interface name> -v <int> -o <offline file>"
    " (-f <filter>)", argv[0]);

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

void printHelp(void) {
  fputs(
    "Usage : \n"
    "  -data DOSSIER         chemin vers le dossier contenant les fichiers\n"
    "                        RATP\n"
    "  -req FICHIER          chemin vers le fichier contenant les requetes\n"
    "  -itinerary            affiche l'itinéraire au format long\n"
    "  -help                 affiche l'usage\n",
    stderr
  );
  exit(ERROR_ARGS);
}
