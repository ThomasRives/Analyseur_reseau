#include <stdnoreturn.h>
#include "args.h"
#include "utilities.h"
#include "interfaces.h"

void parseArgs(int argc, char **argv, Options *options)
{
	int opt= 0;
	options->interface = NULL;
	options->offline_file = NULL;
	options->filter_exp = NULL;
	options->verbose = 0;

	static struct option long_options[] =
	{
		{"interface",    required_argument, 0,  'i' },
		{"offline_file", required_argument, 0,  'o' },
		{"filter",       required_argument, 0,  'f' },
		{"verbose",      required_argument, 0,  'v' },
		{"usable",   no_argument, 0,  'u' },
		{"help",         no_argument, 0,  'h' },
		{0, 0, 0, 0}
	};

	int long_index = 0;
	size_t len_optarg;
	while ((opt = getopt_long_only(argc, argv,"",
				long_options, &long_index )) != -1)
		switch (opt)
		{
			case 'i':
				len_optarg = strlen(optarg);
				options->interface = calloc(len_optarg + 1, sizeof(char));
				memcpy(options->interface, optarg, len_optarg);
				break;
			case 'o':
				len_optarg = strlen(optarg);
				options->offline_file = calloc(len_optarg + 1, sizeof(char));
				memcpy(options->offline_file, optarg, len_optarg);
				break;
			case 'f':
				fflush(stdout);
				len_optarg = strlen(optarg);
				options->filter_exp = calloc(len_optarg + 1, sizeof(char));
				memcpy(options->filter_exp, optarg, len_optarg);
				break;
			case 'v':
				options->verbose = atoi(optarg);
				break;
			case 'u':
				print_all_interfaces();
				exit(ERROR_ARGS);
			case 'h':
			default:
				printHelp();
				exit(ERROR_ARGS);
		}

	if (options->offline_file == NULL && options->interface == NULL)
	{
		fprintf(stderr, 
			"If you are using the online mode, an interface is required.");
		printHelp();
		exit(ERROR_ARGS);
	}

	if(options->verbose < 1 || options->verbose > 3)
	{
		printHelp();
		exit(ERROR_ARGS);
	}
}

noreturn void
printHelp(void) {
	fputs(
	"Usage:\n"
	"  ./bin/main: -i <interface> -v <int> (-o <offline file> -f <filter>)\n"
	"  -i interface_name     the name of the interface that will be listen\n"
	"  -f filter             the filter that will be used for package search\n"
	"  -v verbose            the level of details that will be printed\n"
	"                        (1,2 or 3)\n"
	"  -o offline_file       the file you want to read in offline mode\n"
	"  -h                    print help\n",
	stderr
	);
	exit(ERROR_ARGS);
}

void
free_args(Options options)
{
	if(options.interface)
		free(options.interface);

	if(options.offline_file)
		free(options.offline_file);

	if(options.filter_exp)
		free(options.filter_exp);
}
