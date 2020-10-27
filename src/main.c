#include <pcap.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "args.h"
#include "utilities.h"
#include "interfaces.h"
#include "analyze_packet.h"


extern char *error;

int
main(int argc, char *argv[])
{
	Options options;
	pcap_if_t * interface;
	pcap_t *read_on;
	parseArgs(argc,argv, &options);
	interface = get_selected_interface(options.interface);

	if(options.offline_file != NULL)
		NULL_CHECK(read_on = pcap_open_offline(options.offline_file, error));
	else
		NULL_CHECK(read_on = pcap_open_live(interface->name,
											BUFSIZ,
											0,
											10000,
											error));
											
	pcap_loop(read_on, 0, got_packet, NULL);

	pcap_close(read_on);
	return 0;
}
