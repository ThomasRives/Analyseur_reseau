#include <pcap.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "args.h"
#include "utilities.h"
#include "interfaces.h"
#include "analyze_packet.h"


int
main(int argc, char *argv[])
{
	Options options;
	pcap_if_t * interface;
	pcap_t *read_on;
	bpf_u_int32 network_mask, network_number;
	struct bpf_program filterprog;
	char error[PCAP_ERRBUF_SIZE];
	parseArgs(argc,argv, &options);
	interface = get_selected_interface(options.interface);

	CHECK(pcap_lookupnet(options.interface, &network_number, &network_mask, error));

	if (options.offline_file != NULL)
		NULL_CHECK(read_on = pcap_open_offline(options.offline_file, error));
	else
		NULL_CHECK(read_on = pcap_open_live(interface->name, BUFSIZ,
											0, 10000, error)
				  );

	if (options.filter_exp)
	{
		CHECK(pcap_compile(read_on, &filterprog, options.filter_exp, 0, network_mask));
		CHECK(pcap_setfilter(read_on, &filterprog));
	}

	pcap_loop(read_on, 0, got_packet, (u_char *)&options);

	if (options.filter_exp)
		pcap_freecode(&filterprog);
		
	pcap_close(read_on);
	free(interface);
	free_args(options);
	return 0;
}
