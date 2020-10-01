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
  pcap_t *off_file;
  parseArgs(argc,argv, &options);
  print_all_interfaces();

  interface = get_selected_interface(options.interface);

  NULL_CHECK(off_file = pcap_open_live(interface->name,
                                       BUFSIZ,
                                       0,
                                       10000,
                                       error));

  pcap_loop(off_file, 0, got_packet, NULL);

  pcap_close(off_file);
  return 0;
}
