#include <pcap.h>
#include "args.h"
#include "utilities.h"
#include <string.h>
 #include <sys/types.h>
 #include <sys/stat.h>
 #include <fcntl.h>

 char error[PCAP_ERRBUF_SIZE];

pcap_if_t *
get_selected_interface(const char *interface_name)
{
  pcap_if_t *interfaces,*temp;
  CHECK(pcap_findalldevs(&interfaces,error));
  temp = interfaces;

  while(temp != NULL && strcmp(interface_name, temp->name) != 0)
    temp = temp->next;

  if(temp != NULL)
    printf("Interface found !\n");
  else
    err_n_die(0, "Interface not found...\n");
  return temp;
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  
}

void
print_all_interfaces(void)
{
  char error[PCAP_ERRBUF_SIZE];
  pcap_if_t *interfaces,*temp;
  int i = 0;
  CHECK(pcap_findalldevs(&interfaces,error));

  printf("\n the interfaces present on the system are:");
  for(temp = interfaces; temp; temp = temp->next)
  {
    printf("\n%d  :  %s",i++,temp->name);
  }
  printf("\n");
}

int
main(int argc, char *argv[])
{
  Options options;
  pcap_if_t * interface;
  pcap_t *off_file;
  parseArgs(argc,argv, &options);
  //print_all_interfaces();

  interface = get_selected_interface(options.interface);
  (void)interface;


  NULL_CHECK(off_file = pcap_open_live(
                                       interface->name,
                                       BUFSIZ,
                                       0,
                                       10000,
                                       error));

  pcap_loop(off_file, -1, got_packet, NULL);

  pcap_close(off_file);
  return 0;
}
