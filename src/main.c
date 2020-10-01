#include <pcap.h>
#include "args.h"
#include "utilities.h"

int
main(int argc, char *argv[])
{
  Options options;
  parseArgs(argc,argv, &options);

  char error[PCAP_ERRBUF_SIZE];
  pcap_if_t *interfaces,*temp;
  int i=0;
  CHECK(pcap_findalldevs(&interfaces,error));

  printf("\n the interfaces present on the system are:");
  for(temp=interfaces;temp;temp=temp->next)
  {
      printf("\n%d  :  %s",i++,temp->name);
  }
  printf("\n");

  return 0;
}
