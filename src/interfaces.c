#include "interfaces.h"

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
    printf("Interface found %s !\n", temp->name);
  else
    err_n_die(0, "Interface not found...\n");
  return temp;
}

void
print_all_interfaces(void)
{
  char error[PCAP_ERRBUF_SIZE];
  pcap_if_t *interfaces,*temp;
  int i = 0;
  CHECK(pcap_findalldevs(&interfaces,error));

  printf("\nThe interfaces present on the system are:");
  for(temp = interfaces; temp; temp = temp->next)
  {
    printf("\n%d  :  %s",i++,temp->name);
  }
  printf("\nPlease peak one of those when you run the programm\n");
}
