#include "interfaces.h"

#define ERROR_INTERFACE 2

void
check_selected_interface(const char *interface_name)
{
    char error[PCAP_ERRBUF_SIZE];

    pcap_if_t *interfaces, *temp;
    CHECK(pcap_findalldevs(&interfaces,error));
    temp = interfaces;

    while(temp != NULL && strcmp(interface_name, temp->name) != 0)
        temp = temp->next;

    if(temp != NULL)
    {
        printf("Interface found %s !\n", interface_name);
    }
    else
    {
        fprintf(stderr, "Interface not found...\n");
        print_all_interfaces();
        pcap_freealldevs(interfaces);
        exit(ERROR_INTERFACE);
    }
    pcap_freealldevs(interfaces);
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
    printf("\nPlease peak one of those when you run the program\n");
    pcap_freealldevs(interfaces);
}
