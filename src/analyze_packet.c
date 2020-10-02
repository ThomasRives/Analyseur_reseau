#include "analyze_packet.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  (void)args;
  print_packet(header->len, (uint16_t *)packet);
  struct ether_header *eth_header = (struct ether_header *)packet;
  printf("destination: %s\n", eth_header->ether_dhost);
  printf("source: %s\n", eth_header->ether_shost);
  printf("type: %i\n", eth_header->ether_type);

  switch(eth_header->ether_type)
  {
    case ETHERTYPE_IPV6:
      printf("protocole IPV6\n");
      break;
    case ETHERTYPE_IP:
      printf("protocole IPV6\n");
      break;
    case ETHERTYPE_ARP:
      printf("protocol ARP\n");
      break;
    // case ETHERTYPE_RARP:
    //   printf("protocol RARP\n");
    //   break;
  }

}

void
print_packet(uint pack_length, uint16_t *packet)
{
  static int nb_pack = 0;
  nb_pack++;

  printf("___Packet number %i___\n", nb_pack);
  printf("Packet's length: %i\n\n", pack_length);

  for(unsigned int i = 0; i < pack_length; i++, packet++)
  {
    if(i%8 == 0)
      printf("\n");
    printf("%.4x ", *packet);
  }

  printf("\n\n");
  fflush(stdout);
}
