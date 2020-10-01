#include "analyze_packet.h"

/**
 * @param args: args supp mais pr nous NULL;
 * @param header: ptr vers les info du packet
 * @param packet: début du packet.
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  (void)args;
  static int nb_pack = 0;
  nb_pack++;
  uint16_t *two_oct_packet = (uint16_t *)packet;

  printf("___Packet number %i___\n", nb_pack);
  printf("Packet's length: %i\n\n", header->len);

  for(unsigned int i = 0; i < header->len; i++, two_oct_packet++)
  {
    if(i%8 == 0)
      printf("\n");
    printf("%.4x ", *two_oct_packet);
  }

  printf("\n\n");
  fflush(stdout);
}
