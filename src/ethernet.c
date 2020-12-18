#include "ethernet.h"
#include "network_layout.h"

void
analyze_ethernet_hearder(const u_char *packet, uint len, int verbose)
{
	puts("\n");
	struct ether_header *eth_header = (struct ether_header *)packet;
	if(verbose == 1)
	{
		print_bg_red("Ethernet", 0);
		printf(" ");
	}
	else if(verbose == 2)
	{
		print_bg_red("Ethernet\t", 0);
		printf("destination host : %s\t",
			   ether_ntoa((const struct ether_addr *)eth_header->ether_dhost));
		printf("source host: %s\n",
			   ether_ntoa((const struct ether_addr *)eth_header->ether_shost));
	}
	else if(verbose == 3)
	{
		printf("Protocol: ");
		print_bg_red("Ethernet", 1);
		printf("destination host : %s\n",
			ether_ntoa((const struct ether_addr *)eth_header->ether_dhost));
		printf("source host: %s\n",
			ether_ntoa((const struct ether_addr *)eth_header->ether_shost));
		puts("");
	}

	ethernet_demult_prot(packet + sizeof(struct ether_header),
						 len - sizeof(struct ether_header),
						 ntohs(eth_header->ether_type),
						 verbose);
}

void ethernet_demult_prot(const u_char *packet, uint len, uint16_t prot, 
	int verbose)
{
	if(verbose == 3)
		printf("Protocole: ");
	switch(prot)
	{
		case ETHERTYPE_IPV6:
			if(verbose == 1)
			{
				print_bg_blue("IPV6", 0);
				printf(" ");
			}
			else if(verbose == 2)
			{
				print_bg_blue("IPV6", 0);
				printf("\t");
			}
			else
				print_bg_blue("IPV6", 1);
			ipv6_header_analyze(packet, len, verbose);
			break;
		case ETHERTYPE_IP:
			if (verbose == 1)
			{
				print_bg_green("IPV4", 0);
				printf(" ");
			}
			else if (verbose == 2)
			{
				print_bg_green("IPV4", 0);
				printf("\t");
			}
			else
				print_bg_green("IPV4", 1);
			ipv4_header_analyze(packet, len, verbose);
			break;
		case ETHERTYPE_ARP:
			if (verbose == 1)
			{
				print_bg_cyan("ARP", 0);
				printf(" ");
			}
			else if (verbose == 2)
			{
				print_bg_cyan("ARP", 0);
				printf("\t");
			}
			else
				print_bg_cyan("ARP", 1);
			arp_header_analyze(packet, verbose);
			break;
		case ETHERTYPE_REVARP:
			if (verbose == 1)
			{
				print_bg_cyan("RARP", 0);
				printf(" ");
			}
			else if (verbose == 2)
			{
				print_bg_cyan("RARP", 0);
				printf("\t");
			}
			else
				print_bg_cyan("RARP", 1);
			rarp_header_analyze(packet, verbose);
			break;
		default:
			puts("Unknown type...");
	}
}
