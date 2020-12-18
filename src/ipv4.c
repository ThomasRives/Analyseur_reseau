#include "ipv4.h"

void
ipv4_header_analyze(const u_char *packet, uint length)
{
	struct iphdr *ip_header = (struct iphdr *)packet;
	printf("IHL: %u bytes\n", ip_header->ihl*4);
	ipv4_tos(ip_header->tos);
	printf("Total length: %u\n", ntohs(ip_header->tot_len));
	printf("Packet's ID: 0x%x\n", ntohs(ip_header->id));
	ipv4_print_flags(ip_header->frag_off & IPV4_FLAGS);
	printf("Fragment offset: %u\n", ip_header->frag_off & IPV4_FRAG_OFF);
	printf("Time to live: %u\n", ip_header->ttl);
	printf("Checksum : 0x%x\n", ntohs(ip_header->check));
	printf("Source address : %s\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr));
	printf("Destination address: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->daddr));

	ipv4_demult_prot(packet + ip_header->ihl * 4,
					 length - ip_header->ihl * 4,
					 ip_header->protocol);
}

void
ipv4_tos(uint8_t tos)
{
	puts("Type of service:");
	switch((tos >> 5))
	{
		case IPV4_TOS_ROUTINE:
			puts("\tRoutine");
			break;
		case IPV4_TOS_PRIORITY:
			puts("\tPriority");
			break;
		case IPV4_TOS_IMMED:
			puts("\tImmediate");
			break;
		case IPV4_TOS_FLASH:
			puts("\tFlash");
			break;
		case IPV4_TOS_FLASH_OVER:
			puts("\tFlash Override");
			break;
		case IPV4_TOS_CRITICAL:
			puts("\tCritical");
			break;
		case IPV4_TOS_INTERNET_CTRL:
			puts("\tInternetwork Control");
			break;
		case IPV4_TOS_NETW_CTRL:
			puts("\tNetwork Control");
			break;
	}
	
	printf("\tDelay: ");
	if (tos & IPV4_DELAY)
		puts("Low");
	else
		puts("Normal");

	printf("\tThroughout: ");
	if (tos & IPV4_THRGPUT)
		puts("High");
	else
		puts("Normal");

	printf("\tReliability: ");
	if (tos & IPV4_RELIAB)
		puts("High");
	else
		puts("Normal");

	printf("\tCost: ");
	if (tos & IPV4_COST)
		puts("Low");
	else
		puts("Normal");
}

void
ipv4_print_flags(uint8_t flags)
{
	if (!(flags & IPV4_FLAG_DO_NOT_FRAG) &&
		!(flags & IPV4_FLAG_MORE_FRAG))
		return;

	puts("Flags:");
	if (flags & IPV4_FLAG_DO_NOT_FRAG)
		puts("\tDo not fragment");
	if (flags & IPV4_FLAG_MORE_FRAG)
		puts("\tMore fragment");
}

void
ipv4_demult_prot(const u_char *packet, uint len, uint8_t prot)
{
	printf("Protocol used: ");
	switch (prot) 
	{
		case IPPROTO_TCP:
			print_bg_green("TCP", 0);
			printf(" (%i)\n", prot);
			tcp_header_analyze(packet, len);
			break;
		case IPPROTO_UDP:
			print_bg_yellow("UDP", 0);
			printf(" (%i)\n", prot);
			udp_header_analyze(packet, len);
			break;
		case IPPROTO_ICMP:
			print_bg_red("ICMP", 0);
			printf(" (%i)\n", prot);
			icmp_header_analyze(packet);
			break;
		case IPPROTO_IPV6:
			print_bg_blue("IPv6", 0);
			printf(" (%i)\n", prot);
			break;
		case IPPROTO_SCTP:
			print_bg_purple("SCTP", 0);
			printf(" (%i)\n", prot);
			sctp_analayze(packet, len);
			break;
		default:
			puts("Not supported");
	}
}