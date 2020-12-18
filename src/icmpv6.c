#include "icmpv6.h"

void
icmpv6_header_analyze(const u_char *packet, uint length, int verbose)
{
	struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)packet;
	char buf_adr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, packet + sizeof(struct icmp6_hdr),
			  buf_adr, INET6_ADDRSTRLEN);
	if(verbose == 2)
	{
		printf("Target address: %s\n", buf_adr);
		return;
	}
	
	print_icmpv6_type_code(icmp6_header->icmp6_type, icmp6_header->icmp6_code);

	printf("Checksum: 0x%x\n", ntohs(icmp6_header->icmp6_cksum));
	printf("Target address: %s\n", buf_adr);
	uint bytes_read = sizeof(struct icmp6_hdr) + 16;
	printf("%x\n", ntohl(*(uint32_t *)packet + bytes_read));
	(void)length;
	// print_icmpv6_option(packet + bytes_read, length - bytes_read);
}

void
print_icmpv6_type_code(uint8_t type, uint8_t code)
{
	printf("Type: ");
	switch(type)
	{
		case ICMP6_DST_UNREACH:
			puts("Destination Unreachable");
			print_icmp6_dest_unreach_code(code);
			break;
		case ICMP6_PACKET_TOO_BIG:
			puts("Packet Too Big");
			printf("Code: %i\n", code);
			break;
		case ICMP6_TIME_EXCEEDED:
			puts("Time Exceeded");
			print_icmp6_time_exc_code(code);
			break;
		case ICMP6_PARAM_PROB:
			puts("Parameter Problem");
			print_icmpv6_par_prob_code(code);
			break;
		case ICMP6_ECHO_REPLY:
			puts("Echo Reply");
			break;
		case MLD_LISTENER_QUERY:
			puts("Multicast Listener Query");
			break;
		case MLD_LISTENER_REPORT:
			puts("Multicast Listener Report");
			break;
		case MLD_LISTENER_REDUCTION:
			puts("Multicast Listener Done");
			break;
		case ND_ROUTER_SOLICIT:
			puts("Router Solicitation");
			break;
		case ND_ROUTER_ADVERT:
			puts("Router Advertisement");
			break;
		case ND_NEIGHBOR_SOLICIT:
			puts("Neighbor Solicitation");
			break;
		case ND_NEIGHBOR_ADVERT:
			puts("Neighbor Advertisement");
			break;
		case ND_REDIRECT:
			puts("Redirect Message");
			break;
		case ICMP6_ROUTER_RENUMBERING:
			puts("Router Renumbering");
			print_icmpv6_rout_rem_code(code);
			break;
		default:
			puts("Unknown...");
	}
}

void
print_icmp6_dest_unreach_code(uint8_t code)
{
	printf("Code: ");
	switch (code)
	{
		case ICMP6_DST_UNREACH_NOROUTE:
			puts("No route to destination");
			break;
		case ICMP6_DST_UNREACH_ADMIN:
			puts("Communication with destination administratively prohibited");
			break;
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
			puts("Beyond scope of source address");
			break;
		case ICMP6_DST_UNREACH_ADDR:
			puts("Address unreachable");
			break;
		case ICMP6_DST_UNREACH_NOPORT:
			puts("Bad port");
			break;
		case ICMP6_SRC_ADDR_FAIL:
			puts("Source address failed ingress/egress policy");
			break;
		case ICMP6_REJ_ROUTE_DST:
			puts("Reject route to destination");
			break;
		case ICMP6_ERR_SRC_ROUT:
			puts("Error in Source Routing Header");
			break;
		case ICMP6_HEADER_TOO_LONG:
			puts("Headers too long");
			break;
		default:
			puts("Unknown...");
	}
}

void
print_icmp6_time_exc_code(uint8_t code)
{
	printf("Code :");
	switch (code)
	{
		case ICMP6_TIME_EXCEED_TRANSIT:
			puts("Hop limit exceeded in transit");
			break;
		case ICMP6_TIME_EXCEED_REASSEMBLY:
			puts("Fragment reassembly time exceeded");
			break;
		default:
			puts("Unknown...");
	}
}

void
print_icmpv6_par_prob_code(uint8_t code)
{
	printf("Code: ");
	switch (code)
	{
		case ICMP6_PARAMPROB_HEADER:
			puts("Erroneous header field encountered");
			break;
		case ICMP6_PARAMPROB_NEXTHEADER:
			puts("Unrecognized Next Header type encountered");
			break;
		case ICMP6_PARAMPROB_OPTION:
			puts("Unrecognized IPv6 option");
			break;
		case ICMP6_PARAMPROB_INC:
			puts("IPv6 First Fragment has incomplete IPv6 Header Chain");
			break;
		case ICMP6_PARAMPROB_UP_LAY:
			puts("SR Upper-layer Header Error");
			break;
		case ICMP6_PARAMPROB_UNREC_NXT_HEAD:
			puts("Unrecognized Next Header type encountered by intermediate node");
			break;
		case ICMP6_PARAMPROB_EXT_TOO_BIG:
			puts("Extension header too big");
			break;
		case ICMP6_PARAMPROB_EXT_CHAIN_TL:
			puts("Extension header chain too long");
			break;
		case ICMP6_PARAMPROB_TOO_MNY_EXT:
			puts("Too many extension headers");
			break;
		case ICMP6_PARAMPROB_TOO_MNY_OPT:
			puts("Too many options in extension header");
			break;
		case ICMP6_PARAMPROB_OPT_TOO_BIG:
			puts("Option too big");
			break;
		default:
			puts("Unknown...");
	}
}

void
print_icmpv6_rout_rem_code(uint8_t code)
{
	printf("Code: ");
	switch (code)
	{
		case ICMP6_ROUTREM_RENUMB_COMM:
			puts("Router Renumbering Command");
			break;
		case ICMP6_ROUTREM_RENUMB_RES:
			puts("Router Renumbering Result");
			break;
		case ICMP6_ROUTREM_SEQ_NUM_RES:
			puts("Sequence Number Reset");
			break;
		default:
			puts("Unknown...");
	}
}

void
print_icmpv6_option(const u_char *packet, uint length)
{
	puts("ICMPv6 options:");
	for(uint i = 0; i < length;)
	{
		struct tlv next_tlv = tlv_translate_icmpv6(packet + i);
		switch (next_tlv.type)
		{
			case ND_OPT_SOURCE_LINKADDR:
				// puts("");
				break;
			case ND_OPT_TARGET_LINKADDR:
				// puts("");
				break;
			case ND_OPT_PREFIX_INFORMATION:
				// puts("");
				break;
			case ND_OPT_REDIRECTED_HEADER:
				// puts("");
				break;
			case ND_OPT_MTU:
				// puts("");
				break;
			case ND_OPT_RTR_ADV_INTERVAL:
				// puts("");
				break;
			case ND_OPT_HOME_AGENT_INFO:
				// puts("");
				break;
		}
		i += next_tlv.length;
		free(next_tlv.value);
	}
}