#include "bootp.h"

void
bootp_analyze(const u_char *packet)
{
	struct bootphdr *btphdr = (struct bootphdr *)packet;

	bootp_print_op(btphdr->op);
	bootp_print_htype(btphdr->htype);
	bootp_print_hlen(btphdr->hlen);
	printf("Hop count: %u\n", btphdr->hops);
	printf("Transaction ID: 0x%x\n", ntohl(btphdr->xid));
	printf("Seconds elapsed: %u\n", ntohs(btphdr->secs));
	printf("Client IP address: %s\n", inet_ntoa(btphdr->ciaddr));
	printf("Your IP address: %s\n", inet_ntoa(btphdr->yiaddr));
	printf("Server IP address: %s\n", inet_ntoa(btphdr->siaddr));
	printf("Gateway IP address: %s\n", inet_ntoa(btphdr->giaddr));
	bootp_print_chaddr(btphdr->chaddr, btphdr->hlen);
	printf("Server name: ");
	bootp_print_str(btphdr->sname, sizeof(btphdr->sname));
	printf("File name: ");
	bootp_print_str(btphdr->file, sizeof(btphdr->file));
	bootp_print_vendor(&btphdr->vend);
}

void
bootp_print_op(uint8_t op)
{
	printf("Operation: ");
	switch (op)
	{
		case BOOTREQUEST:
			puts("Request (1)");
			break;
		case BOOTREPLY:
			puts("Reply (2)");
			break;
		default:
			puts("Unknown...");
	}
}

void
bootp_print_htype(uint8_t htype)
{
	printf("Hardware type: ");
	switch (htype)
	{
		case HTYPE_ETHERNET:
			puts("Ethernet (1)");
			break;
		case HTYPE_EXP_ETHERNET:
			puts("Experimental Ethernet (2)");
			break;
		case HTYPE_IEEE802:
			puts("IEEE802 (6)");
			break;
		case HTYPE_ARCNET:
			puts("ARCnet (7)");
			break;
		default:
			puts("Unknown...");
	}
}

void
bootp_print_hlen(uint8_t hlen)
{
	printf("Hardware address length: %u", hlen);
	if (hlen == 6)
		printf(" (Ethernet)\n");
	else
		puts("");
}

void
bootp_print_chaddr(u_char *chaddr, uint8_t hlen)
{
	printf("Client address: ");
	if (hlen == 6)
		printf("%s (Ethernet)\n",
			   ether_ntoa((const struct ether_addr *)chaddr));
	else
	{
		printf("0x");
		for(uint i = 0; i < hlen; i++)
			printf("%x", *(chaddr + i));
		puts("");
	}
}

void
bootp_print_str(u_char *str, uint length)
{
	printf("%.*s", length, str);

	if (*str == '\0')
		printf("Unknown");
	puts("");
}

void
bootp_print_vendor(u_char *vend)
{
	if (ntohl(*(uint32_t *)vend) != MAGIC_COOKIE)
	{
		puts("No magic cookie");
		return;
	}
	
	vend += sizeof(uint32_t);
	puts("Options:");
	for (;;)
	{
		struct tlv next_opt = tlv_translate_bootp(vend);
		
		if(bootp_print_opt_tlv(next_opt) == END_OPT)
			return;

		vend += next_opt.length + 2 * sizeof(uint8_t);
		free(next_opt.value);
	}
}

int
bootp_print_opt_tlv(struct tlv opt)
{
	printf("\tType: %i\n", opt.type);
	if (opt.type == OPT_END)
	{
		puts("\tEnd of options");
		return END_OPT;
	}
	printf("\t\tLength: %i\n\t\t", opt.length);
	switch (opt.type)
	{
		case OPT_PAD:
			puts("Option pad");
			break;
		case OPT_SUBNET_MASK:
			printf("Subnet Mask: %s\n", inet_ntoa(*(struct in_addr *)opt.value));
			break;
		case OPT_TIME_OFFSET:
			printf("Time offset: ");
			print_value_nb(opt.length, opt.value);
			printf("s\n");
			break;
		case OPT_GATEWAY:
			printf("Gateway: %s\n",
				inet_ntoa(*(struct in_addr *)opt.value));
			break;
		case OPT_TIME_SERVER:
			puts("Time server:");
			bootp_print_opt_lip(opt.value, opt.length);
			break;
		case OPT_DOMAIN_SERVER:
			puts("List of Domain Name System:");
			bootp_print_opt_lip(opt.value, opt.length);
			break;
		case OPT_HOSTNAME:
			printf("Hostname: ");
			for (uint i = 0; i < opt.length; i++)
				printf("%c", opt.value[i]);
			puts("");
			break;
		case OPT_DOMAIN_NAME:
			puts("Domain name: ");
			for (uint i = 0; i < opt.length; i++)
				printf("%c", opt.value[i]);
			puts("");
			break;
		case OPT_BROADCAST_ADDR:
			printf("Broadcast address: %s\n",
				inet_ntoa(*(struct in_addr *)opt.value));
			break;
		case OPT_MTU_INT:
			printf("MTU Interface: ");
			print_value_nb(opt.length, opt.value);
			puts("");
			break;
		case OPT_NETBIOS_NS:
			printf("Netbios Name server: %s\n",
				inet_ntoa(*(struct in_addr *)opt.value));
			break;
		case OPT_NETBIOS_SCOPE:
			printf("Netbios Scope: ");
			for (uint i = 0; i < opt.length; i++)
				printf("%c", opt.value[i]);
			puts("");
			break;
		case OPT_REQ_IP_ADDR:
			printf("Request IP address: %s\n",
				inet_ntoa(*(struct in_addr *)opt.value));
			break;
		case OPT_LEASE_TIME:
			printf("IP lease time: ");
			print_value_nb(opt.length, opt.value);
			puts("s");
			break;
		case OPT_DHCP_TYPE:
			bootp_print_dhcp_type(*(uint8_t *)opt.value);
			break;
		case OPT_SERV_ID:
			printf("Server ID: %s\n",
				inet_ntoa(*(struct in_addr *)opt.value));
			break;
		case OPT_PARAM_REQ_LIST:
			bootp_print_par_list(opt.length, opt.value);
			break;
		case OPT_MAX_MSG_SIZE:
			printf("DHCP Max message size: ");
			print_value_nb(opt.length, opt.value);
			puts("");
			break;
		case OPT_RENEWAL_TIME:
			printf("Renwal time: ");
			print_value_nb(opt.length, opt.value);
			puts("");
			break;
		case OPT_REBINDING_TIME:
			printf("Rebinding time: ");
			print_value_nb(opt.length, opt.value);
			puts("");
			break;
		case OPT_CLIENT_ID:
			printf("client ID : ");
			for (uint i = 0; i < opt.length; i++)
				printf("%c", opt.value[i]);
			puts("");
			break;
		case OPT_TFTP_SN:
			printf("TFTP Serveur name: %.*s\n", 
				opt.length, opt.value);
			break;
		case OPT_CLIENT_FQDN:
			printf("Client FQDN: ");
			for (uint i = 0; i < opt.length; i++)
				printf("%c", opt.value[i]);
			puts("");
			break;
		default:
			puts("Unknown...");
	}
	return NOT_END_OPT;
}

void
bootp_print_opt_lip(u_char *value, uint length)
{
	for (uint i = 0; i < length; i += sizeof(struct in_addr))
		printf("\t\t\t%s\n",
			inet_ntoa(*(struct in_addr *)(value + i)));
}

void
bootp_print_dhcp_type(uint type)
{
	printf("DHCP message type: ");
	switch (type)
	{
		case MSG_DISCOVER:
			puts("Discover (1)");
			break;
		case MSG_OFFER:
			puts("Offer (2)");
			break;
		case MSG_REQUEST:
			puts("Request (3)");
			break;
		case MSG_DECLINE:
			puts("Decline (4)");
			break;
		case MSG_ACK:
			puts("Ack (5)");
			break;
		case MSG_NACK:
			puts("Nack (6)");
			break;
		case MSG_RELEASE:
			puts("Release (7)");
			break;
		default:
			puts("Unknown...");
	}
}

void
bootp_print_par_list(uint length, u_char *value)
{
	printf("Parameters Request list:\n\t\t");
	for (uint i = 0; i < length; i++)
	{
		switch (value[i])
		{
			case OPT_PAD:
				printf("Option pad");
				break;
			case OPT_SUBNET_MASK:
				printf("Netmask");
				break;
			case OPT_TIME_OFFSET:
				printf("Time offset");
				break;
			case OPT_GATEWAY:
				printf("Gateway");
				break;
			case OPT_TIME_SERVER:
				printf("Time server");
				break;
			case OPT_DOMAIN_SERVER:
				printf("List of Domain Name System");
				break;
			case OPT_HOSTNAME:
				printf("Hostname");
				break;
			case OPT_DOMAIN_NAME:
				puts("Domain name");
				break;
			case OPT_BROADCAST_ADDR:
				printf("Broadcast address");
				break;
			case OPT_MTU_INT:
				printf("MTU Interface");
				break;
			case OPT_NETBIOS_NS:
				printf("Netbios Name server");
				break;
			case OPT_NETBIOS_SCOPE:
				printf("Netbios Scope");
				break;
			case OPT_REQ_IP_ADDR:
				printf("Request IP address");
				break;
			case OPT_LEASE_TIME:
				printf("IP lease time");
				break;
			case OPT_DHCP_TYPE:
				printf("DHCP type");
				break;
			case OPT_SERV_ID:
				printf("Server ID");
				break;
			case OPT_PARAM_REQ_LIST:
				printf("Parameters request list");
				break;
			case OPT_MAX_MSG_SIZE:
				printf("DHCP Max message size");
				break;
			case OPT_RENEWAL_TIME:
				printf("Renwal time");
				break;
			case OPT_REBINDING_TIME:
				printf("Rebinding time");
				break;
			case OPT_CLIENT_ID:
				puts("Client ID");
				break;
			case OPT_CLIENT_FQDN:
				printf("Client FQDN");
				break;
			default:
				printf("Unknown...");
		}
		printf(" (%u)\n\t\t", i);
	}
}