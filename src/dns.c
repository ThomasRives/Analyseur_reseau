#include "dns.h"


void
printf_dns_ctrl(uint16_t ctrl)
{
	ctrl = ntohs(ctrl);
	if((ctrl & QR) == QR_QUERY)
		puts("Type: Query");
	else
		puts("Type: Response");
	
	printf("Type of request: ");
	switch(ctrl & OPCODE)
	{
		case OP_QUERY:
			puts("Standard request");
			break;
		case OP_IQUERY:
			puts("Revert Query");
			break;
		case OP_STATUS:
			puts("Query status");
			break;
		case OP_NOTIFY:
			puts("Notify");
			break;
		case OP_UPDATE:
			puts("Update");
			break;
		case OP_DSO:
			puts("DNS Stateful Operations");
			break;
		default:
			puts("Unknown...");
	}
	if ((ctrl & QR) != QR_QUERY && (ctrl & AA) == AA)
		puts("Authoritative Answer");
	if((ctrl & TC) == TC)
		puts("Troncated message");
	else
		puts("Not troncate");
	if((ctrl & RD) == RD)
		puts("Ask recursivity");
	if ((ctrl & QR) != QR_QUERY && (ctrl & RA) == RA)
		puts("Recursivity authorized");

	if((ctrl & QR) == QR_QUERY)
		return;

	printf("RCode: ");
	switch(ctrl & RCODE)
	{
		case RC_NE:
			puts("No Error");
			break;
		case RC_FORM_ERR:
			puts("Format Error");
			break;
		case RC_SERV_FAIL:
			puts("Server Failure");
			break;
		case RC_NALE_ERR:
			puts("Name Error");
			break;
		case RC_NOT_IMP:
			puts("Not Implemented");
			break;
		case RC_REFUSED:
			puts("Query Refused");
			break;
		case RC_YXD:
			puts("Name Exists when it should not");
			break;
		case RC_YXRRS:
			puts("RR Set Exists when it should not");
			break;
		case RC_NXRRS:
			puts("RR Set that should exist does not");
			break;
		case RC_NA:
			puts("Not Authorized");
			break;
		case RC_NZ:
			puts("Name not contained in zone");
			break;
		case RC_BADVERS:
			puts("Bad OPT Version");
			break;
		case RC_BADKEY:
			puts("Key not recognized");
			break;
		case RC_BADTIME:
			puts("Signature out of time window");
			break;
		case RC_BADMODE:
			puts("Bad TKEY Mode");
			break;
		case RC_BADNAME:
			puts("Duplicate key name");
			break;
		case RC_BADALG:
			puts("Algorithm not supported");
			break;
		case RC_BADTRUNC:
			puts("Bad Truncation");
			break;
		default:
			puts("Unknown...");
	}
}

int print_dns_name(const u_char *query, const u_char *packet)
{
	uint byte_read = 0;
	uint16_t is_ptr = *(uint16_t *)query;
	printf("%x\n", is_ptr);
	printf("\tName: ");
	if ((is_ptr & PT_N) == PT_N)
	{
		uint16_t shift = (*((uint16_t *)query) & N_DECL);
		byte_read += 2;
		shift++;
		while (packet[shift] != '\0')
		{
			printf("%c", packet[shift]);
			shift++;
		}
		puts("");
	}
	else
	{
		byte_read++;
		while (query[byte_read] != '\0')
		{
			if ((query[byte_read] <= 'z' && query[byte_read] >= 'a') ||
				(query[byte_read] <= 'Z' && query[byte_read] >= 'A'))
				printf("%c", query[byte_read]);
			else
				printf(".");

			byte_read++;
		}
		puts("");
		byte_read++;
	}
	return byte_read;
}

void
print_dns_type(uint16_t type)
{
	switch(type)
	{
		case T_A:
			puts("IPv4 address");
			break;
		case T_NS:
			puts("Authoritative name server");
			break;
		case T_MD:
			puts("Mail destination");
			break;
		case T_MF:
			puts("Mail forwarder");
			break;
		case T_CNAME:
			puts("Canonical name");
			break;
		case T_SOA:
			puts("Start of a zone of authority");
			break;
		case T_MB:
			puts("Mailbox domain name");
			break;
		case T_MG:
			puts("Mail group member");
			break;
		case T_MR:
			puts("Mail rename domain name");
			break;
		case T_NULL:
			puts("Null resource record");
			break;
		case T_WKS:
			puts("Well known service description");
			break;
		case T_PTR:
			puts("Domain name ptr");
			break;
		case T_HINFO:
			puts("Host info");
			break;
		case T_MINFO:
			puts("Mailbox or mail list info");
			break;
		case T_MX:
			puts("Mail exchange");
			break;
		case T_TXT:
			puts("Text strings");
			break;
		case T_RP:
			puts("Responsible person");
			break;
		case T_AFSDB:
			puts("AFS Data Base location");
			break;
		case T_X25:
			puts("X.25 PSDN address");
			break;
		case T_ISDN:
			puts("ISDN address");
			break;
		case T_RT:
			puts("Route Throught");
			break;
		case T_NSAP:
			puts("NSAP address");
			break;
		case T_SIG:
			puts("Security signature");
			break;
		case T_KEY:
			puts("Security key");
			break;
		case T_PX:
			puts("X.400 mail mapping information");
			break;
		case T_GPOS:
			puts("Geographical Position");
			break;
		case T_AAAA:
			puts("IPv6 address");
			break;
		case T_LOC:
			puts("Location Information");
			break;
		case T_NXT:
			puts("Next domain");
			break;
		case T_EID:
			puts("Endpoint Id");
			break;
		case T_NIMLOC:
			puts("Nimrod locator");
			break;
		case T_SRV:
			puts("Server location");
			break;
		case T_ATMA:
			puts("ATM Address");
			break;
		case T_NAPTR:
			puts("Naming Authority Pointer");
			break;
		case T_KX:
			puts("Key Exchanger");
			break;
		case T_A6:
			puts("Adresse IPv6");
			break;
		case T_DNAME:
			puts("Delegation Name");
			break;
		case T_OPT:
			puts("EDNS");
			break;
		case T_DS:
			puts("Delegation Signer");
			break;
		case T_SSHFP:
			puts("SSH Key Fingerprint");
			break;
		case T_RRSIG:
			puts("DNSSEC");
			break;
		case T_NSEC:
			puts("Next SECure");
			break;
		case T_DNSKEY:
			puts("DNSSEC");
			break;
		case T_DHCID:
			puts("DHCP id");
			break;
		case T_NSEC3:
			puts("DNSSEC");
			break;
		case T_NSEC3PARAM:
			puts("DNSSEC");
			break;
		case T_HIP:
			puts("Host Id Protocol");
			break;
		case T_TALINK:
			puts("Trust Anchor LINK");
			break;
		case T_CDS:
			puts("Child DS");
			break;
		case T_SPF:
			puts("Sender Policy Framework");
			break;
		case T_TSIG:
			puts("Transaction Signature");
			break;
		case T_IXFR:
			puts("Incremental transfer");
			break;
		case T_AXFR:
			puts("A request for a transfer of an entire zone");
			break;
		case T_MAILB:
			puts("A request for mailbox-related records");
			break;
		case T_MAILA:
			puts("A request for mail agent RRs");
			break;
		case T_ALL:
			puts("A request for all records");
			break;
		case T_CAA:
			puts("Certification Authority Authorization");
			break;
		case T_DNSSECTA:
			puts("Trust Authorities");
			break;
		case T_DNSSECLV:
			puts("Lookaside Validation");
			break;
		default:
			puts("Unknown...");
	}
}

int
print_dns_query(const u_char *query, const u_char *packet)
{
	printf("Query:\n");
	uint byte_read = print_dns_name(query, packet);
	printf("\tType: ");
	print_dns_type(ntohs(*(uint16_t *)(query + byte_read)));

	byte_read += sizeof(uint16_t);

	printf("\tClass: ");
	switch (ntohs(*(uint16_t *)(query + byte_read)))
	{
		case CL_RESERVED:
			puts("Reserved");
			break;
		case CL_IN:
			puts("Internet");
			break;
		case CL_CH:
			puts("Chaos");
			break;
		case CL_HS:
			puts("Hesiod");
			break;
		case CL_ANY:
			puts("QCLASS only");
			break;
		default:
			puts("Unknown...");
	}
	return byte_read + sizeof(uint16_t);
}


int
print_dns_answer(const u_char *query, const u_char *packet)
{
	printf("Answers:\n");
	uint byte_read = print_dns_name(query, packet);
	print_dns_type(ntohs(*(uint16_t *)(query + byte_read)));
	byte_read += sizeof(uint16_t);
	printf("\tTTL: %i\n", ntohl(*(uint32_t *)(query + byte_read)));
	byte_read += sizeof(uint32_t);
	uint data_len = ntohs(*(uint16_t *)(query + byte_read));
	printf("\tData length: %i\n", data_len);
	byte_read += sizeof(uint16_t);

	if(data_len == 16)
	{
		char buf_adr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, (void *)(query + byte_read), buf_adr, INET6_ADDRSTRLEN);
		printf("\tAAAA Address: %s", buf_adr);
	}
	// else
	// 	printf("A Address: %s\n", inet_ntoa(*(void *)(query + byte_read)));
	
	return byte_read + data_len;
}