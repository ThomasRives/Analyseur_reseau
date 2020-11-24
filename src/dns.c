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
	if ((ctrl & QR) != QR_QUERY && (ctrl & AA) == AA_)
		puts("Authoritative Answer");
	if((ctrl & TC) == TC_)
		puts("Troncated message");
	if((ctrl & RD) == RD_)
		puts("Ask recursivity");
	if ((ctrl & QR) != QR_QUERY && (ctrl & RA) == RA_)
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