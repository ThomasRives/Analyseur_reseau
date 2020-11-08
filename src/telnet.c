#include "telnet.h"

void
print_telnet_command(uint8_t command)
{
	printf("Command: ");
	switch(command)
	{
		case IAC:
			puts("Interpret as command");
			break;
		case DONT:
			puts("DONT");
			break;
		case DO:
			puts("Do");
			break;
		case WONT:
			puts("WONT");
			break;
		case WILL:
			puts("WILL");
			break;
		case SB:
			puts("Interpret as subnegotiation");
			break;
		case GA:
			puts("You may reverse the line");
			break;
		case EL:
			puts("Erase the current line");
			break;
		case EC:
			puts("Erase the current character");
			break;
		case AYT:
			puts("Are you there");
			break;
		case AO:
			puts("Abort output--but let prog finish");
			break;
		case IP:
			puts("Interrupt process--permanently");
			break;
		case BREAK:
			puts("Break");
			break;
		case DM:
			puts("Data mark--for connect");
			break;
		case NOP:
			puts("Nop");
			break;
		case SE:
			puts("End sub negotiation");
			break;
		case EOR:
			puts("End of record");
			break;
		case ABORT:
			puts("Abort process");
			break;
		case SUSP :
			puts("Suspend process");
			break;
		case xEOF:
			puts("End of file: EOF is already used...");
			break;
	}
}

void
print_telnet_suboption(uint8_t subopt)
{
	printf("Subcommand: ");
	switch(subopt)
	{
		case TELOPT_BINARY:
			printf("8-bit data path");
			break;
		case TELOPT_ECHO:
			printf("Echo");
			break;
		case TELOPT_RCP:
			printf("Prepare to reconnect");
			break;
		case TELOPT_SGA:
			printf("Suppress go ahead");
			break;
		case TELOPT_NAMS:
			printf("Approximate message size");
			break;
		case TELOPT_STATUS:
			printf("Give status");
			break;
		case TELOPT_TM :
			printf("Timing mark");
			break;
		case TELOPT_RCTE:
			printf("Remote controlled transmission and echo");
			break;
		case TELOPT_NAOL:
			printf("Negotiate about output line width");
			break;
		case TELOPT_NAOP:
			printf("Negotiate about output page size");
			break;
		case TELOPT_NAOCRD:
			printf("Negotiate about CR disposition");
			break;
		case TELOPT_NAOHTS:
			printf("Negotiate about horizontal tabstops");
			break;
		case TELOPT_NAOHTD:
			printf("Negotiate about horizontal tab disposition");
			break;
		case TELOPT_NAOFFD:
			printf("Negotiate about formfeed disposition");
			break;
		case TELOPT_NAOVTS:
			printf("Negotiate about vertical tab stops");
			break;
		case TELOPT_NAOVTD:
			printf("Negotiate about vertical tab disposition");
			break;
		case TELOPT_NAOLFD:
			printf("Negotiate about output LF disposition");
			break;
		case TELOPT_XASCII:
			printf("Extended ascii character set");
			break;
		case TELOPT_LOGOUT:
			printf("Force logout");
			break;
		case TELOPT_BM:
			printf("Byte macro");
			break;
		case TELOPT_DET:
			printf("Data entry terminal");
			break;
		case TELOPT_SUPDUP:
			printf("Supdup protocol");
			break;
		case TELOPT_SUPDUPOUTPUT:
			printf("Supdup output");
			break;
		case TELOPT_SNDLOC:
			printf("Send location");
			break;
		case TELOPT_TTYPE:
			printf("Terminal type");
			break;
		case TELOPT_EOR:
			printf("End or record");
			break;
		case TELOPT_TUID:
			printf("TACACS user identification");
			break;
		case TELOPT_OUTMRK:
			printf("Output marking");
			break;
		case TELOPT_TTYLOC:
			printf("Terminal location number");
			break;
		case TELOPT_3270REGIME:
			printf("3270 regime");
			break;
		case TELOPT_X3PAD:
			printf("X.3 PAD");
			break;
		case TELOPT_NAWS:
			printf("Window size");
			break;
		case TELOPT_TSPEED:
			printf("Terminal speed");
			break;
		case TELOPT_LFLOW:
			printf("Remote flow control");
			break;
		case TELOPT_LINEMODE:
			printf("Linemode option");
			break;
		case TELOPT_XDISPLOC:
			printf("X Display Location");
			break;
		case TELOPT_OLD_ENVIRON:
			printf("Old - Environment variables");
			break;
		case TELOPT_AUTHENTICATION:
			printf("Authenticate");
			break;
		case TELOPT_ENCRYPT:
			printf("Encryption option");
			break;
		case TELOPT_NEW_ENVIRON:
			printf("New - Environment variables");
			break;
		case TELOPT_EXOPL:
			printf("Extended-options-list");
			break;
	}
	
	printf(" (%i)\n", subopt);
}
