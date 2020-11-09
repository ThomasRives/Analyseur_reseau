#include "ftp.h"

int
is_digit(uint8_t character)
{
	return '0' <= character && character <= '9';
}

int
print_until_rn(const uint8_t *str)
{
	uint32_t i = 0;
	do{
		putchar(str[i]);
		i++;
	}while(str[i-1] != '\r' && str[i] != '\n');
	putchar(str[i]);
	return i+1;
}

int printf_ftp_command(const uint8_t *command)
{
	uint32_t command_int = ntohl((*(uint32_t *)command)) >> 8;
	printf("Command: ");
	switch(command_int)
	{
		case REP_COD_OK:
			printf("Command okay.");
			break;
		case REP_COD_CU:
			printf("Syntax error, command unrecognized. This may include errors"
				" such as command line too long.");
			break;
		case REP_COD_PA:
			printf("Syntax error in parameters or arguments.");
			break;
		case REP_COD_CNIS:
			printf("Command not implemented, superfluous at this site.");
			break;
		case REP_COD_CNI:
			printf("Command not implemented.");
			break;
		case REP_COD_BAD_SEQ:
			printf("Bad sequence of commands.");
			break;
		case REP_COD_CNI_PARAM:
			printf("Command not implemented for that parameter.");
			break;
		case REP_COD_RESTART:
			printf("Restart marker reply. In this case, the text is exact and "
				"not left to the particular implementation; it must read: "
				"MARK yyyy = mmmm Where yyyy is User-process data stream "
				"marker, and mmmm server's equivalent marker (note the spaces"
				" between markers and \"=\").");
			break;
		case REP_COD_SYST_STAT:
			printf("System status, or system help reply.");
			break;
		case REP_COD_DIR_STAT:
			printf("Directory status.");
			break;
		case REP_COD_FILE_STAT:
			printf("File status.");
			break;
		case REP_COD_HELP_MSG:
			printf("Help message. On how to use the server or the meaning of a "
				"particular non-standard command.  This reply is useful only to "
				"the human user.");
			break;
		case REP_COD_NAME:
			printf("NAME system type. Where NAME is an official system name from"
				" the list in the Assigned Numbers document.");
			break;
		case REP_COD_MIN:
			printf("Service ready in nnn minutes.");
			break;
		case REP_COD_NEW_USR:
			printf("Service ready for new user.");
			break;
		case REP_COD_CLOSE_CON:
			printf("Service closing control connection. Logged out if "
				"appropriate.");
			break;
		case REP_COD_SNA:
			printf("Service not available, closing control connection. This may"
				" be a reply to any command if the service knows it must shut "
				"down.");
			break;
		case REP_COD_CON_AO:
			printf("Data connection already open; transfer starting.225 Data "
				"connection open; no transfer in progress.");
			break;
		case REP_COD_CANT_OPEN:
			printf("Can't open data connection.");
			break;
		case REP_COD_CLOSE_DATA:
			printf("Closing data connection. Requested file action successful "
				"(for example, file transfer or file abort).");
			break;
		case REP_COD_CON_CLOSED:
			printf("Connection closed; transfer aborted.");
			break;
		case REP_COD_PASSIVE_MOD:
			printf("Entering Passive Mode (h1,h2,h3,h4,p1,p2).");
			break;

		case REP_COD_USER_LOGGEDIN:
			printf("User logged in, proceed.");
			break;
		case REP_COD_NOT_LOG:
			printf("Not logged in.");
			break;
		case REP_COD_USR_NAME_OK:
			printf("User name okay, need password.");
			break;
		case REP_COD_NA_LOGIN:
			printf("Need account for login.");
			break;
		case REP_COD_NA_STOR_FILES:
			printf("Need account for storing files.");
			break;
		case REP_COD_FS_OK:
			printf("File status okay; about to open data connection.");
			break;
		case REP_COD_REQ_FILE:
			printf("Requested file action okay, completed.");
			break;
		case REP_COD_PATHNAME:
			printf("\"PATHNAME\" created.");
			break;
		case REP_COD_REQ_FILE_INFO:
			printf("Requested file action pending further information.");
			break;
		case REP_COD_FILE_BSY:
			printf("Requested file action not taken. File unavailable (e.g., "
				"file busy).");
			break;
		case REP_COD_FNF:
			printf("Requested action not taken. File unavailable (e.g., file "
				"not found, no access).");
			break;
		case REP_COD_LOCAL_ERR:
			printf("Requested action aborted. Local error in processing.");
			break;
		case REP_COD_PAGE_TYPE_UNK:
			printf("Requested action aborted. Page type unknown.");
			break;
		case REP_COD_STORAGE:
			printf("Requested action not taken. Insufficient storage space in "
				"system.");
			break;
		case REP_COD_STORAGE_ALLOC:
			printf("Requested file action aborted. Exceeded storage allocation "
				"(for current directory or dataset).");
			break;
		case REP_COD_FILE_NAME_ERR:
			printf("Requested action not taken. File name not allowed.");
			break;
		case REP_COD_NO_TRANS_IN_PROG:
			printf("Data connection open; no transfer in progress.");
			break;
	}
	printf(" (%c%c%c)\n", command[0], command[1], command[2]);
	return 3; // Size in bytes for
}