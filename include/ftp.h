#ifndef FTP_H
#define FTP_H
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#define REP_COD_OK 0x323030 /* Command okay. */
#define REP_COD_CU 0x353030 /* Syntax error, command unrecognized. This may include errors such as command line too long. */
#define REP_COD_PA 0x353031 /* Syntax error in parameters or arguments. */
#define REP_COD_CNIS 0x323032 /* Command not implemented, superfluous at this site. */
#define REP_COD_CNI 0x353032 /* Command not implemented. */
#define REP_COD_BAD_SEQ 0x353033 /* Bad sequence of commands. */
#define REP_COD_CNI_PARAM 0x353034 /* Command not implemented for that parameter. */
#define REP_COD_RESTART 0x313130 /* Restart marker reply. In this case, the text is exact and not left to the particular implementation; it must read: MARK yyyy = mmmm Where yyyy is User-process data stream marker, and mmmm server's equivalent marker (note the spaces between markers and "="). */
#define REP_COD_SYST_STAT 0x323131 /* System status, or system help reply. */
#define REP_COD_DIR_STAT 0x323132 /* Directory status. */
#define REP_COD_FILE_STAT 0x323133 /* File status. */
#define REP_COD_HELP_MSG 0x323134 /* Help message. On how to use the server or the meaning of a particular non-standard command.  This reply is useful only to the human user. */
#define REP_COD_NAME 0x323135 /* NAME system type. Where NAME is an official system name from the list in the Assigned Numbers document. */

#define REP_COD_MIN 0x313230 /* Service ready in nnn minutes. */
#define REP_COD_NEW_USR 0x323230 /* Service ready for new user. */
#define REP_COD_CLOSE_CON 0x323231 /* Service closing control connection. Logged out if appropriate. */
#define REP_COD_SNA 0x343231 /* Service not available, closing control connection. This may be a reply to any command if the service knows it must shut down. */
#define REP_COD_CON_AO 0x313235 /* Data connection already open; transfer starting.225 Data connection open; no transfer in progress. */
#define REP_COD_CANT_OPEN 0x343235 /* Can't open data connection. */
#define REP_COD_CLOSE_DATA 0x323236 /* Closing data connection. Requested file action successful (for example, file transfer or file abort). */
#define REP_COD_CON_CLOSED 0x343236 /* Connection closed; transfer aborted. */
#define REP_COD_PASSIVE_MOD 0x323237 /* Entering Passive Mode (h1,h2,h3,h4,p1,p2). */

#define REP_COD_USER_LOGGEDIN 0x323330 /* User logged in, proceed. */
#define REP_COD_NOT_LOG 0x353330 /* Not logged in. */
#define REP_COD_USR_NAME_OK 0x333331 /* User name okay, need password. */
#define REP_COD_NA_LOGIN 0x333332 /* Need account for login. */
#define REP_COD_NA_STOR_FILES 0x353332 /* Need account for storing files. */
#define REP_COD_FS_OK 0x313530 /* File status okay; about to open data connection. */
#define REP_COD_REQ_FILE 0x323530 /* Requested file action okay, completed. */
#define REP_COD_PATHNAME 0x323537 /* "PATHNAME" created. */
#define REP_COD_REQ_FILE_INFO 0x333530 /* Requested file action pending further information. */
#define REP_COD_FILE_BSY 0x343530 /* Requested file action not taken. File unavailable (e.g., file busy). */
#define REP_COD_FNF 0x353530 /* Requested action not taken. File unavailable (e.g., file not found, no access). */
#define REP_COD_LOCAL_ERR 0x343531 /* Requested action aborted. Local error in processing. */
#define REP_COD_PAGE_TYPE_UNK 0x353531 /* Requested action aborted. Page type unknown. */
#define REP_COD_STORAGE 0x343532 /* Requested action not taken. Insufficient storage space in system. */
#define REP_COD_STORAGE_ALLOC 0x353532 /* Requested file action aborted. Exceeded storage allocation (for current directory or dataset). */
#define REP_COD_FILE_NAME_ERR 0x353533 /* Requested action not taken. File name not allowed. */
#define REP_COD_NO_TRANS_IN_PROG 0x323235 /* Data connection open; no transfer in progress. */

/**
 * @brief Indicate if a character is a number (ASCII).
 * 
 * @param caracter: the caracter you want to check.
 * @return an integer indicating if the caracter is a number.
 */
int is_digit(uint8_t caracter);

/**
 * @brief Print a string until \r\n.
 * 
 * @param: the string to print.
 * @return an interger corresponding to the number of char printed.
 */
int print_until_rn(const uint8_t *str);

/**
 * @brief printf the command associated to the code for ftp.
 * 
 * @param command: the code of the command.
 */
void printf_ftp_command(const uint8_t *command);

#endif //FTP_H