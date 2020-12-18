#ifndef FTP_H
#define FTP_H

#include "application_layout.h"

#define PORT_FTP 21

/**
 * @brief Print the content of a ftp packet.
 * 
 * @param packet: the packet himself.
 * @param length: the packet length.
 */
void ftp_analyze(const u_char *packet, uint length);

#endif //FTP_H