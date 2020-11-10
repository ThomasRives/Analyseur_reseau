#ifndef APPLICATION_LAYOUT_H
#define APPLICATION_LAYOUT_H
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/telnet.h>
#include "bootp.h"
#include "telnet.h"
#include "tlv_analyzer.h"
#include "ftp.h"
#include "utilities.h"

/**
 * @brief Analyze the bootp header of the packet.
 * 
 * @param packet: the packet himself.
 */
void bootp_analyze(const u_char *packet);

/**
 * @brief Print the content of an SMTP packet.
 * 
 * @param packet: the packet himself.
 * @param length: the packet length.
 */
void smtp_analyze(const u_char *packet, uint length);

/**
 * @brief Print the content of an telnet packet.
 * 
 * @param packet: the packet himself.
 * @param length: the packet length.
 */
void telnet_analyze(const u_char *packet, uint length);

/**
 * @brief Print the content of a ftp packet.
 * 
 * @param packet: the packet himself.
 * @param length: the packet length.
 */
void ftp_analyze(const u_char *packet, uint length);

/**
 * @brief Print the content of a http packet.
 * 
 * @param packet: the packet himself.
 * @param length: the packet length.
 */
void http_analyze(const u_char *packet, uint length);

/*
Port|UDP|TCP|decription
-----------------------
9   | 1 | 1 | Disar
21  | 1 | 1 | ftp DONE
22  | 1 | 1 | ssh
23  | 0 | 1 | telnet DONE
25  | 0 | 1 | smtp DONE
42  | 1 | 1 | Service de noms
50  | 1 | 1 | Remote Mail Checking 
53  | 1 | 1 | Résolution de nom par DNS TODO
67  | 1 | 0 | Service Bootp Protocol DONE
68  | 1 | 0 | Bootstrap Client 
69  | 1 | 0 | TFTP 
80  | 0 | 1 | HTTP DONE
101 | 0 | 1 | NIC Host Name 
115 | 0 | 1 | SFTP
443 | 0 | 1 | HTTPS
514 | 0 | 1 | Shell remote
514 | 1 | 0 | Unix Syslog
521 | 1 | 0 | Routing Info Protocol for IPv6
992 | 1 | 1 | Telnets via SSL/TLS

//LDAP TODO
//IMAP TODO
//POP TODO
//SCTP TODO


Use destination port to know the protocol
*/

#endif //APPLICATION_LAYOUT_H