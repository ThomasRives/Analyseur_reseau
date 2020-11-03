#ifndef APPLICATION_LAYOUT_H
#define APPLICATION_LAYOUT_H
#include <stdio.h>
#include <stdint.h>
#include "bootp.h"

/**
 * @brief Analyze the bootp header of the packet.
 * 
 * @param packet: the packet himself.
 */
void bootp_header_analyze(const u_char *packet);

/**
 * @brief Print the operation of a bootp packet.
 * 
 * @param op: the operation of the bootp packet.
 */
void print_bootp_op(uint8_t op);

/**
 * @brief Print the harware type of a bootp packet.
 * 
 * @param htype: the code of the hardware type.
 */
void print_bootp_htype(uint8_t htype);

/**
 * @brief Print the harware address length of a bootp packet.
 * 
 * @param htype: the length of the hardware address.
 */
void print_bootp_hlen(uint8_t hlen);


/**
 * @brief Print the client hardware address.
 * 
 * @param chaddr: the hardware address of the client.
 */
void
print_bootp_chaddr(u_char *chaddr);

/**
 * @brief Print the serveur host name.
 * 
 * @param sname: the serveur host name.
 */
void
print_bootp_sname(u_char *sname);

/**
 * @brief Print the file name given in the packet.
 * 
 * @param file: the file name given in the packet.
 */
void
print_bootp_file(u_char *file);

/**
 * @brief Print the vendor of a bootp packet
 * 
 * @param vend: a pointer to the beginning of the vendor.
 */
void
print_bootp_vendor(u_char *vend);

/*
Port|UDP|TCP|decription
-----------------------
9   | 1 | 1 | Disar
 21  | 1 | 1 | ftp TODO
22  | 1 | 1 | ssh
23  | 0 | 1 | telnet TODO
25  | 0 | 1 | smtp TODO
42  | 1 | 1 | Service de noms
50  | 1 | 1 | Remote Mail Checking 
53  | 1 | 1 | Résolution de nom par DNS TODO
67  | 1 | 0 | Service Bootp Protocol TODO
68  | 1 | 0 | Bootstrap Client 
69  | 1 | 0 | TFTP 
80  | 0 | 1 | HTTP TODO
101 | 0 | 1 | NIC Host Name 
115 | 0 | 1 | SFTP
443 | 0 | 1 | HTTPS
514 | 0 | 1 | Shell remote
514 | 1 | 0 | Unix Syslog
521 | 1 | 0 | Routing Info Protocol for IPv6
992 | 1 | 1 | Telnets via SSL/TLS

//LDAP
//IMAP
//POP


Use destination port to know the protocol
*/

#endif //APPLICATION_LAYOUT_H