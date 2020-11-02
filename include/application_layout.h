#ifndef APPLICATION_LAYOUT_H
#define APPLICATION_LAYOUT_H
#include <stdio.h>
#include <stdint.h>
#include "bootp.h"


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