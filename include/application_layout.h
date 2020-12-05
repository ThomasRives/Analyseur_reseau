#ifndef APPLICATION_LAYOUT_H
#define APPLICATION_LAYOUT_H
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/telnet.h>
#include <netinet/ether.h>
#include "bootp.h"
#include "telnet.h"
#include "tlv_analyzer.h"
#include "dns.h"
#include "utilities.h"
#include "smtp.h"
#include "ftp.h"
#include "http.h"
#include "imap.h"
#include "pop.h"
#include "sctp.h"

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
53  | 1 | 1 | Résolution de nom par DNS WIP
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
//IMAP DONE
//POP DONE
//SCTP TODO

Use destination port to know the protocol
*/

#endif //APPLICATION_LAYOUT_H