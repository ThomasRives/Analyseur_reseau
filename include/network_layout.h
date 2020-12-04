#ifndef NETWORK_LAYOUT_H
#define NETWORK_LAYOUT_H

#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include "transport_layout.h"
#include "ipv4.h"
#include "ipv6.h"
#include "arp.h"
#include "rarp.h"

#define VERS_MASK 0xf0000000
#define TRAF_CLASS_MASK 0x0ff00000
#define ID_MASK 0x000fffff

#endif //NETWORK_LAYOUT_H