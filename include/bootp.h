#ifndef BOOTP_H
#define BOOTP_H
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ether.h>

struct bootphdr
{
	uint8_t op;	/* packet opcode type */
	uint8_t htype; /* hardware addr type */
	uint8_t hlen;	/* hardware addr length */
	uint8_t hops;	/* gateway hops */
	uint32_t xid;	/* transaction ID */
	uint16_t secs; /* seconds since boot began */
	uint16_t flags; /* flags */
	struct in_addr ciaddr;	 /* client IP address */
	struct in_addr yiaddr;	 /* 'your' IP address */
	struct in_addr siaddr;	 /* server IP address */
	struct in_addr giaddr;	 /* gateway IP address */
	u_char chaddr[16]; /* client hardware address */
	u_char sname[64];	 /* server host name */
	u_char file[128];	 /* boot file name */
	u_char vend[64];	 /* vendor-specific area */
};

/*
 * UDP port numbers, server and client.
 */
#define IPPORT_BOOTPS 67
#define IPPORT_BOOTPC 68

#define BOOTREQUEST 1
#define BOOTREPLY 2

/*
 * Hardware types
 */
#define HTYPE_ETHERNET 1
#define HTYPE_EXP_ETHERNET 2
#define HTYPE_IEEE802 6
#define HTYPE_ARCNET 7

#define MAGIC_COOKIE 0x63825363 /* Magic Cookie */

#define OPT_END 255
#define OPT_PAD 0
#define OPT_SUBNET_MASK 1
#define OPT_TIME_OFFSET 2
#define OPT_GATEWAY 3
#define OPT_DOMAIN_SERVER 6
#define OPT_DOMAIN_NAME 15
#define OPT_BROADCAST_ADDR 28
#define OPT_NETBIOS_NS 44
#define OPT_NETBIOS_SCOPE 47
#define OPT_REQ_IP_ADDR 50
#define OPT_LEASE_TIME 51
#define OPT_DHCP_TYPE 53
#define OPT_SERV_ID 54
#define OPT_PARAM_REQ_LIST 55
#define OPT_CLIENT_ID 61

/* Different DHCP message possible */
#define MSG_DISCOVER 1
#define MSG_OFFER 2
#define MSG_REQUEST 3
#define MSG_DECLINE 4
#define MSG_ACK 5
#define MSG_NACK 6
#define MSG_RELEASE 7

/* Parameters request list */
#define SUBNET_MASK 1
#define ROUTER 3
#define DNS 6
#define DOMAINE_NAME 15
#define BROADCAST_ADDR 28
#define NETBIOS_SCOPE 47
#define NETBIOS 44
#define NETBIOS_NODE_TYPE 46

#endif //BOOTP_H