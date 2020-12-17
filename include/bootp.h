#ifndef BOOTP_H
#define BOOTP_H
#include "application_layout.h"

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
	u_char vend;         /* first char of the vendor */ 
};

/*
 * UDP port numbers, server and client.
 */
#define PORT_BOOTPS 67
#define PORT_BOOTPC 68

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
#define OPT_TIME_SERVER 4
#define OPT_DOMAIN_SERVER 6
#define OPT_HOSTNAME 12
#define OPT_DOMAIN_NAME 15
#define OPT_MTU_INT 26
#define OPT_BROADCAST_ADDR 28
#define OPT_NETBIOS_NS 44
#define OPT_NETBIOS_SCOPE 47
#define OPT_REQ_IP_ADDR 50
#define OPT_LEASE_TIME 51
#define OPT_DHCP_TYPE 53
#define OPT_SERV_ID 54
#define OPT_PARAM_REQ_LIST 55
#define OPT_MAX_MSG_SIZE 57
#define OPT_RENEWAL_TIME 58
#define OPT_TFTP_SN 66
#define OPT_REBINDING_TIME 59
#define OPT_CLIENT_ID 61
#define OPT_TFTP_SERV_NAME 66
#define OPT_CLIENT_FQDN 81

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

#define END_OPT 1
#define NOT_END_OPT 0

/**
 * @brief Analyze the bootp header of the packet.
 * 
 * @param packet: the packet himself.
 */
void bootp_analyze(const u_char *packet);

/**
 * @brief Print the operation of a bootp packet.
 * 
 * @param op: the operation of the bootp packet.
 */
void bootp_print_op(uint8_t op);

/**
 * @brief Print the harware type of a bootp packet.
 * 
 * @param htype: the code of the hardware type.
 */
void bootp_print_htype(uint8_t htype);

/**
 * @brief Print the harware address length of a bootp packet.
 * 
 * @param htype: the length of the hardware address.
 */
void bootp_print_hlen(uint8_t hlen);

/**
 * @brief Print the client hardware address.
 * 
 * @param chaddr: the hardware address of the client.
 * @param hlen: the length of the address.
 */
void bootp_print_chaddr(u_char *chaddr, uint8_t hlen);

/**
 * @brief Print the content of a data as a string.
 * 
 * @param str: the data to print as a string.
 * @param length: the length of the string.
 */
void bootp_print_str(u_char *str, uint length);

/**
 * @brief Print the vendor of a bootp packet
 * 
 * @param vend: a pointer to the beginning of the vendor.
 */
void bootp_print_vendor(u_char *vend);

/**
 * @brief Print an option of the bootp vendor.
 * 
 * @param opt: the tlv of the option.
 * @return an interger that indicate if there is other options.
 */
int bootp_print_opt_tlv(struct tlv opt);

/**
 * @brief Print the Domain servers.
 * 
 * @param value: the value containing the domain servers.
 * @param length: the length of the option.
 */
void bootp_print_opt_lip(u_char *value, uint length);

/**
 * @brief Print the dhcp type of a bootp packet.
 * 
 * @param type: the type of the dhcp message.
 */
void bootp_print_dhcp_type(uint type);

/**
 * @brief Print the dhcp type of a bootp packet.
 * 
 * @param length: the length of the value.
 * @param value: a pointer to the value.
 */
void bootp_print_par_list(uint length, u_char *value);

#endif //BOOTP_H