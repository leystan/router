/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"
#include "sr_arpcache.h"
#include "sr_rt.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

	if (ethertype(packet) == ethertype_arp) {			/* ARP packet */
		struct sr_arp_hdr *arpHeader = (struct sr_arp_hdr *) (packet + sizeof(struct sr_ethernet_hdr));
		if (is_broadcast_mac(packet) || we_are_dest(sr, arpHeader->ar_tip)) {
			/* Process only broadcasted packets or packets meant for me */
			processArp(sr, packet, len, interface);
		}

	} else if (ethertype(packet) == ethertype_ip) { 	/* IP packet */
		struct sr_ip_hdr *ipHeader = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

		/* Ignore invalid packets */
		if (!is_sane_ip_packet(packet, len)) {
			return;
		}

		/* If NAT is enabled, do an address translation */
		if (sr->natEnable) {
			int failed = sr_nat_translate_packet(sr, packet, len, interface);
			if (failed) {
				/* packet could not be translated. Drop it */
				return;
			}
		}

		if (we_are_dest(sr, ipHeader->ip_dst)) {
			/* We are destination */
			processIP(sr, packet, len, interface);
		} else {
			/* We are not destination. Forward it. */
			processForward(sr, packet, len, interface);
		}
	}

}/* end sr_ForwardPacket */

void processArp(struct sr_instance *sr , uint8_t *packet, unsigned int len, char *interface) {

	struct sr_arp_hdr *arpHeader = (struct sr_arp_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

	/* Put ARP header into cache */
	struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arpHeader->ar_sha, ntohl(arpHeader->ar_sip));
	if (req != NULL) {

		/* Found requests in queue waiting for this reply. Send all waiting packets */
		struct sr_packet *waiting = req->packets;
		struct sr_rt *rt = findLongestMatchPrefix(sr->routing_table, htonl(req->ip));

		while (waiting != NULL) {
			send_packet_to_dest(sr, waiting->buf, waiting->len, rt->interface, arpHeader->ar_sha, arpHeader->ar_sip);
			waiting = waiting->next;
		}

		/* Destroy arp request when complete */
		sr_arpreq_destroy(&(sr->cache), req);
	}

	if (ntohs(arpHeader->ar_op) == arp_op_request) {
		/* Reply to sender with our information */
		arp_send_reply(sr, packet, len, interface);
	}

}

void processIP(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface) {

	struct sr_ip_hdr *ipHeader = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

	ipHeader->ip_ttl--;

	if (ipHeader->ip_p == ip_protocol_icmp) {
		/* ICMP request */

		/* Ignore invalid packets */
		if (!is_sane_icmp_packet(packet, len)) {
			return;
		}

		/* Process ICMP only if echo*/
		struct sr_icmp_hdr *icmpHeader = (struct sr_icmp_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
		if (icmpHeader->icmp_type == icmp_echo_req_type) {
			icmp_send_echo_reply(sr, packet, len, interface);
		}

	} else if (ipHeader->ip_p == ip_protocol_tcp || ipHeader->ip_p == ip_protocol_udp) {

		/* TCP or UDP Payload */
		icmp_send_port_unreachable(sr, packet, len, interface);

	}

}

void arp_send_reply(struct sr_instance *sr , uint8_t *packet, unsigned int len, char *interface) {

    int i;
    struct sr_if *sourceIf = sr_get_interface(sr, interface);
    struct sr_ethernet_hdr *ethHeader = (struct sr_ethernet_hdr *) packet;
	struct sr_arp_hdr *arpHeader = (struct sr_arp_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

    /* Initialize reply packet */
    uint8_t *reply = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr));
    struct sr_ethernet_hdr *replyEth = (struct sr_ethernet_hdr *) reply;
    struct sr_arp_hdr *replyArp = (struct sr_arp_hdr *) (reply + sizeof(struct sr_ethernet_hdr));

    /* Construct ethernet header */
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        replyEth->ether_dhost[i] = ethHeader->ether_shost[i];
        replyEth->ether_shost[i] = sourceIf->addr[i];
    }
    replyEth->ether_type = htons(ethertype_arp);

    /* Construct ARP header */
    replyArp->ar_hrd = arpHeader->ar_hrd;
    replyArp->ar_pro = arpHeader->ar_pro;
    replyArp->ar_hln = arpHeader->ar_hln;
    replyArp->ar_pln = arpHeader->ar_pln;
    replyArp->ar_op = htons(arp_op_reply);
    replyArp->ar_sip = sourceIf->ip;
    replyArp->ar_tip = arpHeader->ar_sip;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        replyArp->ar_sha[i] = sourceIf->addr[i];
        replyArp->ar_tha[i] = arpHeader->ar_sha[i];
    }

    sr_send_packet(sr, reply, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr), interface);
    free(reply);

}

void send_packet_to_dest(struct sr_instance *sr , uint8_t *packet, unsigned int len, char *interface, unsigned char *dest_mac, uint32_t dest_ip) {

    int i;
	struct sr_if *sourceIf = sr_get_interface(sr, interface);
    struct sr_ethernet_hdr *ethHeader = (struct sr_ethernet_hdr *) packet;
    struct sr_ip_hdr *ipHeader = (struct sr_ip_hdr *) (packet + sizeof(sr_ethernet_hdr_t));

    /* send the given packet to the destination mac and ip */
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
		ethHeader->ether_shost[i] = sourceIf->addr[i];
        ethHeader->ether_dhost[i] = dest_mac[i];
    }
    ipHeader->ip_dst = dest_ip;
	ipHeader->ip_sum = 0;
	ipHeader->ip_sum = cksum(ipHeader, sizeof(sr_ip_hdr_t));

    sr_send_packet(sr, packet, len, interface);

}

void arp_send_request(struct sr_instance *sr , struct sr_arpreq *arp) {

	int i;
	struct sr_rt *rt = findLongestMatchPrefix(sr->routing_table, htonl(arp->ip));
	struct sr_if *sourceIf = sr_get_interface(sr, rt->interface);

	/* Initialize request packet */
	uint8_t *req = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
	struct sr_ethernet_hdr *reqEth = (struct sr_ethernet_hdr *) req;
	struct sr_arp_hdr *reqArp = (struct sr_arp_hdr *) (req + sizeof(sr_ethernet_hdr_t));

	/* Construct ethernet header */
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
	    reqEth->ether_dhost[i] = 0xff;
	    reqEth->ether_shost[i] = sourceIf->addr[i];
	}
	reqEth->ether_type = htons(ethertype_arp);

	/* Construct ARP header */
	reqArp->ar_hrd = htons(arp_hrd_ethernet);
	reqArp->ar_pro = htons(ethertype_ip);			/*IPv4 protocol type*/
	reqArp->ar_hln = 6;								/*Ethernet addresses size*/
	reqArp->ar_pln = 4;								/*IPv4 address size*/
	reqArp->ar_op = htons(arp_op_request);
	reqArp->ar_sip = sourceIf->ip;
	reqArp->ar_tip = rt->gw.s_addr;
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		reqArp->ar_tha[i] = 0x00;
		reqArp->ar_sha[i] = sourceIf->addr[i];
	}
	sr_send_packet(sr, req, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), sourceIf->name);
	free(req);

}

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {

	if (req->times_sent >= 5) {
		/* Max number of ARP requests send. Host is unreachable */
		struct sr_packet *pkt = req->packets;
		while (pkt != NULL) {
			icmp_send_host_unreachable(sr, pkt->buf, pkt->len, pkt->iface);
			pkt = pkt->next;
		}
		sr_arpreq_destroy(&(sr->cache), req);

	} else {
		/* Can send request again */
		arp_send_request(sr, req);
		req->times_sent++;
		req->sent = time(NULL);
	}
}

void icmp_send_echo_reply(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	/* Modify and resend packet at echo reply */
	/* Ethernet header */
	int i;
	unsigned char *sourceEth = sr_get_interface(sr, interface)->addr;
	struct sr_ethernet_hdr *ethHeader = (struct sr_ethernet_hdr *) packet;
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		ethHeader->ether_dhost[i] = ethHeader->ether_shost[i];
		ethHeader->ether_shost[i] = sourceEth[i];
	}

	/* IP header */
	uint32_t sourceIP = sr_get_interface(sr, interface)->ip;
	struct sr_ip_hdr *ipHeader = (struct sr_ip_hdr *) (packet + sizeof(sr_ethernet_hdr_t));
	ipHeader->ip_dst = ipHeader->ip_src;
	ipHeader->ip_src = sourceIP;
	ipHeader->ip_sum = 0;
	ipHeader->ip_ttl = 64;
	ipHeader->ip_sum = cksum(ipHeader, sizeof(struct sr_ip_hdr));

	/* ICMP header */
	struct sr_icmp_hdr *icmpHeader = (struct sr_icmp_hdr *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	icmpHeader->icmp_type = htons(icmp_echo_reply_type);
	icmpHeader->icmp_code = htons(0);
	icmpHeader->icmp_sum = 0;
	icmpHeader->icmp_sum = cksum(icmpHeader, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

	/* Record this IP into arp cache if not found */
	struct sr_arpentry *arpEntry = sr_arpcache_lookup(&(sr->cache), ntohl(ipHeader->ip_dst));
	if (arpEntry == NULL) {
		sr_arpcache_queuereq(&(sr->cache), ntohl(ipHeader->ip_dst), packet, len, interface);
	} else {
		sr_send_packet(sr, packet, len, interface);
	}
}

void icmp_send_net_unreachable(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	icmp_send_type3(sr, packet, len, interface, icmp_unreachable_type, icmp_net_unreachable);
}

void icmp_send_host_unreachable(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	icmp_send_type3(sr, packet, len, interface, icmp_unreachable_type, icmp_host_unreachable);
}

void icmp_send_port_unreachable(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	icmp_send_type3(sr, packet, len, interface, icmp_unreachable_type, icmp_port_unreachable);
}

void icmp_send_time_exceeded(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	/* Re-increment TTL */
	struct sr_ip_hdr *ipHeader = (struct sr_ip_hdr *) (packet + sizeof(sr_ethernet_hdr_t));
	ipHeader->ip_ttl = 1;

    icmp_send_type3(sr, packet, len, interface, icmp_time_exceeded_type, 0);
}

void icmp_send_type3(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */,
        uint8_t type,
	    uint8_t code)
{
	int newLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	uint8_t *response = malloc(newLen);

	/* Ethernet header */
	int i;
	unsigned char *sourceEth = sr_get_interface(sr, interface)->addr;
	struct sr_ethernet_hdr *ethHeader = (struct sr_ethernet_hdr *) response;
	struct sr_ethernet_hdr *packetEth = (struct sr_ethernet_hdr *) packet;
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		ethHeader->ether_dhost[i] = packetEth->ether_shost[i];
		ethHeader->ether_shost[i] = sourceEth[i];
	}
	ethHeader->ether_type = htons(ethertype_ip);

	/* IP header */
	uint32_t sourceIP = sr_get_interface(sr, interface)->ip;
	struct sr_ip_hdr *ipHeader = (struct sr_ip_hdr *) (response + sizeof(sr_ethernet_hdr_t));
	struct sr_ip_hdr *packetIp = (struct sr_ip_hdr *) (packet + sizeof(sr_ethernet_hdr_t));
	ipHeader->ip_hl = 5;
	ipHeader->ip_id = 0;
	ipHeader->ip_v = 4;
	ipHeader->ip_tos = 0;
	ipHeader->ip_off = htons(IP_DF);
	ipHeader->ip_ttl = 100;
	ipHeader->ip_dst = packetIp->ip_src;
	ipHeader->ip_src = sourceIP;
	ipHeader->ip_len = htons(newLen - sizeof(sr_ethernet_hdr_t));
	ipHeader->ip_p = ip_protocol_icmp;
	ipHeader->ip_sum = 0;
	ipHeader->ip_sum = cksum(ipHeader, sizeof(struct sr_ip_hdr));

	/* type3 ICMP header */
	struct sr_icmp_t3_hdr *icmpResponse = (struct sr_icmp_t3_hdr *) (response + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
	icmpResponse->icmp_type = type;
	icmpResponse->icmp_code = code;
	icmpResponse->unused = 0;
	icmpResponse->next_mtu = 0;

	/* Recompute IP packet sum before copying */
	packetIp->ip_sum = 0;
	packetIp->ip_sum = cksum(packetIp, sizeof(struct sr_ip_hdr));
	memcpy(icmpResponse->data, packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t) + 8);

	icmpResponse->icmp_sum = 0;
	icmpResponse->icmp_sum = cksum(icmpResponse, sizeof(sr_icmp_t3_hdr_t));

	sr_send_packet(sr, response, newLen, interface);
	free(response);
}

/*MISC*/

void processForward(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface) {

	struct sr_ip_hdr *ipHeader = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

	/* Reply with timeout if TTL exceeded */
	ipHeader->ip_ttl = ipHeader->ip_ttl - 1;
	if (ipHeader->ip_ttl == 0) {
		icmp_send_time_exceeded(sr, packet, len, interface);
		return;
	}

	/* At this point, all checks passed, check routing table */
	struct sr_rt *closestMatch = findLongestMatchPrefix(sr->routing_table, ipHeader->ip_dst);

	if (closestMatch == NULL) {
		/* No match found. Send net unreachable */
		icmp_send_net_unreachable(sr, packet, len, interface);

	} else {
		/* Match found. Lookup MAC address in ARP cache */
		struct sr_arpentry *arpEntry = sr_arpcache_lookup(&(sr->cache), ntohl(closestMatch->gw.s_addr));

		if (arpEntry != NULL) {
			/* Found MAC address. Send the packet */
			struct sr_rt *arpClosestMatch = findLongestMatchPrefix(sr->routing_table, ntohl(arpEntry->ip));
			send_packet_to_dest(sr, packet, len, arpClosestMatch->interface, arpEntry->mac, ntohl(arpEntry->ip));

		} else {
			/* Could not find MAC address. Queue request for ARP  */
			sr_arpcache_queuereq(&(sr->cache), ntohl(closestMatch->gw.s_addr), packet, len, interface);
		}
	}
}

int we_are_dest(struct sr_instance *sr, uint32_t ip) {
	struct sr_if *if_list = sr->if_list;
	while (if_list != NULL) {
		if (if_list->ip == ip) {
			return 1;
		}
		if_list = if_list->next;
	}
	return 0;
}