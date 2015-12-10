#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"

uint16_t tcp_cksum(uint8_t *packet, int len) {
	sr_ip_hdr_t *ip = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
	sr_tcp_hdr_t *tcp = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

	/* init */
	size_t tcpLen = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
	size_t buffLen = sizeof(sr_tcp_pseudo_hdr_t) + tcpLen;
	uint8_t *buff = (uint8_t *) malloc(buffLen);
	memset(buff, 0, buffLen);

	/* Create pseudoheader */
	sr_tcp_pseudo_hdr_t *pseudoHdr = (sr_tcp_pseudo_hdr_t *) malloc(sizeof(sr_tcp_pseudo_hdr_t));
	pseudoHdr->ip_src = ip->ip_src;
	pseudoHdr->ip_dst = ip->ip_dst;
	pseudoHdr->reserved = 0;
	pseudoHdr->protocol = ip->ip_p;
	pseudoHdr->len = htons(tcpLen);
	memcpy(buff, pseudoHdr, sizeof(sr_tcp_pseudo_hdr_t));

	/* Copy tcp packet into buffer */
	tcp->sum = 0;
	memcpy(buff + sizeof(sr_tcp_pseudo_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), tcpLen);

	uint16_t checksum = cksum(buff, buffLen);

	free(pseudoHdr);
	free(buff);
	return checksum;

}

struct sr_rt *findLongestMatchPrefix(struct sr_rt *rt, uint32_t ip_dst) {
	struct sr_rt *closestMatch = NULL;
	while (rt != NULL) {
		uint32_t mask = rt->mask.s_addr;
		if ((ip_dst & mask) == (rt->dest.s_addr & mask)) {
			if (closestMatch == NULL || (mask > closestMatch->mask.s_addr)) {
				closestMatch = rt;
			}
		}
		rt = rt->next;
	}
	return closestMatch;
}

/*
 * Verify if this packet was broadcast
 * MAC address must match ff-ff-ff-ff-ff-ff
 */
int is_broadcast_mac(uint8_t * packet) {
	sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) packet;

	int i;
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		if (ehdr->ether_dhost[i] != 0xff) {
			return 0;
		}
	}
	return 1;
}

/*
 * Verify packet is of right length for an ICMP packet
 * and that checksum is valid
 */
int is_sane_icmp_packet(uint8_t *packet, unsigned int len) {

	/* Check packet size is valid */
	if (len < (sizeof(struct sr_icmp_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr))) {
		printf("ICMP Packet is too small %d) \n", len);
		return 0;
	}

	struct sr_icmp_hdr *icmpHeader = (struct sr_icmp_hdr *) (packet + sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr));

	/* Verify checksum */
	uint16_t actual = icmpHeader->icmp_sum;
	icmpHeader->icmp_sum = 0;
	uint16_t expected = cksum(icmpHeader, len - sizeof(struct sr_ip_hdr) - sizeof(struct sr_ethernet_hdr));

	if (expected != actual) {
		printf("ICMP Expected checksum(%d) does not match given checksum(%d) \n", expected, actual);
		return 0;
	}

	/* Packet passes sanity checks */
	return 1;
}

/*
 * Verify packet is of right length for an ip packet
 * and that checksum is valid
 */
int is_sane_ip_packet(uint8_t *packet, unsigned int len) {

	/* Check packet size is valid */
	if (len < (sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr))) {
		printf("IP Packet is too small %d) \n", len);
		return 0;
	}

	struct sr_ip_hdr *ipHeader = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

	/* Verify checksum */
	uint16_t actual = ipHeader->ip_sum;
	ipHeader->ip_sum = 0;
	uint16_t expected = cksum(ipHeader, sizeof(struct sr_ip_hdr));

	if (expected != actual) {
		printf("IP Expected checksum(%d) does not match given checksum(%d) \n", expected, actual);
		return 0;
	}

	/* Packet passes sanity checks */
	return 1;
}

uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}


uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

