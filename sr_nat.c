
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_nat.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "icmp_handler.h"


int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  /* Initialize any variables here */
	nat->mappings = NULL;
	nat->incoming = NULL;
	nat->nextPort = 1024;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

	pthread_mutex_lock(&(nat->lock));

	/* free nat memory here */
	struct sr_nat_mapping *curr = nat->mappings;
	while (curr != NULL) {
		struct sr_nat_mapping *prev = curr;
		curr = curr->next;
		free(prev);
	}

	struct sr_tcp_syn *incoming = nat->incoming;
	while (incoming != NULL) {
		struct sr_tcp_syn *prev = incoming;
		incoming = incoming->next;
		free(prev);
	}

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
	struct sr_nat *nat = (struct sr_nat *)nat_ptr;
	while (1) {
		sleep(1.0);
		pthread_mutex_lock(&(nat->lock));

		time_t curtime = time(NULL);

		/* Unsolicited incoming SYN timeout */
		struct sr_tcp_syn *incoming = nat->incoming;
		struct sr_tcp_syn *prevIncoming = NULL;
		while (incoming != NULL) {

			if (difftime(curtime, incoming->arrived) >= 6) {
				/* Timeout exceeded. Send ICMP packet */
				icmp_send_port_unreachable(nat->sr, incoming->data, incoming->len, incoming->interface);

				/* Remove entry from incoming list*/
				if (prevIncoming == NULL) {
					nat->incoming = incoming->next;
				} else {
					prevIncoming->next = incoming->next;
				}

				/* Free incoming entry */
				struct sr_tcp_syn *tmp = incoming;
				incoming = incoming->next;
				free(tmp->data);
				free(tmp);			
			
			} else {
				prevIncoming = incoming;
				incoming = incoming->next;
			}		
		}

		/* NAT Mapping timeout */
		struct sr_nat_mapping *mapping = nat->mappings;
		struct sr_nat_mapping *prevMapping = NULL;

		while (mapping != NULL) {			
			int mappingTimeout = 0;

			switch (mapping->type) {
				case nat_mapping_icmp: {
					int diff = difftime(curtime, mapping->last_updated);						

					/* ICMP timed out. Remove entry */				
					mappingTimeout = diff >= (nat->icmpTimeout);	
					break;

				} case nat_mapping_tcp: {
					struct sr_nat_connection *conn = mapping->conns;
					struct sr_nat_connection *prevConn = NULL;

					while (conn != NULL) {
						int diff = difftime(curtime, conn->update_time);

						/* Established: Both SYN recevied, no FIN received */
						int isEstablished = conn->int_syn && conn->ext_syn && !(conn->int_fin) && !(conn->ext_fin);
						int connTimeout = 0;

						if (isEstablished) {
							connTimeout = diff >= nat->tcpEstTimeout;
						} else {
							connTimeout = diff >= nat->tcpTransTimeout;
						}

						if (connTimeout) {
							/* Remove the connection from mapping */
							if (prevConn == NULL) {
								mapping->conns = conn->next;
							} else {	
								prevConn->next = conn->next;
							}

							struct sr_nat_connection *tmp = conn;
							conn = conn->next;
							free(tmp);

							/* No more connections left. Can remove mapping */					
							mappingTimeout = mapping->conns == NULL;	

						} else {
							/* No timeout. Check next connection */
							prevConn = conn;
							conn = conn->next;
						}
					}
					break;
				}
			}

			/* Timeout exceeded on this mapping. Remove it */
			if (mappingTimeout) {
				if (prevMapping == NULL) {
					nat->mappings = mapping->next;
				} else {
					prevMapping->next = mapping->next;
				}

				/* Free memory */
				struct sr_nat_mapping *tmp = mapping;
				mapping = mapping->next;
				free(tmp);

			} else {
				prevMapping = mapping;
				mapping = mapping->next;
			}
		}

		pthread_mutex_unlock(&(nat->lock));
	}

	return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

	pthread_mutex_lock(&(nat->lock));

	/* handle lookup here, malloc and assign to copy */
	struct sr_nat_mapping *copy = NULL;
	struct sr_nat_mapping *curr = nat->mappings;

	while (curr != NULL) {
		if (curr->aux_ext == aux_ext && curr->type == type) {
			/* Found mapping */
			curr->last_updated = time(NULL);
			copy = malloc(sizeof(struct sr_nat_mapping));
			memcpy(copy, curr, sizeof(struct sr_nat_mapping));
			break;						
		}
		curr = curr->next;
	}

	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  	pthread_mutex_lock(&(nat->lock));

  	/* handle lookup here, malloc and assign to copy */
  	struct sr_nat_mapping *copy = NULL;
	struct sr_nat_mapping *curr = nat->mappings;

	while (curr != NULL) {
		if (curr->ip_int == ip_int && curr->aux_int == aux_int && curr->type == type) {
			/* Found mapping */
			curr->last_updated = time(NULL);
			copy = malloc(sizeof(struct sr_nat_mapping));
			memcpy(copy, curr, sizeof(struct sr_nat_mapping));
			break;						
		}
		curr = curr->next;
	}

	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
	uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

	pthread_mutex_lock(&(nat->lock));

	/* handle insert here, create a mapping, and then return a copy of it */
	struct sr_if *externalIf = sr_get_interface(nat->sr, "eth2");
	struct sr_nat_mapping *mapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));

	/* Construct mapping from given values*/
	mapping->type = type;
	mapping->ip_int = ip_int;
	mapping->ip_ext = externalIf->ip;
	mapping->aux_int = aux_int;
	mapping->last_updated = time(NULL);
	mapping->conns = NULL;

	/* Generate external port */
	mapping->aux_ext = htons(nat->nextPort); 
	nat->nextPort = nat->nextPort + 1;
	if (nat->nextPort >= 65535) {
		/* Max ports reached. Restart back at first port */
		nat->nextPort = 1024;
	}

	/* Insert mapping into front of list */
	mapping->next = nat->mappings;
	nat->mappings = mapping;

	/* Create a copy to return*/ 
	struct sr_nat_mapping *copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
	memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

/*	Translate the packet's dest/src IP based on whether it is
		incoming or outcoming	*/
int sr_nat_translate_packet(struct sr_instance* sr,
	uint8_t *packet, unsigned int len, char* interface) {

	struct sr_ip_hdr *ipPacket= (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));
	pkt_dir direction = getPacketDirection(sr, ipPacket);
	uint8_t ip_p = ipPacket->ip_p;

	/* Unsupported protocol: Drop packet */
	if (ip_p != ip_protocol_icmp && ip_p != ip_protocol_tcp) {
		return 1;
	}	

	/* Packet does not cross NAT. Do not need translation */
	if (direction == dir_notCrossing) {
		return 0;
	}

	/* External src trying to reach private IP behind NAT. Block */
	if (direction == dir_blocked) {
		return 1;
	}

	/* At this point, packet is valid for mapping-lookup */

	struct sr_nat_mapping *mapping = sr_nat_get_mapping_from_packet(sr, packet, len, interface, direction);

	/* NULL mapping case */
	if (mapping == NULL) {
		switch(ip_p) {
			case ip_protocol_icmp: {
				/* Packet meant for router. Do nothing to it*/
				return 0;

			} case ip_protocol_tcp: {
				/* packet currently queued, drop it*/
				return 1;
							
			}
		}		
	}

	/* Mapping exists/Packet is valid and must be translated */

	/* Process connections if type is TCP */
	if (mapping->type == nat_mapping_tcp) {
		sr_nat_update_tcp_connection(sr, packet, mapping, direction);
	}

	/* Rewrite the IP, Port, and recompute checksum*/
	switch(ip_p) {
		case ip_protocol_icmp: {
			sr_icmp_hdr_t *icmpPacket = (sr_icmp_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
			
			if (direction == dir_incoming) {
				ipPacket->ip_dst = mapping->ip_int;
				icmpPacket->icmp_identifier = mapping->aux_int;

			} else if (direction == dir_outgoing) {
				ipPacket->ip_src = mapping->ip_ext;
				icmpPacket->icmp_identifier = mapping->aux_ext;
			}

			if (icmpPacket->icmp_type == 3) {
				icmpPacket->icmp_sum = 0;
				icmpPacket->icmp_sum = cksum(icmpPacket, len - sizeof(struct sr_ip_hdr) - sizeof(struct sr_ethernet_hdr));
			} else {
				icmpPacket->icmp_sum = 0;
				icmpPacket->icmp_sum = cksum(icmpPacket, len - sizeof(struct sr_ip_hdr) - sizeof(struct sr_ethernet_hdr));
			}
			break;

		} case ip_protocol_tcp: {
			sr_tcp_hdr_t *tcpPacket = (sr_tcp_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
		
			if (direction == dir_incoming) {
				ipPacket->ip_dst = mapping->ip_int;
				tcpPacket->dest_port = mapping->aux_int;

			} else if (direction == dir_outgoing) {
				ipPacket->ip_src = mapping->ip_ext;
				tcpPacket->src_port = mapping->aux_ext;
			}	
			
			tcpPacket->sum = tcp_cksum(packet, len);				
			break;
		 }
	}

	/* Rewrite the IP checksum */
	ipPacket->ip_sum = 0;
	ipPacket->ip_sum = cksum(ipPacket, sizeof(sr_ip_hdr_t));
	
	free(mapping);
	return 0;
}

void sr_nat_update_tcp_connection(struct sr_instance *sr, uint8_t *packet, struct sr_nat_mapping *mapping, pkt_dir direction) {
	struct sr_nat *nat = sr->nat;
	sr_ip_hdr_t *ipPacket= (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));
	sr_tcp_hdr_t *tcpPacket = (sr_tcp_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

	pthread_mutex_lock(&(nat->lock));

	uint32_t ip;
	uint16_t port;

	/* Get the external ip and port*/
	switch (direction) {
		case dir_incoming: {
			ip = ipPacket->ip_src;
			port = tcpPacket->src_port;
			break;
		} case dir_outgoing: {
			ip = ipPacket->ip_dst;
			port = tcpPacket->dest_port;
			break;
		} default: {
			printf("ERROR at sr_nat_update_tcp_connection: Should never be here 1\n");
			return;
		}
	} 

	/* Get pointer to actual mapping*/
	struct sr_nat_mapping *prevMapping = NULL;
	struct sr_nat_mapping *actual = nat->mappings;
	while (actual != NULL) {
		if (actual->ip_int == mapping->ip_int && actual->aux_int ==  mapping->aux_int && actual->type == mapping->type) {
			mapping = actual;
			break;						
		}
		prevMapping = actual;
		actual = actual->next;
	}
	
	/* Should never print this */
	if (actual == NULL) {
		printf("COULD NOT FIND MAPPING\n");
		return;
	}

	/* Get matching connection. Create new one if it does not exist*/
	struct sr_nat_connection *conn = mapping->conns;
	struct sr_nat_connection *prev = NULL;
	while (conn != NULL) {	
		if (conn->ext_ip == ip && conn->ext_port == port) {
			break;
		}
		prev = conn;
		conn = conn->next;
	}

	if (conn == NULL) {
		conn = (struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));
		conn->ext_ip = ip;
		conn->ext_port = port;
		conn->ext_syn = 0;
		conn->ext_fin = 0;
		conn->ext_fack = 0;
		conn->int_syn = 0;	
		conn->int_fin = 0;	
		conn->int_fack = 0;	
		conn->int_fin_seqnum = 0;
		conn->ext_fin_seqnum = 0;
		conn->next = mapping->conns;
		mapping->conns = conn;
	}

	/* At this point, connection struct exists. Start TCP syncing flags */
	conn->update_time = time(NULL);

	switch (direction) {
		case dir_incoming: {
			if (tcpPacket->flags & TCP_FIN) {
				conn->ext_fin_seqnum = ntohl(tcpPacket->seq_num);
			}

			conn->ext_syn = conn->ext_syn || (tcpPacket->flags & TCP_SYN);
			conn->ext_fin = conn->ext_fin || (tcpPacket->flags & TCP_FIN);
			conn->ext_fack = conn->ext_fack || (conn->int_fin && (conn->int_fin_seqnum < ntohl(tcpPacket->ack_num)));
			break;
			
		} case dir_outgoing: {
			if (tcpPacket->flags & TCP_FIN) {
				conn->int_fin_seqnum = ntohl(tcpPacket->seq_num);
			}

			conn->int_syn = conn->int_syn || (tcpPacket->flags & TCP_SYN);	
			conn->int_fin = conn->int_fin || (tcpPacket->flags & TCP_FIN);	
			conn->int_fack = conn->int_fack || (conn->ext_fin && (conn->ext_fin_seqnum < ntohl(tcpPacket->ack_num)));
			break;
	
		} default: {
			printf("ERROR at sr_nat_update_tcp_connection: Should never be here 2\n");
			return;
		}
	} 

	/* Check if connection needs to be closed */
	if ((tcpPacket->flags & TCP_RST) || (conn->int_fack && conn->ext_fack)) {
		/* Remove this connection from mapping */
		if (prev == NULL) {
			mapping->conns = conn->next;
		} else {
			prev->next = conn->next;
		}
		free(conn);

		/* Cleanup mapping if no more connections*/	
		if (mapping->conns == NULL) {
			if (prevMapping == NULL) {
				nat->mappings = mapping->next;
			} else {
				prevMapping->next = mapping->next;
			}
			free(mapping);
		}
	}	

	pthread_mutex_unlock(&(nat->lock));
}

struct sr_nat_mapping *sr_nat_get_mapping_from_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface, pkt_dir direction) {
	
	struct sr_ip_hdr *ipPacket= (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

	struct sr_nat_mapping *mapping = NULL;
	uint16_t port = 0;
	sr_nat_mapping_type mappingType = 0;		

	/* Get the type and port from the packet */
	switch(ipPacket->ip_p) {
		case ip_protocol_icmp: {
			sr_icmp_hdr_t *icmpPacket = (sr_icmp_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
			mappingType =  nat_mapping_icmp;
			port = icmpPacket->icmp_identifier;
			break;

		} case ip_protocol_tcp: {
			sr_tcp_hdr_t *tcpPacket = (sr_tcp_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
			mappingType = nat_mapping_tcp;
			if (direction == dir_incoming) {
				port = tcpPacket->dest_port;
			} else if (direction == dir_outgoing) {
				port = tcpPacket->src_port;
			}			
			break;
		 }
	}

	/* Get mapping based on direction */
	switch (direction) {
		case dir_incoming: {
			mapping = sr_nat_lookup_external(sr->nat, port, mappingType);
			
			if (mapping == NULL) {
				/* Do nothing for ICMP */

				if (mappingType == nat_mapping_tcp) {
					sr_tcp_hdr_t *tcp = (sr_tcp_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
					
					/* Queue unsolicited incoming SYN TCP packets */
					if (tcp->flags & TCP_SYN) {
						pthread_mutex_lock(&(sr->nat->lock));

						/* Check if this TCP packet is already waiting */	
						struct sr_tcp_syn *incoming = sr->nat->incoming;					
						while (incoming != NULL) {
							if ((incoming->ip_src == ipPacket->ip_src) && (incoming->port_src == tcp->src_port)) {
								break;
							}
							incoming = incoming->next;
						}			

						if (incoming == NULL) {
							/* this connection not waiting. Add into waiting packets */
							struct sr_tcp_syn *newTcp = (struct sr_tcp_syn *) malloc(sizeof(struct sr_tcp_syn));
							newTcp->ip_src = ipPacket->ip_src;
							newTcp->port_src = tcp->src_port;
							newTcp->arrived = time(NULL);

							newTcp->len = len;
							newTcp->interface = interface;
							newTcp->data = (uint8_t *) malloc(len);
							memcpy(newTcp->data, packet, len);

							/* Put new packet at front of list */
							newTcp->next = sr->nat->incoming;
							sr->nat->incoming = newTcp;
						}	

						pthread_mutex_unlock(&(sr->nat->lock));
					}
				}
			}
			break;

		} case dir_outgoing: {
			mapping = sr_nat_lookup_internal(sr->nat, ipPacket->ip_src, port, mappingType);

			if (mapping == NULL) {				

				/* Additional TCP processing */
				if (mappingType == nat_mapping_tcp) {
					sr_tcp_hdr_t *tcp = (sr_tcp_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
			
					if (tcp->flags & TCP_SYN) {
						pthread_mutex_lock(&(sr->nat->lock));

						struct sr_tcp_syn *incoming = sr->nat->incoming;
						struct sr_tcp_syn *prev = NULL;

						/* Check if this TCP packet is already waiting */						
						while (incoming != NULL) {
							if ((incoming->ip_src == ipPacket->ip_dst) && (incoming->port_src == tcp->dest_port)) {

								/* Silently drop matching incoming SYN packet */
								if (prev != NULL) {
									prev->next = incoming->next;
								} else {
									sr->nat->incoming = incoming->next;
								}	
								break;								
							}

							prev = incoming;
							incoming = incoming->next;
						}

						pthread_mutex_unlock(&(sr->nat->lock));
					} else {
						/* No existing mapping for non-SYN TCP packet. Drop it */
						return NULL;
					}
				}

				/* Create new mapping for this IP/Port entry */
				mapping = sr_nat_insert_mapping(sr->nat, ipPacket->ip_src, port, mappingType);
			}
			break;

		} default: {
			printf("ERROR: Should never be here\n");
			break;			
		}
	}

	return mapping;
}

pkt_dir getPacketDirection(struct sr_instance* sr, struct sr_ip_hdr *ipPacket) {
	int internalSrc = is_ip_within_nat(sr, ipPacket->ip_src);
	int internalDest = is_ip_within_nat(sr, ipPacket->ip_dst);

	struct sr_if* if_eth2 = sr_get_interface(sr, "eth2");	
	int destIsNat = ipPacket->ip_dst == if_eth2->ip;	

	/* INCOMING: src is outside NAT. Dest is eth2*/
	if (!internalSrc && destIsNat) {
		return dir_incoming;
	}

	/* UNKNOWN DEST IP: Do nothing to this packet */
	if (internalDest < 0) {
		return dir_notCrossing;
	}

	/* BLOCKED: Destination is private, source is external */
	if (!internalSrc && internalDest) {
		return dir_blocked;
	}

	/* OUTCOMING: src is inside NAT. Dest is outside NAT */
	if (internalSrc && !internalDest) {
		return dir_outgoing;
	}

	/* NOTCROSSING: src/dest is inside NAT or src/dest is outside NAT */
	return dir_notCrossing;
}

int is_ip_within_nat(struct sr_instance *sr, uint32_t ip) {
	struct sr_rt *closest = findLongestMatchPrefix(sr->routing_table, ip);
	if (closest == NULL) {
		/* Net unreachable. Do nothing to this packet */
		return -1;

	} else {		
		/* Check if this IP uses eth1 */
		if (strncmp(closest->interface, "eth1", 4) == 0) {
			return 1;
		}
	}
	return 0;
}
