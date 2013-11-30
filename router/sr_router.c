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
#include <string.h>
#include <stdlib.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#include "sr_nat.h"

int sr_checkIPchecksum(sr_ip_hdr_t *iphdr);
void sr_handleIPforwarding(struct sr_instance* sr,
			   uint8_t * packet/* lent */,
			   unsigned int len,
			   char* interface/* lent */);
void sr_sendARPRequst(struct sr_instance* sr, struct sr_arpreq* req,
		      char* interface);
void sr_handleARPReply(struct sr_instance* sr,
		       sr_ethernet_hdr_t *old_ethhdr/* lent */,
		       sr_arp_hdr_t *arphdr,
		       char* interface);
void setICMPNormal(sr_icmp_hdr_t *new_icmphdr,
		   uint8_t icmp_type,
		   uint8_t icmp_code);
void setICMPHeader(sr_icmp_t3_hdr_t *new_icmphdr,
		   uint8_t type,
		   uint8_t code);
void setIPHeaderAsReply(sr_ip_hdr_t *new_iphdr, sr_ip_hdr_t *old_iphdr,
			uint16_t ip_len,uint8_t ip_p, struct sr_if *cur_interface);
void setEthernetHeader(sr_ethernet_hdr_t *new_ethhdr,
		       uint8_t *ether_dhost,
		       struct sr_if *cur_interface,
		       uint16_t ether_type);
void sr_sendICMPPingRep(struct sr_instance *sr, 
			uint8_t *packet,
			unsigned int len,
			char * interface);
void sr_sendICMPMsg(struct sr_instance * sr,
		    uint8_t icmp_type,
		    uint8_t icmp_code,
		    char * interface, 
		    uint8_t * old_packet,
		    unsigned int len);
void sr_sendARPreply(struct sr_instance* sr,
		     sr_ethernet_hdr_t *ethhdr/* lent */,
		     sr_arp_hdr_t *arphdr,
		     char* interface);

int sr_checkInterface(struct sr_instance * sr, uint32_t target);
int sr_checkICMPchecksum(sr_icmp_hdr_t *icmp_hdr, int len);

void sr_sendNATpacket(struct sr_instance* sr,
			   uint8_t * packet/* lent */,
			   unsigned int len,
			   char* interface/* lent */);
			   
void sr_receiveNATpacket(struct sr_instance* sr,
			   uint8_t * packet/* lent */,
			   unsigned int len,
			   char* interface/* lent */);


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
	
	int result = sr_load_rt(sr, "rtable");
	if (result) {
		fprintf(stderr, "Failed loading routing table..");
		return;
	}
	
} /* -- sr_init -- */

void sr_enable_NAT(struct sr_instance* sr, int nat_enable)
{
	sr_nat_init(sr->nat);
	sr->nat_enable = 1;
	/* set internal external iface for nat */
		
	sr->nat->int_iface =  sr_get_interface(sr,"eth1");
	sr->nat->ext_iface =  sr_get_interface(sr,"eth2");
	
}

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
	
	printf("\n*********Raw*************\n");
	print_hdrs(packet, len);
	printf("**********************\n\n");
	/* fill in code here */
	int result;
	
	if (len > 1514){
		fprintf(stderr, "Failed to handle ETHERNET packet, max MTU exceeded\n");
		return;
	}
	
	/* Ethernet length checking */
	int minlength = sizeof(sr_ethernet_hdr_t);
	if (len < minlength) {
		fprintf(stderr, "Failed to handle ETHERNET packet, insufficient packet length\n");
		return;
	}
	
	sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) packet;
	
	/* get the ethernet type */
	uint16_t ethtype = ethertype((uint8_t *) ehdr);
	switch (ethtype) {
		
		case ethertype_ip:
			
			/* IP Length checking */
			minlength += sizeof(sr_ip_hdr_t);
			if (len < minlength) {
				fprintf(stderr, "Failed to parse IP header, insufficient length\n");
				return;
			}
			
			sr_ip_hdr_t *iphdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
			
			/* Checking checksum for IP */
			result = sr_checkIPchecksum(iphdr);
			if (result) {
				fprintf(stderr, "Failed to handle IP packet, incorrent IP checksum\n");
				return;
			}
			
			if (iphdr->ip_v != 4) {
				fprintf(stderr, "Failed to parse IP header, version is not IPv4\n");
				return;
			}
			
			struct sr_if* cur_interface =  sr_get_interface(sr,interface);
			if (cur_interface == NULL){
				fprintf(stderr, "Can't get current interface from the list in the router\n");
				return;
			}
			
			if (sr_checkInterface(sr, iphdr->ip_dst)){
				/* If it's an ICMP protocol */
				
				if (sr->nat_enable && iphdr->ip_dst == sr->nat->ext_iface->ip){
						/* Some one send packet to NAT client*/
						sr_receiveNATpacket(sr, packet, len, interface);
						return;
				}		
				
				if (ip_protocol((uint8_t *) iphdr) == ip_protocol_icmp) {
					/* Checking checksum for ICMP */
					
					minlength += sizeof(sr_icmp_hdr_t);
					if (len < minlength) {
						fprintf(stderr, "Failed to parse ICMP header, insufficient length\n");
						return;
					}
					
					sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
					
					result = sr_checkICMPchecksum(icmphdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
					if (result) {
						fprintf(stderr, "Incorrent ICMP checksum for the ping to the router\n");
						return;
					}
					
					sr_sendICMPPingRep(sr, packet, len, interface);
					return;
				}else if (ip_protocol((uint8_t *) iphdr) == 0x06 || ip_protocol((uint8_t *) iphdr) == 0x11){
					/* If this is an TCP/UDP packet for the router, reply ICMP port unreachable */
					sr_sendICMPMsg(sr,3,3,interface,packet,len);
					return;
				} else {
					/* This is not a ping or TCP/UDP ip packet, just return*/
					return;
				}
			}else{
				/* Do IP forwarding*/
				/* Checking TTL*/
				if (iphdr->ip_ttl == 1 || iphdr->ip_ttl == 0) {
					sr_sendICMPMsg(sr,11,0,interface,packet,len);
					return;
				}
				
				if (sr->nat_enable && (strcmp(interface, "eth1") == 0)){
					sr_sendNATpacket(sr, packet, len, interface);
					return;
				}
				
				sr_handleIPforwarding(sr, packet, len, interface);
				return;
			}
			break;
			/* I'm an ARP packet */
		case ethertype_arp:
			minlength += sizeof(sr_arp_hdr_t);
			if (len < minlength) {
				fprintf(stderr, "Failed to parse ARP header, insufficient length\n");
				return;
			}
			sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
				
			switch (ntohs(arp_hdr->ar_op)) {
				case (arp_op_request):
					sr_sendARPreply(sr, ehdr, arp_hdr,interface);
					return;
				case (arp_op_reply):
					sr_handleARPReply(sr, ehdr, arp_hdr, interface);
					return;
				default:
					fprintf(stderr, "Unknown ARP op type");
					return;
			}
		default:
			fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
			return;
	}
	
	return;
	
}/* end sr_ForwardPacket */

/**
 * Send out ARP reply with the arp header and interface.
 */
void sr_sendARPreply(struct sr_instance* sr,
		     sr_ethernet_hdr_t *ethhdr/* lent */,
		     sr_arp_hdr_t *arphdr,
		     char* interface)
{
	uint8_t *new_packet = (uint8_t *)malloc(sizeof (sr_ethernet_hdr_t) + sizeof (sr_arp_hdr_t));
	
	sr_ethernet_hdr_t *new_ethhdr = (sr_ethernet_hdr_t *) new_packet;
	sr_arp_hdr_t *new_arphdr = (sr_arp_hdr_t *)(new_packet +
	sizeof(sr_ethernet_hdr_t));
	
	/* setup ethhder */
	int i = 0;
	struct sr_if* cur_interface =  sr_get_interface(sr,interface);
	for (i = 0; i < ETHER_ADDR_LEN;i++){
		new_ethhdr->ether_dhost[i] = ethhdr->ether_shost[i];
		new_ethhdr->ether_shost[i] = cur_interface->addr[i];
	}
	new_ethhdr->ether_type = ntohs(ethertype_arp);
	
	/* setup arphdr */
	new_arphdr->ar_hrd = arphdr->ar_hrd;
	new_arphdr->ar_pro = arphdr->ar_pro;
	new_arphdr->ar_hln = arphdr->ar_hln;
	new_arphdr->ar_pln = arphdr->ar_pln;
	new_arphdr->ar_op = ntohs(arp_op_reply);
	
	for (i = 0; i < ETHER_ADDR_LEN;i++){
		new_arphdr->ar_sha[i] = cur_interface->addr[i];
		new_arphdr->ar_tha[i] = arphdr->ar_sha[i];
	}
	new_arphdr->ar_sip = cur_interface->ip;
	new_arphdr->ar_tip = arphdr->ar_sip;
	
	sr_send_packet(sr, new_packet, sizeof (sr_ethernet_hdr_t) +
	sizeof (sr_arp_hdr_t),interface);
}

/**
 * Send out ARP Request for the arp request
 */
void sr_sendARPRequst(struct sr_instance* sr, struct sr_arpreq *req,
		      char* interface)
{
	uint8_t *new_packet = (uint8_t *) malloc(sizeof (sr_ethernet_hdr_t) +
	sizeof (sr_arp_hdr_t));
	
	sr_ethernet_hdr_t *new_ethhdr = (sr_ethernet_hdr_t *) new_packet;
	sr_arp_hdr_t *new_arphdr = (sr_arp_hdr_t *)(new_packet +
	sizeof(sr_ethernet_hdr_t));
	
	/* setup ethhder */
	struct sr_if* cur_interface =  sr_get_interface(sr, interface);
	int i;
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		/* Source is the interface mac address */
		new_ethhdr->ether_shost[i] = (uint8_t) cur_interface->addr[i];
		/* Destination is fffffff */
		new_ethhdr->ether_dhost[i] = 0xff;
	}

	new_ethhdr->ether_type = ntohs(ethertype_arp);
	
	/* setup arphdr */
	new_arphdr->ar_hrd = ntohs(arp_hrd_ethernet);
	new_arphdr->ar_pro = ntohs(0x0800);
	new_arphdr->ar_hln = ETHER_ADDR_LEN;
	new_arphdr->ar_pln = 4; /*ip_hl*/
	new_arphdr->ar_op = ntohs(arp_op_request);
	
	for (i = 0; i < ETHER_ADDR_LEN;i++){
		new_arphdr->ar_sha[i] = cur_interface->addr[i];
		new_arphdr->ar_tha[i] = 0x0;
	}
	
	new_arphdr->ar_sip = cur_interface->ip;
	new_arphdr->ar_tip = req->ip;
	sr_send_packet(sr, new_packet, sizeof (sr_ethernet_hdr_t) + sizeof (sr_arp_hdr_t), interface);
}

/*
 * Find an entry for the ip address in the routing table, return NULL if not found.
 */
struct sr_rt *sr_findMatchInRoutingTable(struct sr_rt *rt_entry, uint32_t ip)
{
	/* -------------- IP FORWARDING -----------------------------------------*/
	/* Find out which entry in the routing table has the longest prefix match
	 * with the destination IP address. - next-hop IP address*/
	struct sr_rt* match_rt_entry = NULL;
	while (rt_entry != NULL)
	{
		/* Use gateway ip to find the longest matching ip */
		uint32_t cur_gw = *(uint32_t*) & rt_entry->gw;
		uint32_t cur_mask = *(uint32_t*) & rt_entry->mask;
		
		/* Find a match */
		if ((cur_gw & cur_mask) == (cur_mask & ip))
		{
			/* No previous match */
			if (match_rt_entry == NULL) {
				match_rt_entry = rt_entry;
				/* There is a previous match, get the match with the longer mask */
			} else {
				uint32_t match_mask = *(uint32_t*) & match_rt_entry->mask;
				if (cur_mask > match_mask) {
					match_rt_entry = rt_entry;
				}
			}
		}
		rt_entry = rt_entry->next;
	}
	return match_rt_entry;
}

/**
 * Handle IP forwarding:
 * packet:		packet to forward (ethernet)
 * len:			length of packet
 * interface:	interface of coming packet
 */
void sr_handleIPforwarding(struct sr_instance* sr,
			   uint8_t * packet/* lent */,
			   unsigned int len,
			   char* interface/* lent */)
{
	sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) packet;
	sr_ip_hdr_t *iphdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
	
	/* Decrement TTL */
	iphdr->ip_ttl = iphdr->ip_ttl - 1;
	
	/* Recalculate checksum */
	iphdr->ip_sum = 0;
	iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
	
	struct sr_rt *match_rt_entry = sr_findMatchInRoutingTable(sr->routing_table, iphdr->ip_dst);
	
	if (match_rt_entry == NULL) {
		sr_sendICMPMsg(sr,3,0, interface, packet,len);
		return;
	}
	struct sr_if *next_interface = sr_get_interface(sr, match_rt_entry->interface);
	/* Check the ARP cache for the next-hop MAC address corresponding
	 * to the next-hop IP. - next-hop MAC address*/
	struct sr_arpentry *next_arp_entry;
	next_arp_entry = sr_arpcache_lookup(&sr->cache, iphdr->ip_dst);
	/* If it's there, send it.*/
	if (next_arp_entry != NULL) {
		/* put next hop mac in ethernet frame */
		int i;
		for (i = 0; i < ETHER_ADDR_LEN;i++){
			ehdr->ether_shost[i] = next_interface->addr[i];
			ehdr->ether_dhost[i] = next_arp_entry->mac[i];
		}
		/* send the packet */
		sr_send_packet(sr, packet, len, match_rt_entry->interface);
		/* Sending packet fails, free the pointer */
		free((void *) next_arp_entry);
	}else{
		/* Otherwise, send an ARP request for the next-hop IP (if one
		 * hasn't been sent within the last second), */
		/* Send ARP Request for destinating ip */
		struct sr_arpreq *req;
		req = sr_arpcache_queuereq(&sr->cache, iphdr->ip_dst, packet, len,
					   next_interface->name);
		sr_handle_arpreq(sr,req);
	}
	return;
}

/**
 * Check if the checksum in IP header is correct; Return 0 if it's correct and 1 otherwise.
 */
int sr_checkIPchecksum(sr_ip_hdr_t *iphdr){
	
	sr_ip_hdr_t *buff = malloc(sizeof(sr_ip_hdr_t));
	int ip_sum = iphdr->ip_sum;
	memcpy(buff, iphdr, sizeof(sr_ip_hdr_t));
	buff->ip_sum = 0;
	
	if (cksum(buff,  sizeof(sr_ip_hdr_t)) != ip_sum) {
		free(buff);
		return 1;
	}
	
	free(buff);
	return 0;
}

/**
 * Check if the checksum in t3 ICMP header is correct; Return 0 if it's correct and 1 otherwise.
 */
int sr_checkICMPchecksum(sr_icmp_hdr_t *icmp_hdr, int len){
	
	sr_icmp_hdr_t *buff = (sr_icmp_hdr_t *) malloc(len);
	int sum = icmp_hdr->icmp_sum;
	memcpy(buff, icmp_hdr, len);
	buff->icmp_sum = 0;
	
	if (cksum(buff,  len) != sum) {
		free(buff);
		return 1;
	}
	
	free(buff);
	return 0;
}

/**
 * Handle ARP Request: send ARP
 */
void sr_handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req) {
	
	if (!req->sent){req->sent = 0;}
	
	time_t *now_time = malloc(sizeof(time_t));
	time(now_time);
	
	/* Request sent time is greater than 1.0 second before */
	if (difftime(*now_time, req->sent) > 1.0){
		/* Greater than 5 times sent, send an ICMP host unreachable error */
		if (req->times_sent >= 5){
			struct sr_packet *pkt = req->packets;
			
			while (pkt != NULL){
				/* Host unreachable: Do not send ICMP message for ICMP Error Message */
				sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) pkt->buf;
				sr_ip_hdr_t *iphdr = (sr_ip_hdr_t*) (pkt->buf + sizeof(sr_ethernet_hdr_t));
				
				if (iphdr->ip_p == ip_protocol_icmp) {
					sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *) (iphdr + sizeof(sr_icmp_hdr_t));
					/* Do not generate ICMP error messages for ICMP error Messages */
					uint8_t type;
					type = icmphdr->icmp_type;
					
					
					if (type == 3 ||type == 4 ||type == 5 ||type == 11 || type == 12){
						pkt = pkt->next;
						continue;
					}
				}
				
				/* Make a new ethernet packet with ICMP for IP forwarding */
				
				struct sr_rt *entry = sr_findMatchInRoutingTable(sr->routing_table, iphdr->ip_src);
				
				uint8_t *new_packet = (uint8_t *) malloc(sizeof (sr_ethernet_hdr_t) +
				sizeof (sr_ip_hdr_t) +
				sizeof(sr_icmp_t3_hdr_t));
				
				sr_ethernet_hdr_t *new_ethdr = (sr_ethernet_hdr_t*) (new_packet);
				setEthernetHeader(new_ethdr, ehdr->ether_shost,sr_get_interface(sr, entry->interface),ethertype_ip);
				
				sr_ip_hdr_t *new_iphdr = (sr_ip_hdr_t*) (new_packet + sizeof(sr_ethernet_hdr_t));
				
				/* Change the destination of the IP packet to be the old source */
				/* Change the source to be the interface's ip */
				
				setIPHeaderAsReply(new_iphdr, iphdr,sizeof (sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t),
						   ip_protocol_icmp, sr_get_interface(sr, entry->interface));
				/* Now make the body to be an ICMP message */
				sr_icmp_t3_hdr_t * new_icmp = (sr_icmp_t3_hdr_t*) (new_packet + sizeof (sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
				
				/* Copy the old ip header */
				memcpy(new_icmp->data, iphdr, ICMP_DATA_SIZE);
				setICMPHeader(new_icmp, 3, 1);
				
				/* And then use IP forwarding to send out packet */
				sr_handleIPforwarding(sr, new_packet/* lent */,	sizeof (sr_ethernet_hdr_t) +
				sizeof (sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), entry->interface);
				
				pkt = pkt->next;
			}
			/* Destory the corresponding ARP request */
			sr_arpreq_destroy(&sr->cache, req);
		} else {
			/* Broadcast ARP request */
			struct sr_if *interface_entry = sr->if_list;
			
			while (interface_entry != NULL){
				sr_sendARPRequst(sr, req, interface_entry->name);
				interface_entry = interface_entry->next;
			}
			req->sent = *now_time;
			req->times_sent++;
		}
	}
}

/**
 * handle ARP reply with the arp header and interface.
 */
void sr_handleARPReply(struct sr_instance* sr,
		       sr_ethernet_hdr_t *old_ethhdr/* lent */,
		       sr_arp_hdr_t *arphdr,
		       char* interface)
{	
	struct sr_arpreq *req = NULL;
	
	req = sr_arpcache_insert(&sr->cache, arphdr->ar_sha, arphdr->ar_sip);
	
	if (req != NULL) {
		struct sr_packet *pkts = req->packets;
		int i;
		while (pkts != NULL) {
			sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) (pkts->buf);
			
			struct sr_if* pkt_interface =  sr_get_interface(sr,pkts->iface);
			
			/* Put in the mac address */
			for (i = 0; i < ETHER_ADDR_LEN; i++) {
				ehdr->ether_dhost[i] = (uint8_t) arphdr->ar_sha[i];
				ehdr->ether_shost[i] = (uint8_t) pkt_interface->addr[i];
			}
			
			int result = sr_checkIPchecksum((sr_ip_hdr_t*) (pkts->buf + sizeof(sr_ethernet_hdr_t)));
			if (result) {
				fprintf(stderr, "incorrent IP checksum packet\n");
				return;
			}
			
			sr_send_packet(sr, pkts->buf, pkts->len, pkts->iface);
			pkts = pkts->next;
		}
		sr_arpreq_destroy(&sr->cache, req);
	}
	return;
}

/* 
 * Send ICMP ping reply, which is type 0
 */
void sr_sendICMPPingRep(struct sr_instance *sr, 
			uint8_t *packet,
			unsigned int len,
			char * interface)
{
	sr_ethernet_hdr_t *new_ethhdr = (sr_ethernet_hdr_t *) packet;
	sr_ip_hdr_t *new_iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	sr_icmp_hdr_t *new_icmphdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	
	struct sr_if* cur_interface =  sr_get_interface(sr, interface);
	if (cur_interface == NULL) return;

	/* Set ethernet header and IP header for the new packet */
	setEthernetHeader(new_ethhdr, new_ethhdr->ether_shost, cur_interface, ethertype_ip);
	setIPHeaderAsReply(new_iphdr, new_iphdr, len - sizeof(sr_ethernet_hdr_t), ip_protocol_icmp, cur_interface);
	
	setICMPNormal(new_icmphdr, 0, 0);
	
	sr_send_packet(sr, packet, len, interface);
}

/*
 * Given the ethernet packet receieved, send an ICMP message to the source
 * with the type and code
 */
void sr_sendICMPMsg(struct sr_instance * sr,
		    uint8_t icmp_type,
		    uint8_t icmp_code,
		    char * interface, 
		    uint8_t * old_packet,
		    unsigned int len)
{	
	/* The ICMP error msg has the following structure: */
	/* |eth header| ip header | icmp header | old ip header | first 8 bytes of payload | */
	
	uint8_t *new_packet = (uint8_t *) malloc(sizeof (sr_ethernet_hdr_t) + sizeof (sr_ip_hdr_t) +  sizeof(sr_icmp_t3_hdr_t));
	
	sr_ethernet_hdr_t *new_ethhdr = (sr_ethernet_hdr_t *) new_packet;
	sr_ip_hdr_t *new_iphdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
	
	struct sr_if* cur_interface =  sr_get_interface(sr, interface);
	
	/* setup ethhder */
	sr_ethernet_hdr_t *old_ethhdr = (sr_ethernet_hdr_t *) old_packet;
	setEthernetHeader(new_ethhdr, old_ethhdr->ether_shost, cur_interface, ethertype_ip);
	
	/* Set up IP */
	sr_ip_hdr_t *old_iphdr = (sr_ip_hdr_t *) (old_packet + sizeof(sr_ethernet_hdr_t));
	/* Here the payload is the ICMP Message */
	setIPHeaderAsReply(new_iphdr, old_iphdr,
			   (sizeof (sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)),
			   ip_protocol_icmp, cur_interface);
	
	/* Set up ICMP */
	sr_icmp_t3_hdr_t *new_icmphdr = (sr_icmp_t3_hdr_t *)(new_packet +
	sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	
	/* Copy the old ip header */
	memcpy(new_icmphdr->data, old_packet + sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
	setICMPHeader(new_icmphdr, icmp_type, icmp_code);
	
	sr_send_packet(sr, new_packet, sizeof (sr_ethernet_hdr_t) +
	sizeof (sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
	
	return;
}

/*
 * Return 1 if the interface is one of the router's, 0 otherwise.
 */
int sr_checkInterface(struct sr_instance * sr, uint32_t target){
	struct sr_if* if_walker = 0;
	if_walker = sr->if_list;
	
	while(if_walker)
	{
		if(if_walker->ip == target)
		{ return 1; }
		if_walker = if_walker->next;
	}
	return 0;
}

/*
 * Set up a ICMP header, autocalculate checksum
 */
void 
setICMPNormal(sr_icmp_hdr_t *new_icmphdr,
	      uint8_t icmp_type,
	      uint8_t icmp_code)
{
	/* Setup ICMP */
	new_icmphdr->icmp_type = ntohs(icmp_type);
	new_icmphdr->icmp_code = ntohs(icmp_code);
	new_icmphdr->icmp_sum = 0;
	new_icmphdr->icmp_sum = cksum(new_icmphdr, sizeof (sr_icmp_hdr_t));
	return;
}

/*
 * Set up a t3 ICMP header for error ICMP messages, autocalculate checksum
 */
void setICMPHeader(sr_icmp_t3_hdr_t *new_icmphdr,
		   uint8_t type,
		   uint8_t code)
{
	new_icmphdr->icmp_code = code;
	new_icmphdr->icmp_type = type;
	new_icmphdr->icmp_sum = 0;
	new_icmphdr->unused = 0;
	new_icmphdr->next_mtu = 0;
	new_icmphdr->icmp_sum = cksum(new_icmphdr, sizeof(sr_icmp_t3_hdr_t));
	return;
}

/*
 * Given a pointer to an IP header, set the IP header as the reply for
 * the old_iphdr with the interface.
 *
 * default TTL: 64
 * source as interface's ip; target as the source of the old ip header.
 */
void
setIPHeaderAsReply(sr_ip_hdr_t *new_iphdr, sr_ip_hdr_t *old_iphdr,
		   uint16_t ip_len,uint8_t ip_p, struct sr_if *cur_interface)
{
	memcpy(new_iphdr,old_iphdr, sizeof(sr_ip_hdr_t));
	new_iphdr->ip_len = ntohs(ip_len);
	new_iphdr->ip_ttl = 64; /* 64 */
	new_iphdr->ip_dst = old_iphdr->ip_src;
	new_iphdr->ip_src = cur_interface->ip;
	new_iphdr->ip_p = ip_p;
	new_iphdr->ip_sum = 0;
	new_iphdr->ip_sum = cksum(new_iphdr, sizeof (sr_ip_hdr_t));
	return;
}

/*
 * Set the new ethernet hdr as reply of the old one.
 */
void
setEthernetHeader(sr_ethernet_hdr_t *new_ethhdr, uint8_t *ether_dhost,
		  struct sr_if *cur_interface, uint16_t ether_type)
{
	int i;
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		/* Destination is the sender */
		new_ethhdr->ether_dhost[i] = ether_dhost[i];
		
		/* Source is the interface mac address */
		new_ethhdr->ether_shost[i] = (uint8_t) cur_interface->addr[i];
		
	}
	new_ethhdr->ether_type = ntohs(ether_type);
	return;
}

/*
 * Set the new ethernet hdr as reply of the old one.
 */
void
sr_sendNATpacket(struct sr_instance* sr,
			   uint8_t * packet/* lent */,
			   unsigned int len,
			   char* interface/* lent */)
{
	/* NAT before forwarding */
	printf("Send NAT\n");
	
	sr_ip_hdr_t *iphdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
	
	if (sr->nat_enable && (strcmp(interface,"eth1") == 0)){
		/* from internal interface */
		
		struct sr_nat_mapping *tmp;
		sr_nat_mapping_type packet_type;
		
		print_hdrs(packet,len);
		
		switch (iphdr->ip_p){
			case ip_protocol_icmp:
				/* ICMP */
				packet_type = nat_mapping_icmp;
				sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
				tmp = sr_nat_lookup_internal(sr->nat,iphdr->ip_src,icmphdr->icmp_id,packet_type);
				if (tmp == NULL){
					tmp = sr_nat_insert_mapping(sr->nat,iphdr->ip_src,icmphdr->icmp_id,packet_type);

				}
				iphdr->ip_src = sr->nat->ext_iface->ip;
				icmphdr->icmp_id = tmp->aux_ext;
				
				icmphdr->icmp_sum = 0;
				icmphdr->icmp_sum = cksum(icmphdr, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
				
				free(tmp);
				break;
			case ip_protocol_tcp:
				/* TCP */
				packet_type = nat_mapping_tcp;
				
				sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
				tmp = sr_nat_lookup_internal(sr->nat,iphdr->ip_src,tcphdr->th_sport,packet_type);
				
				if (tmp == NULL){
					tmp = sr_nat_insert_mapping(sr->nat,iphdr->ip_src,tcphdr->th_sport,packet_type);
				}
				
				/* look up connection*/
				/* free con later */
				struct sr_nat_connection *con = sr_nat_lookup_connection(sr->nat, tmp, iphdr->ip_src, tcphdr->th_sport, iphdr->ip_dst, tcphdr->th_dport);
				
				if (con){
					/* check con state */
					if (con->established){
						/* forward */
						
					}else{
						/* check if is SYN ACK */
						if ((tcphdr->th_flags & TH_SYN == 1) && (tcphdr->th_flags & TH_ACK == 1)){
							if (con->isn_src + 1 == tcphdr->th_ack){
								sr_update_isn(sr->nat, tmp, con, con->isn_src, tcphdr->th_seq);
							}
						} else if ((tcphdr->th_flags & TH_SYN == 0) && (tcphdr->th_flags & TH_ACK == 1)){
							if(con->isn_dst + 1 == tcphdr->th_ack){
								/* change to establish state*/
								sr_nat_establish_connection(sr->nat, tmp, con);
							}
						}
						/* otherwies forward */
						
						
					}
				} else {
					/* check if SYN */
					if ((tcphdr->th_flags & TH_SYN == 1) && (tcphdr->th_flags & TH_ACK == 0)){
						sr_nat_add_connection(sr->nat, tmp, iphdr->ip_src, tcphdr->th_sport, iphdr->ip_dst, tcphdr->th_dport, tcphdr->th_seq);
					} else {
						/* DO STH */
					}
				}
				
				
				iphdr->ip_src = sr->nat->ext_iface->ip;
				tcphdr->th_sport = htons(tmp->aux_ext);
				
				tcphdr->th_sum = 0;
				tcphdr->th_sum = sr_get_tcp_cksum(packet, len);
	
				break;
		}
	}
	
	print_hdrs(packet,len);
	
	sr_handleIPforwarding(sr, packet, len, interface);
	
	return;
}

void
sr_receiveNATpacket(struct sr_instance* sr,
			   uint8_t * packet/* lent */,
			   unsigned int len,
			   char* interface/* lent */)
{
	/* NAT before forwarding */
	printf("******\n\nReceiving NAT packet\n\n******");
	print_hdrs(packet, len);
	sr_ip_hdr_t *iphdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
	
	if (sr->nat_enable &&  (strcmp(interface,"eth1") != 0)){
		/* from external interface */
		struct sr_nat_mapping *tmp;
		sr_nat_mapping_type packet_type;
		switch (iphdr->ip_p){
			case ip_protocol_icmp:
				/* ICMP */
				packet_type = nat_mapping_icmp;
				sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
				tmp = sr_nat_lookup_external(sr->nat,icmphdr->icmp_id,packet_type);
				if (tmp == NULL){
					/*TODO handle this case*/
				}
				iphdr->ip_src = sr->nat->int_iface->ip;
				iphdr->ip_dst = tmp->ip_int;
				
				icmphdr->icmp_id = tmp->aux_int;
				icmphdr->icmp_sum = 0;
				icmphdr->icmp_sum = cksum(icmphdr, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
				free(tmp);
				break;
			case ip_protocol_tcp:
				/* TCP */
				packet_type = nat_mapping_tcp;
				
				sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
				
				tmp = sr_nat_lookup_external(sr->nat,ntohs(tcphdr->th_dport),packet_type);
				
				if (tmp == NULL){
					/* TODO: ICMP */
					printf("\n###############################\n");
					return;
				}
				
				/* look up connection*/
				/* free con later */
				struct sr_nat_connection *con = sr_nat_lookup_connection(sr->nat, tmp, tmp->ip_int, tmp->aux_int, iphdr->ip_src, tcphdr->th_sport);
				
				if (con){
					/* check con state */
					if (con->established){
						/* forward */
						
					}else{
						/* check if is SYN ACK */
						if ((tcphdr->th_flags & TH_SYN == 1) && (tcphdr->th_flags & TH_ACK == 1)){
							if (con->isn_src + 1 == tcphdr->th_ack){
								sr_update_isn(sr->nat, tmp, con, con->isn_src, tcphdr->th_seq);
							}
						} else if ((tcphdr->th_flags & TH_SYN == 0) && (tcphdr->th_flags & TH_ACK == 1)){
							if(con->isn_dst + 1 == tcphdr->th_ack){
								/* change to establish state*/
								sr_nat_establish_connection(sr->nat, tmp, con);
							}
						}
						/* otherwies forward */
						
						
					}
				} else {
					/* check if SYN */
					if ((tcphdr->th_flags & TH_SYN == 1) && (tcphdr->th_flags & TH_ACK == 0)){
						sr_nat_add_connection(sr->nat, tmp, iphdr->ip_src, tcphdr->th_sport, iphdr->ip_dst, tcphdr->th_dport, tcphdr->th_seq);
					} else {
						/* DO STH */
					}
				}
				
				iphdr->ip_dst = tmp->ip_int;
				tcphdr->th_dport = tmp->aux_int;
				
				
				
				tcphdr->th_sum = 0;
				tcphdr->th_sum = sr_get_tcp_cksum(packet, len);
	
				break;
				
		}
	}
	print_hdrs(packet, len);
	sr_handleIPforwarding(sr, packet, len, interface);
	return;
}

uint16_t sr_get_tcp_cksum(uint8_t *packet, unsigned int len){
	sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	unsigned ip_plen = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
	
	
	uint8_t *new_hdr = malloc(sizeof(sr_tcp_pseudo_t) + ip_plen);
	sr_tcp_pseudo_t *p_tcphdr = (sr_tcp_pseudo_t *)(new_hdr);
	p_tcphdr->ip_src = iphdr->ip_src;
	p_tcphdr->ip_dst = iphdr->ip_dst;
	p_tcphdr->zeroes = 0;
	p_tcphdr->protocol = 6;
	p_tcphdr->len = htons(ip_plen);
	
	memcpy(new_hdr + sizeof(sr_tcp_pseudo_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), ip_plen);
	
	uint16_t res = cksum (new_hdr, sizeof(sr_tcp_pseudo_t) + ip_plen);
	
	
	free(new_hdr);
	return res;
}



