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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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
	/* TODO: load static routing table??? */
	int result = sr_load_rt(sr, "rtable");
	if (result) {
		fprintf(stderr, "Failed loading routing table..");
		return;
	}

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
	/* fill in code here */

	int result;

	print_hdrs(packet, len);
	
	if (len > 1514){
		fprintf(stderr, "Failed to handle ETHERNET packet, max MTU exceeded\n");
		return;
	}

	/* Ethernet length checking */
	int minlength = sizeof(sr_ethernet_hdr_t);
	if (len < minlength) {
		fprintf(stderr, "Failed to handle ETHERNET packet, insufficient length\n");
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
			fprintf(stderr, "Failed to print IP header, insufficient length\n");
			/* TODO error handling*/
			return;
		}

		sr_ip_hdr_t *iphdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
		
		if (iphdr->ip_v != 4) {
			fprintf(stderr, "Failed to print IP header, version is not 4\n");
			/* TODO error handling*/
			return;
		}

		/* Checking checksum for IP */
		result = sr_checkIPchecksum(iphdr);
		if (result) {
			/* Incorrect checksum: TODO */
			printf("incorrent checksum\n");
			return;
		}

		/* TODO probably nothing else to do done here, but check */

		struct sr_if* cur_interface =  sr_get_interface(sr,interface);
		if (cur_interface == 0){
			/* can't get current interface from the list in the router */
			printf("[DEBUG] cur_interface is 0\n");
		}

		printf("***Check if the packet is for the router\n");
		if (sr_checkInterface(sr, iphdr->ip_dst)){
			printf("[DEBUG] The packet is for the router\n");

			/* If it's an ICMP protocol */
			if (ip_protocol((uint8_t *) iphdr) == ip_protocol_icmp) {
				printf("[DEBUG] ICMP\n");
				if (len < minlength) {
					fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
					/*TODO error handling */
					return;
				}
				printf("[DEBUG] printing incoming PING..\n");
				print_hdr_icmp((uint8_t *) iphdr + sizeof(sr_ip_hdr_t));
				sr_sendICMPPingRep(sr, packet, len, interface);
				return;
			}else{
				printf("***Reply port unreachable\n");
				/* TODO doesn't seem to be right here?
				 */
				sr_sendICMPMsg(sr,3,3,interface,packet,len);
				return;
			}
		}else{
			
			/* Checking TTL*/
			if (iphdr->ip_ttl == 1) {
				printf("[DEBUG] TTL reaches 0, discard packet\n");
				sr_sendICMPMsg(sr,11,0,interface,packet,len);
				return;
			}
			printf("The packet is NOT for the router\n");
			sr_handleIPforwarding(sr, packet, len, interface);
		}
		break;
		/* I'm an ARP packet */
	case ethertype_arp:
		minlength += sizeof(sr_arp_hdr_t);
		if (len < minlength) {
			fprintf(stderr, "Failed to print ARP header, insufficient length\n");
			/* TODO error handling */
			return;
		}
		sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

		/* TODO: ARP handling */
		switch (ntohs(arp_hdr->ar_op)) {
			case (arp_op_request):
				/* TODO: ARP request handling*/
				sr_sendARPreply(sr, ehdr, arp_hdr,interface);
				return;
			case (arp_op_reply):
				/* TODO: ARP reply handling */
				sr_handleARPReply(sr, ehdr, arp_hdr, interface);
				return;
			default:
				fprintf(stderr, "Unknown ARP op type");
				/* TODO: err handling */
				return;
		}

		default:
			fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
			/* TODO error handling, possibly an ICMP packet sending */
			return;
	}

}/* end sr_ForwardPacket */

/**
 * Send out ARP reply with the arp header and interface.
 */
void sr_sendARPreply(struct sr_instance* sr,
		sr_ethernet_hdr_t *ethhdr/* lent */,
		sr_arp_hdr_t *arphdr,
		char* interface)
{
	printf("*** Send arp reply \n");

	uint8_t *new_packet = (uint8_t *)malloc(sizeof (sr_ethernet_hdr_t) +
			sizeof (sr_arp_hdr_t));

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

	//print_hdrs(new_packet, sizeof (sr_ethernet_hdr_t) + sizeof (sr_arp_hdr_t));

	sr_send_packet(sr, new_packet, sizeof (sr_ethernet_hdr_t) +
			sizeof (sr_arp_hdr_t),interface);
}

/**
 * Send out ARP Request for the arp request
 */
void sr_sendARPRequst(struct sr_instance* sr, struct sr_arpreq *req,
		char* interface)
{
	printf("*** send arp request \n");

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

	//print_hdrs(new_packet, sizeof (sr_ethernet_hdr_t) + sizeof (sr_arp_hdr_t));

	sr_send_packet(sr, new_packet, sizeof (sr_ethernet_hdr_t) +
			sizeof (sr_arp_hdr_t), interface);
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

    printf("[DEBUG] Printing out Next-hop routing table entry\n");
    print_addr_ip(match_rt_entry->gw);
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
		int result = sr_send_packet(sr, packet, len, match_rt_entry->interface);
		/* TODO: what if send packet fails */
		free((void *) next_arp_entry);
		return;
	}else{
		/* Otherwise, send an ARP request for the next-hop IP (if one
		 * hasn't been sent within the last second), */
		/* Send ARP Request for destinating ip */
		struct sr_arpreq *req;

		req = sr_arpcache_queuereq(&sr->cache, iphdr->ip_dst, packet, len,
				next_interface->name);
		
		//printf("\nlen is %d\n",len);
		sr_handle_arpreq(sr, req);
	}
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
		fprintf(stderr, "Incorrect checksum %d\n", cksum(buff,  sizeof(sr_ip_hdr_t)));

		free(buff);
		return 1;
	}
	//printf("Correct checksum\n");
	free(buff);
	return 0;
}

/**
 * Handle ARP Request: send ARP
 */
void sr_handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req) {
	
	if (req->sent == NULL){req->sent = 0;}

	time_t *now_time = malloc(sizeof(time_t));
	time(now_time);

	/* Request sent time is greater than 1.0 second before */
	if (difftime(*now_time, req->sent) > 1.0){
		/* Greater than 5 times sent, send an ICMP host unreachable error */
		if (req->times_sent >= 5){
			struct sr_packet *pkt = req->packets;

			while (pkt != NULL){
				
				printf("[DEBUG] Send ICMP to all waiting packet1\n");
				
				// Host unreachable:
				// Do not send ICMP message for ICMP Error Message
				sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) pkt->buf;
				sr_ip_hdr_t *iphdr = (sr_ip_hdr_t*) (pkt->buf + sizeof(sr_ethernet_hdr_t));
				
				if (iphdr->ip_p == ip_protocol_icmp) {
					sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *) (iphdr + sizeof(sr_icmp_hdr_t));
					/* Do not generate ICMP error messages for ICMP error Messages */
					uint8_t type,code;
					type = icmphdr->icmp_type;
					
					
					if (type == 3 ||type == 4 ||type == 5 ||type == 11 || type == 12){
						pkt = pkt->next;
						continue;
					}
				}
				
				// Make a new ethernet packet with ICMP for IP forwarding
				
				struct sr_rt *entry = sr_findMatchInRoutingTable(sr->routing_table, iphdr->ip_src);
				
				uint8_t *new_packet = (uint8_t *) malloc(sizeof (sr_ethernet_hdr_t) +
						sizeof (sr_ip_hdr_t) +
						sizeof(sr_icmp_t3_hdr_t));
				
				sr_ip_hdr_t *new_ethdr = (sr_ethernet_hdr_t*) (new_packet);
				setEthernetHeader(new_ethdr, ehdr->ether_shost,sr_get_interface(sr, entry->interface),ethertype_ip);
				
				sr_ip_hdr_t *new_iphdr = (sr_ip_hdr_t*) (new_packet + sizeof(sr_ethernet_hdr_t));

				// Change the destination of the IP packet to be the old source
				// Change the source to be the interface's ip
				
				setIPHeaderAsReply(new_iphdr, iphdr,sizeof (sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t),
						ip_protocol_icmp, sr_get_interface(sr, entry->interface));
				// Now make the body to be an ICMP message
				sr_icmp_t3_hdr_t * new_icmp = (sr_icmp_t3_hdr_t*) (new_packet + sizeof (sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));

				/* Copy the old ip header */
				memcpy(new_icmp->data, iphdr, ICMP_DATA_SIZE);
				setICMPHeader(new_icmp, 3, 1);

				printf("[DEBUG] Printing host unreachable ICMP Message out..\n");
				print_hdrs(new_packet, sizeof (sr_ethernet_hdr_t) +
						sizeof (sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

				// And then use IP forwarding to send out packet
				sr_handleIPforwarding(sr, new_packet/* lent */,	sizeof (sr_ethernet_hdr_t) +
						sizeof (sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), entry->interface);

				// Now drop pkt in the queue TODO
				pkt = pkt->next;
				
				//free(pkt);
				// Do we need to free memeory? for the new_packet?
			}
			
			sr_arpreq_destroy(&sr->cache, req);
		} else {
			// Broadcast ARP request
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
	printf("*** Get ARP reply \n");

	struct sr_arpreq *req = NULL;
	
	req = sr_arpcache_insert(&sr->cache, arphdr->ar_sha, arphdr->ar_sip);

	if (req != NULL) {
		struct sr_packet *pkts = req->packets;
		int i;
		while (pkts != NULL) {
			//printf("pkts has length %d\n",pkts->len);
			sr_ethernet_hdr_t *ehdr = pkts->buf;
			
			struct sr_if* pkt_interface =  sr_get_interface(sr,pkts->iface);
			
			/* Put in the mac address */
			for (i = 0; i < ETHER_ADDR_LEN; i++) {
				ehdr->ether_dhost[i] = (uint8_t) arphdr->ar_sha[i];
				ehdr->ether_shost[i] = (uint8_t) pkt_interface->addr[i];
			}
			
			
			print_hdrs(pkts->buf,  pkts->len);
			
			int result = sr_checkIPchecksum((sr_ip_hdr_t*) (pkts->buf + sizeof(sr_ethernet_hdr_t)));
			if (result) {
				/* Incorrect checksum: TODO */
				printf("incorrent checksum pkts\n");
				return;
			}
			
			sr_send_packet(sr, pkts->buf, pkts->len, pkts->iface);
			pkts = pkts->next;
		}
		sr_arpreq_destroy(&sr->cache, req);
	}else{
	}
}

/* 
 * Send ICMP ping reply, which is type 0
 */
void sr_sendICMPPingRep(struct sr_instance *sr, 
			uint8_t *packet,
			unsigned int len,
			char * interface)
{
        printf("*** send ICMP ping reply message \n");
	
	sr_ethernet_hdr_t *new_ethhdr = (sr_ethernet_hdr_t *) packet;
	sr_ip_hdr_t *new_iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	sr_icmp_hdr_t *new_icmphdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	
	struct sr_if* cur_interface =  sr_get_interface(sr, interface);
	/* TODO Need to check */
	
	setEthernetHeader(new_ethhdr, new_ethhdr->ether_shost, cur_interface, ethertype_ip);
	
	printf("*** len is %d \n", len);
	
	setIPHeaderAsReply(new_iphdr, new_iphdr, len - sizeof(sr_ethernet_hdr_t), ip_protocol_icmp, cur_interface);
	
	/* TODO: pretty dangerous: assuming the only ICMP receving is an ICMP Ping,
	 * and assuming the rest of the coming ICMP message is all zeros (thus the
	 * checksum will not change), probably need to at least set the rest of
	 * all to be 0's? or just use the type3 structure.
	 */
	setICMPNormal(new_icmphdr, 0, 0);
	
	printf("Ip header size is %d\n",sizeof (sr_ip_hdr_t));
	printf("Icmp header size is %d\n",sizeof (sr_icmp_hdr_t));
	print_hdrs(packet, len);
	
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

	printf("*** send ICMP error message \n");
	// The ICMP error msg has the following structure:
	// |eth header| ip header | icmp header | old ip header | first 8 bytes of payload |

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

	printf("[DEBUG] Printing new ICMP Message out..\n");
	print_hdrs(new_packet, sizeof (sr_ethernet_hdr_t) +
			sizeof (sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

	sr_send_packet(sr, new_packet, sizeof (sr_ethernet_hdr_t) +
			sizeof (sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
	
	
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
 * Set up a normal ICMP, autocalculate checksum
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
}

/*
 * Set up a type 3 ICMP, autocalculate checksum
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
}


