
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "sr_if.h"
#include "sr_router.h"

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

struct sr_nat_connection {
  /* add TCP connection state data members here */
	uint32_t ip_dst;
	uint16_t port_dst;
	
	uint32_t ip_src;
	uint16_t port_src;
	
	/* isn from dst */
	uint16_t isn_dst;
	/* isn from src */
	uint16_t isn_src;
	/* 0: new connection to be established; 1: connection established 
	 * -1: connection pending */
	int established;
	
	/* The unsocilidated packet and its length*/
	uint8_t *pending_packet;
	unsigned int len;
	
	time_t last_updated;
	
  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  uint16_t global_auxext;
  
  uint16_t icmp_timeout;
  uint16_t tcp_establish_timeout;
  uint16_t tcp_transitory_timeout;
  uint16_t tcp_unsolicited_syn_timeout;
  
  struct sr_if *int_iface;
  struct sr_if *ext_iface;
  
  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_instance *sr);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

struct sr_nat_connection *sr_nat_lookup_connection(struct sr_nat *nat, struct sr_nat_mapping *copy, uint32_t ip_src, uint16_t port_src, uint32_t ip_dst, uint16_t port_dst);
  
void sr_nat_add_connection(struct sr_nat *nat, struct sr_nat_mapping *copy, uint32_t ip_src, uint16_t port_src, uint32_t ip_dst, uint16_t port_dst, uint16_t isn_src, int established, 
uint8_t *pending_packet, unsigned int len);
  
int sr_nat_establish_connection(struct sr_nat *nat,
  struct sr_nat_mapping *copy, struct sr_nat_connection *con_copy);

int sr_update_isn(struct sr_nat *nat, struct sr_nat_mapping *copy, struct sr_nat_connection *con_copy, uint16_t isn_src, uint16_t isn_dst);
#endif