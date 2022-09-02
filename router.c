#include "queue.h"
#include "skel.h"
#include "list.h"

#define TIME_EXCEEDED 11
#define DEST_UNREACH 3
#define ECHO_REPLY 0
#define MIN(a,b) { (a < b) ? a : b }

node* arp_cache;
node* packet_cache; 
struct route_table_entry *rtable;
int rtable_len;

typedef struct pkt_cache {
	packet pkt;
	uint32_t next_hop;
} pkt_cache;

typedef struct addr_map {
	uint8_t mac[ETH_ALEN];
	uint32_t ip;
} addr_map;

int compare_sort(const void *x, const void *y) {
	struct route_table_entry *a = (struct route_table_entry *) x;
	struct route_table_entry *b = (struct route_table_entry *) y;

	uint32_t min_mask = MIN(a->mask, b->mask);

	uint32_t fst_prefix = a->prefix & min_mask;
	uint32_t snd_prefix = b->prefix & min_mask;

	return (ntohl(fst_prefix) <= ntohl(snd_prefix)) &&
	 (fst_prefix != snd_prefix || ntohl(a->mask) >= ntohl(b->mask));
}

void arp_request(uint32_t ip_addr, int interface) {
	packet pkt;
	pkt.interface = interface;
	pkt.len = ETHER_HDR_LEN + 28;	// 28 bytes for arp

	struct ether_header *eth_h = (struct ether_header *) pkt.payload;
	struct arp_header *arp_h = (struct arp_header *) (pkt.payload + ETHER_HDR_LEN);
	
	// Completing the ether header
	eth_h->ether_type = htons(ETHERTYPE_ARP);
	get_interface_mac(interface, eth_h->ether_shost);
	for (int i = 0; i < ETH_ALEN; ++i) {
		eth_h->ether_dhost[i] = 0xff;	// Broadcast
	}
	
	// Completing the ARP header
	arp_h->htype = htons(1);
	arp_h->ptype = htons(0x0800);
	arp_h->hlen = 6;
	arp_h->plen = 4;
	arp_h->op = htons(1);
	get_interface_mac(interface, arp_h->sha);

	char *interface_ip = get_interface_ip(interface);
	struct in_addr addr;
	inet_aton(interface_ip, &addr);
	arp_h->spa = addr.s_addr;

	for (int i = 0; i < ETH_ALEN; ++i) {
		arp_h->tha[i] = 0x0;
	}
	arp_h->tpa = ip_addr;

	send_packet(&pkt);
}

void icmp_pack_router(packet pkt) {
	struct ether_header *eth_h = (struct ether_header *) pkt.payload;
	struct iphdr *ip_h = (struct iphdr *) (pkt.payload + ETHER_HDR_LEN);
	struct icmphdr *icmp_h = (struct icmphdr *) 
							(pkt.payload + ETHER_HDR_LEN + sizeof(struct iphdr));	

	// Ether header
	for (int i = 0; i < ETH_ALEN; ++i) {
		uint8_t aux = eth_h->ether_dhost[i];
		eth_h->ether_dhost[i] = eth_h->ether_shost[i];
		eth_h->ether_shost[i] = aux;
	}

	// IP header
	ip_h->daddr = ip_h->saddr;

	char *interface_ip = get_interface_ip(pkt.interface);

	struct in_addr addr;
	inet_aton(interface_ip, &addr);

	ip_h->saddr = addr.s_addr;
	
	ip_h->check = 0;
	ip_h->check = ip_checksum(ip_h, sizeof(struct iphdr));

	// ICMP header
	icmp_h->type = ECHO_REPLY;

	icmp_h->checksum  = 0;
	icmp_h->checksum = icmp_checksum(icmp_h, ntohs(ip_h->tot_len) - ip_h->ihl);

	send_packet(&pkt);
}

void icmp_pack(packet pkt, uint8_t msg_type) {
	pkt.len += 64 + 8;

	struct ether_header *eth_h = (struct ether_header *) pkt.payload;
	struct iphdr *ip_h = (struct iphdr *) (pkt.payload + ETHER_HDR_LEN);

	memmove(pkt.payload + ETHER_HDR_LEN + sizeof(struct iphdr) + 8, pkt.payload, 64);

	struct icmphdr *icmp_h = (struct icmphdr *) (pkt.payload + ETHER_HDR_LEN + sizeof(struct iphdr));	

	// Ether header
	eth_h->ether_type = htons(ETHERTYPE_IP);
	
	for (int i = 0; i < ETH_ALEN; ++i) {
		uint8_t aux = eth_h->ether_dhost[i];
		eth_h->ether_dhost[i] = eth_h->ether_shost[i];
		eth_h->ether_shost[i] = aux;
	}

	// IP header
	ip_h->ttl = 64;
	ip_h->protocol = 1;
	ip_h->daddr = ip_h->saddr;

	char *interface_ip = get_interface_ip(pkt.interface);

	struct in_addr addr;
	inet_aton(interface_ip, &addr);

	ip_h->saddr = addr.s_addr;
	ip_h->tot_len = htons(ntohs(ip_h->tot_len) + 64 + 8);

	ip_h->check = 0;
	ip_h->check = ip_checksum((uint8_t *)ip_h, sizeof(*ip_h));


	// ICMP header
	icmp_h->code = 0;
	icmp_h->type = msg_type;
	printf("%d\n", icmp_h->type);

	icmp_h->checksum  = 0;
	icmp_h->checksum = icmp_checksum(icmp_h, ntohs(ip_h->tot_len) - ip_h->ihl);

	send_packet(&pkt);
}

void ipv4(packet pkt, char *argv[]) {
	struct ether_header *eth_h = (struct ether_header *) pkt.payload;
	struct iphdr *ip_h = (struct iphdr *) (pkt.payload + ETHER_HDR_LEN);

	int i;
	for (i = 0; i < ROUTER_NUM_INTERFACES; ++i) {
		char *interface_ip = get_interface_ip(i);

		struct in_addr addr;
		inet_aton(interface_ip, &addr);

		if (addr.s_addr == ip_h->daddr) {
			// icmp
			struct icmphdr *icmp_h = (struct icmphdr *) 
									(pkt.payload + ETHER_HDR_LEN + sizeof(struct iphdr));

			if (icmp_h->type == 8 && icmp_h->code == 0) {
				icmp_pack_router(pkt);
			}
			return;
		}
	}

	uint16_t checksum = ip_h->check;
	ip_h->check = 0;

	if (checksum != ip_checksum(ip_h, sizeof(struct iphdr))) {
		return;
	}

	if (ip_h->ttl <= 1) {
		// icmp time exceeded
		icmp_pack(pkt, 11);
		return;
	}

	ip_h->ttl--;

	int idx = -1;
	for (int i = 0; i < rtable_len; ++i) {
		if ((ip_h->daddr & rtable[i].mask) == rtable[i].prefix) {
			if (idx == -1) {
				idx = i;
			} else if (rtable[i].mask > rtable[idx].mask) {
				idx = i;
			}
		}
	}

	// int left = 0, right = rtable_len - 1, mid;

	// while (left <= right) {
	// 	mid = (left + right) / 2;

	// 	if ((ip_h->daddr & rtable[mid].mask) == rtable[mid].prefix) {
	// 		if (idx == -1) {
	// 			idx = i;
	// 		} else if (rtable[mid].mask > rtable[idx].mask) {
	// 			idx = i;
	// 		}
	// 		right = mid;
	// 	} else if (ntohs(ip_h->daddr & rtable[mid].mask) < ntohs(rtable[mid].prefix)) {
	// 		right = mid;
	// 	} else {
	// 		left = mid;
	// 	}
	// }

	if (idx == -1) {
		// icmp destination unreachable
		icmp_pack(pkt, 3);
		return;	
	}

	ip_h->check = 0;
	ip_h->check = ip_checksum(ip_h, sizeof(struct iphdr));

	pkt.interface = rtable[idx].interface;

	get_interface_mac(rtable[idx].interface, eth_h->ether_shost);

	// verific daca gasesc pachetul in arp_cache
	// daca nu, trimit un arp_request si il adaug in packet_cache
	node *curr = arp_cache;
	while (curr) {
		addr_map *elem_map = (addr_map *) curr->element;
		if (elem_map->ip == rtable[idx].next_hop) {
			for (int i = 0; i < ETH_ALEN; ++i) {
				eth_h->ether_dhost[i] = elem_map->mac[i];
			}
			send_packet(&pkt);
			return;
		}
		curr = curr->next;
	}

	pkt_cache *new_entry = malloc(1 * sizeof(pkt_cache));
	new_entry->pkt = pkt;
	new_entry->next_hop = rtable[idx].next_hop;
	packet_cache = cons(new_entry, packet_cache);

	arp_request(rtable[idx].next_hop, rtable[idx].interface);
}

void arp_reply(packet pkt) {
	struct ether_header *eth_h = (struct ether_header *) pkt.payload;
	struct arp_header *arp_h = (struct arp_header *) (pkt.payload + ETHER_HDR_LEN);
	
	for (int i = 0; i < ROUTER_NUM_INTERFACES; ++i) {
		char *interface_ip = get_interface_ip(i);

		struct in_addr addr;
		inet_aton(interface_ip, &addr);

		if (addr.s_addr == arp_h->tpa) {

			uint32_t aux32 = arp_h->tpa;
			arp_h->tpa = arp_h->spa;
			arp_h->spa = aux32;

			uint8_t* mac = malloc(ETH_ALEN * sizeof(uint8_t));
			get_interface_mac(i, mac);

			for (int j = 0; j < ETH_ALEN; ++j) {
				arp_h->tha[j] = arp_h->sha[j];
				arp_h->sha[j] = mac[j];

				eth_h->ether_dhost[j] = arp_h->tha[j];
				eth_h->ether_shost[j] = arp_h->sha[j];
			}

			arp_h->op = htons(ARPOP_REPLY);
			pkt.len = ETHER_HDR_LEN + 28;

			send_packet(&pkt);
			free(mac);
			return;
		}
	}
}

void arp(packet pkt) {
	struct arp_header *arp_h = (struct arp_header *) (pkt.payload + ETHER_HDR_LEN);

	if (ntohs(arp_h->op) == ARPOP_REQUEST) {
		arp_reply(pkt);
	} else if (ntohs(arp_h->op) == ARPOP_REPLY) {	
		addr_map *elem = malloc(1 * sizeof(addr_map));
		elem->ip = arp_h->spa;
		for (int i = 0 ; i < ETH_ALEN; ++i) {
			elem->mac[i] = arp_h->sha[i];
		}

		arp_cache = cons(elem, arp_cache);

		node* curr = packet_cache, *prev = NULL;

		while (curr) {
			pkt_cache *p_pack = (pkt_cache *) curr->element;
			struct iphdr *ip_h = (struct iphdr *) (p_pack->pkt.payload + ETHER_HDR_LEN);

			if (elem->ip == p_pack->next_hop) {
				struct ether_header *eth_h = (struct ether_header *) p_pack->pkt.payload;
				for (int i = 0 ; i < ETH_ALEN; ++i) {
					eth_h->ether_dhost[i] = elem->mac[i];
				}
				send_packet(&p_pack->pkt);

				if (!prev) {
					packet_cache = packet_cache->next;
					node* temp = curr;
					curr = curr->next;
					free(temp);	
				} else {
					prev->next = curr->next;

					node* temp = curr;
					curr = curr->next;
					free(temp);					
				}
			} else {
				prev = curr;
				curr = curr->next;
			}
		}
	}
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(100000 * sizeof(struct route_table_entry));
	rtable_len = read_rtable(argv[1], rtable);
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_sort);
	
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		
		struct ether_header *eth_h = (struct ether_header *) m.payload;

		if (ntohs(eth_h->ether_type) == ETHERTYPE_IP) {
			ipv4(m, argv);
		} else if (ntohs(eth_h->ether_type) == ETHERTYPE_ARP){
			arp(m);
		}
	}
}
