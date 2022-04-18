#include "queue.h"
#include "skel.h"
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>

struct route_table_entry *rtable;
struct arp_entry *arp_table;

int rtable_len;
int arptable_len;



void arp_reply(packet m, struct ether_header *eth_hdr, struct arp_header *arp_hdr, int interface) {
	
	struct arp_header arp_hdr0;

	arp_hdr0.htype = htons(ARPHRD_ETHER);
	arp_hdr0.ptype = htons(2048);
	arp_hdr0.hlen = 6;
	arp_hdr0.plen = 4;
	arp_hdr0.op = htons(ARPOP_REPLY);
	memcpy(arp_hdr0.sha, eth_hdr->ether_shost, 6);
	memcpy(arp_hdr0.tha, eth_hdr->ether_dhost, 6);
	arp_hdr0.spa = arp_hdr->tpa;
	arp_hdr0.tpa = arp_hdr->spa;

	packet pack;
	pack.len = sizeof(struct arp_header) + sizeof(struct arp_header);
	pack.interface = interface;

	memcpy(pack.payload, eth_hdr, sizeof(struct ether_header));
	memcpy(pack.payload + sizeof(struct ether_header), &arp_hdr0, sizeof(struct arp_header));
	send_packet(&pack);

}

void arp_reply2(packet m, struct ether_header *eth_hdr, uint32_t s_addr, uint32_t d_addr, int interface) {
	
	struct arp_header arp_hdr0;

	arp_hdr0.htype = htons(ARPHRD_ETHER);
	arp_hdr0.ptype = htons(2048);
	arp_hdr0.hlen = 6;
	arp_hdr0.plen = 4;
	arp_hdr0.op = htons(ARPOP_REQUEST);
	memcpy(arp_hdr0.sha, eth_hdr->ether_shost, 6);
	memcpy(arp_hdr0.tha, eth_hdr->ether_dhost, 6);
	arp_hdr0.spa = s_addr;
	arp_hdr0.tpa = d_addr;

	packet pack;
	pack.len = sizeof(struct arp_header) + sizeof(struct ether_arp);
	pack.interface = interface;

	memcpy(pack.payload, eth_hdr, sizeof(struct ether_header));
	memcpy(pack.payload + sizeof(struct ether_header), &arp_hdr0, sizeof(struct arp_header));
	send_packet(&pack);

}

struct rtable_entry *get_best_route2(__u32 dest_ip, struct route_table_entry *rtable) {
    size_t idx = -1;	

    for (size_t i = 0; i < rtable_len; i++) {
        if ((dest_ip & rtable[i].mask) == rtable[i].prefix) {
	    if (idx == -1) idx = i;
	    else if (ntohl(rtable[idx].mask) < ntohl(rtable[i].mask)) idx = i;
	    else if (rtable[idx].mask == rtable[i].mask) idx = i;
	
    }
	}
    
    if (idx == -1)
        return NULL;

    else
        return &rtable[idx];
}


int binarySearch(int l, int r, __u32 dest) {
    if (l <= r) {
		int mid = (r+l) / 2;
        if (rtable[mid].prefix == (rtable[mid].mask & dest))
            return mid;
        else if (rtable[mid].prefix >(rtable[mid].mask & dest))
            binarySearch(l, mid - 1, dest);
        else
            binarySearch(mid + 1, r, dest);
    }
    return -1;
}

struct route_table_entry *get_best_route(__u32 dest) {
    struct route_table_entry *best = NULL;
	
	int idx = binarySearch(0, rtable_len, dest);
	
	
	

	for (int i = idx; i < rtable_len; i++){
		int aux = dest & rtable[i].mask;
		if(aux == rtable[i].prefix){
			if(best == NULL || (best->mask < rtable[i].mask)){
				best = &rtable[i];
				
			}
		} 
	}
	
    return best;
}


int comp_func(const void *a, const void *b) {
 	uint32_t pref_a = ((struct route_table_entry *)a)->prefix;
 	uint32_t pref_b = ((struct route_table_entry *)b)->prefix;
	uint32_t mask_a = ((struct route_table_entry *)a)->mask;
	uint32_t mask_b = ((struct route_table_entry *)b)->mask;
	int aux = 0;
 	if(pref_a != pref_b) {
		aux = mask_a - mask_b;
	} else {
 		aux = pref_a - pref_b;
	}
	return aux;
 }
// int comp_func(const void *a, const void *b) {
// 	struct route_table_entry *r1 = (struct route_table_entry *)a;
// 	struct route_table_entry *r2 = (struct route_table_entry *)b;
// 	if (r1->prefix == r2->prefix) {
// 		return (int)r2->mask - r1->mask;
// 	} else {
// 		return (int)r1->prefix - r2->prefix;
// 	}
// }
struct arp_entry *get_arp_entry(struct arp_entry *arp_tab, int arptable_size, uint32_t ip) {

	for (int i = 0; i < arptable_size; i++) {
		if (ip == arp_tab[i].ip) {
			return &arp_tab[i];
		}
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	//printf("Asa sunt zilele mele\n");
	packet m;
	int rc;
	// Do not modify this line
	init(argc - 2, argv + 2);
	//printf("Una buna 10 rele\n");
	queue q;
	q = queue_create();
	rtable = malloc(sizeof(struct route_table_entry) * 1000000);
	arp_table = malloc(sizeof(struct arp_entry ) * 10000000);
	//printf("Nu da doamne cineva\n");

	rtable_len = read_rtable(argv[1], rtable);
	//arptable_len = parse_arp_table("arp_table.txt", arp_table);
	//printf("Sa ma scape de lumea rea\n");
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), comp_func);
	//printf("Of lume rea blestemata esti\n");
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct arp_header *arp_hdr = (struct ether_arp*)(m.payload + sizeof(struct ether_header));
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
		//printf("Am intrat aici4\n");
		struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

		if (eth_hdr->ether_type == htons(0x800)) {
			//printf("Am intrat aici2\n");
			if (icmp_hdr != NULL) {
				if ((icmp_hdr->type == ICMP_ECHO) && (ip_hdr->daddr == inet_addr)) {
					
				}
			}

			if (ip_checksum( (void*)ip_hdr, sizeof(struct iphdr)) != 0)
				continue;

			if (ip_hdr->ttl <= 0)
				continue;
		
		
			(ip_hdr->ttl)--;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum((void*)ip_hdr, sizeof(struct iphdr));

			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
			if (best_route == NULL) {
				
				continue;
			}
			struct arp_entry *arp_ent = get_arp_entry(arp_table, arptable_len, best_route->next_hop);

			if (arp_ent != NULL) {
				memcpy(eth_hdr->ether_dhost, arp_ent->mac, 6);
				get_interface_mac(best_route->interface, eth_hdr->ether_shost);

				m.interface = best_route->interface;
				send_packet(&m);
				
			} else {
				//printf("am ajuns si aici\n");
				struct arp_header arp_hdr0;
				arp_hdr0.htype = htons(ARPHRD_ETHER);
				arp_hdr0.ptype = htons(2048);

				arp_hdr0.hlen = 6;
				arp_hdr0.plen = 4;
				arp_hdr0.op = htons(ARPOP_REQUEST);
				memcpy(arp_hdr0.sha, eth_hdr->ether_shost, 6);
				memcpy(arp_hdr0.tha, eth_hdr->ether_dhost, 6);
				arp_hdr0.spa = inet_addr(get_interface_ip(best_route->interface));
				arp_hdr0.tpa = best_route->next_hop;

				packet *pack = malloc(sizeof(packet));
				pack->len = m.len;
				pack->interface = best_route->interface;
				memcpy(pack->payload, m.payload, sizeof(m.payload));
				eth_hdr->ether_type = htons(ETHERTYPE_ARP);
				memset(eth_hdr->ether_dhost, 255, 6);
				queue_enq(q, pack);

				packet pack2;
				pack2.len = sizeof(struct arp_header) + sizeof(struct ether_arp);
				pack2.interface = best_route->interface;

				memcpy(pack2.payload, eth_hdr, sizeof(struct ether_header));
				memcpy(pack2.payload + sizeof(struct ether_header), &arp_hdr0, sizeof(struct arp_header));
				send_packet(&pack2);
				continue;
			} 
			
		} else {
			if (ntohs(eth_hdr->ether_type) == 0x806) {
				if ((arp_hdr->op) == htons(ARPOP_REPLY)) {
					arp_table[arptable_len].ip = arp_hdr->spa;
					for (int i = 0; i < 6; i++) {
						arp_table[arptable_len].mac[i] = arp_hdr->sha[i];
					}
						//memcpy(arp_table[arptable_len].mac, eth_hdr->ether_shost, ETH_ALEN);
					arptable_len++;
					queue aux = queue_create();

					while (!queue_empty(q)) {
						packet *last = queue_deq(q);
						struct ether_header *eth_hdr0 = (struct ether_header *)last->payload;
							//struct ether_arp *arp_hdr0 = (struct ether_arp*)(last->payload + sizeof(struct ether_header));
						struct iphdr *ip_hdr0 = (struct iphdr *)(last->payload + sizeof(struct ether_header));
						struct route_table_entry *best_r = get_best_route(ip_hdr0->daddr);
						struct arp_entry *arp_ent0 = get_arp_entry(arp_table, arptable_len, best_r->next_hop);
						if (arp_ent0 == NULL) {
							queue_enq(aux, last);
							continue;
						}
						memcpy(eth_hdr0->ether_dhost, eth_hdr0->ether_shost, 6);
							get_interface_mac(last->interface, eth_hdr0->ether_shost);
							//last->interface = best_r->interface;
						send_packet(last);
							//free(last);
							// if ((ip_hdr0 != NULL) && (ip_hdr0->daddr == arp_hdr->arp_spa)) {
							// 	get_interface_mac(last->interface, eth_hdr->ether_shost);
							// 	//memcpy(eth_hdr0->ether_dhost, eth_hdr0->ether_shost, 6);
							// 	send_packet(last);
							// 	queue_deq(aux);
							// 	free(last);
							// }
							
					}
					q = aux;
					
				}
				if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {
					printf("REQUEST\n");
					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
					get_interface_mac(m.interface, eth_hdr->ether_shost);
					arp_reply(m, eth_hdr, arp_hdr, m.interface);
					//continue;
				}
			}
		}
		
	}
}
