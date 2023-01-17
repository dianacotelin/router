#include "queue.h"
#include "skel.h"
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>

struct route_table_entry *rtable;
struct arp_entry *arp_table;

int rtable_len;
int arptable_len;


// Functie folosita pentru a raspunde la cererea arp request
void arp_reply(packet m, struct ether_header *eth_hdr, struct arp_header *arp_hdr, int interface) {
	
	struct arp_header arp_hdr0;
	// Antetul arp-ului
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


// Functia din laborator pentru best_route
struct route_table_entry *get_best_route2(__u32 dest_ip, struct route_table_entry *rtable) {
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

// Cautare binara iterativa
struct route_table_entry *get_best_route3(__u32 dest) {
	struct route_table_entry *best = NULL;
	int mid = 0;
	int l = 0;
	int r = rtable_len - 1;
	while (l <= r) {
        mid = (r+l) / 2;
 
        if ((rtable[mid].prefix) == (rtable[mid].mask & dest)){
            best = &rtable[mid];
			l = mid + 1;

		} else 
        	if (ntohl(rtable[mid].prefix) > ntohl(rtable[mid].mask & dest))
            	r = mid - 1;
        
        	else
				l = mid + 1;
            
    }
    return best;
}
// Cautare binara recursiva
int binarySearch(int l, int r, __u32 dest) {
    if (l <= r) {
		int mid = (r+l) / 2;
        if (rtable[mid].prefix == (rtable[mid].mask & dest))
            return mid;
        else if (ntohl(rtable[mid].prefix) < ntohl(rtable[mid].mask & dest))
            return binarySearch(l, mid - 1, dest);
        else
            return binarySearch(mid + 1, r, dest);
    } else
    	return -1;
}

struct route_table_entry *get_best_route(__u32 dest) {
    struct route_table_entry *best = NULL;
	
	int idx = binarySearch(0, rtable_len -1, dest);
	// Caut in contiunare pentru a gasi ruta cu prefixul cel mai mare si masca cea mai mare
	for (int i = idx; i < rtable_len; i++){
		int aux = dest & rtable[i].mask;
		if(aux == rtable[i].prefix){
			
			if(best == NULL || (ntohl(best->mask) < (ntohl(rtable[i].mask)))) {
				best = &rtable[i];
				
			}
		} 
	}
	
    return best;
}

void icmp_error (packet *m, uint8_t code, uint8_t type) {
	struct ether_header *eth_hdr = (struct ether_header *)m->payload;
	struct iphdr *ip_hdr = (struct iphdr *)(m->payload + sizeof(struct ether_header));

	packet new;
	new.len = sizeof(struct ether_header ) + sizeof(struct iphdr) + sizeof(struct icmp) + 64;
	memcpy(new.payload + new.len - 64, ip_hdr, 64);

	struct ether_header *eth_hdr0 = (struct ether_header *) new.payload;
	memcpy(eth_hdr0->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr0->ether_dhost, eth_hdr->ether_shost, 6);
	eth_hdr0->ether_type = htonl(ETHERTYPE_IP);

	struct iphdr *ip_hdr0 = (void*) eth_hdr0 + sizeof(struct ether_header);
	ip_hdr0->version = 4;
	ip_hdr0->ihl = 5;
	ip_hdr0->tos = 0;
	ip_hdr0->protocol = IPPROTO_ICMP;
	ip_hdr0->ttl = 64;
	ip_hdr0->tot_len = htons(84);
	ip_hdr0->daddr = ip_hdr->saddr;
	ip_hdr0->saddr = 0; //my ip
	ip_hdr0->daddr = ip_hdr->saddr;
	ip_hdr0->check = 0;
	ip_hdr0->check = ip_checksum((uint8_t*)ip_hdr, sizeof(struct iphdr));


	struct icmphdr *icmp_hdr = malloc(sizeof(struct icmphdr*));
	icmp_hdr->code = code;
	icmp_hdr->type = type;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = icmp_checksum((void *)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr));
	memcpy((void*)ip_hdr0 + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));
	
	send_packet(&new);
}


// Functie de comparare pentru qsort
int comp_func(const void *a, const void *b) {
 	uint32_t pref_a = ((struct route_table_entry *)a)->prefix;
 	uint32_t pref_b = ((struct route_table_entry *)b)->prefix;
	uint32_t mask_a = ((struct route_table_entry *)a)->mask;
	uint32_t mask_b = ((struct route_table_entry *)b)->mask;
	uint32_t aux = 0;
 	if(pref_a == pref_b) {
		aux = ntohl(mask_a) - ntohl(mask_b);
	} else {
 		aux = ntohl(pref_a) - ntohl(pref_b);
	}
	return (int)aux;
 }

// Caut arp_entry dupa ip
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
	
	packet m;
	int rc;
	// Do not modify this line
	init(argc - 2, argv + 2);
	
	queue q;
	q = queue_create();

	rtable = malloc(sizeof(struct route_table_entry) *70000);
	arp_table = malloc(sizeof(struct arp_entry ) * 70000);
	

	rtable_len = read_rtable(argv[1], rtable);
	//arptable_len = parse_arp_table("arp_table.txt", arp_table);
	
	// Sortez tabela pentru a face apoi cautarea binara
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), comp_func);
	
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct arp_header *arp_hdr = (struct arp_header*)(m.payload + sizeof(struct ether_header));
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
		
		struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

		// Daca pachetul este de tip IPv4
		if (eth_hdr->ether_type == htons(0x800)) {
			
			if (icmp_hdr != NULL) {
				if (icmp_hdr->type == ICMP_ECHO)  {
					
				}
			}

			// Daca checksum-ul nu este bun, nu pastrez pachetul
			if (ip_checksum( (void*)ip_hdr, sizeof(struct iphdr)) != 0)
				continue;

			// La fel si pentru ttl
			if (ip_hdr->ttl <= 0)
				continue;
		
			// Actualizez checksum si ttl
			(ip_hdr->ttl)--;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum((void*)ip_hdr, sizeof(struct iphdr));

			// Caut ruta pe care sa il trimit folosind cautarea binara
			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
			if (best_route == NULL) {
				icmp_error(&m, 0, ICMP_DEST_UNREACH);
				continue;
			}

			struct arp_entry *arp_ent = get_arp_entry(arp_table, arptable_len, best_route->next_hop);

			if (arp_ent != NULL) {
				memcpy(eth_hdr->ether_dhost, arp_ent->mac, 6);
				get_interface_mac(best_route->interface, eth_hdr->ether_shost);

				m.interface = best_route->interface;
				send_packet(&m);
				
			} else {
			// Daca nu il gasesc in tabela ARP trimit un arp request si salvez pachetul in coada

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
			// Am primit un pachet ARP
			if (ntohs(eth_hdr->ether_type) == 0x806) {

				// Arp Reply, il pun in tabela si apoi trimit toate pachetele care erau in coada
				if ((arp_hdr->op) == htons(ARPOP_REPLY)) {
					arp_table[arptable_len].ip = arp_hdr->spa;
					for (int i = 0; i < 6; i++) {
						arp_table[arptable_len].mac[i] = arp_hdr->sha[i];
					}
					arptable_len++;
					queue aux = queue_create();

				// Coada auxiliara in care pun pachetele care nu trebuiesc trimise acum
					while (!queue_empty(q)) {
						packet *last = queue_deq(q);
						struct ether_header *eth_hdr0 = (struct ether_header *)last->payload;
						struct iphdr *ip_hdr0 = (struct iphdr *)(last->payload + sizeof(struct ether_header));
						struct route_table_entry *best_r = get_best_route(ip_hdr0->daddr);
						struct arp_entry *arp_ent0 = get_arp_entry(arp_table, arptable_len, best_r->next_hop);

						// Acelasi proces ca mai sus cand trimiteam pachetul
						if (arp_ent0 != NULL) {
							memcpy(eth_hdr0->ether_dhost, eth_hdr0->ether_shost, 6);
							get_interface_mac(last->interface, eth_hdr0->ether_shost);
							send_packet(last);
							
						} else {

						queue_enq(aux, last);
						continue;
							
						}	
					}
					q = aux;
					
				}
				if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {
					// Am primit arp request, trimit reply

					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
					get_interface_mac(m.interface, eth_hdr->ether_shost);
					arp_reply(m, eth_hdr, arp_hdr, m.interface);
				}
			}
		}
		
	}
}
