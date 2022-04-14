Repository for the first homework of the Communication Networks class. In this homework the students will implement the dataplane of a router.

#include "skel.h"

/* Array of router interfaces (e.g. 0,1,2,3) */
int interfaces[ROUTER_NUM_INTERFACES];

/* Routing table */
struct rtable_entry *rtable;
int rtable_len;

/* Mac table */
struct nei_entry *nei_table;
int nei_table_len;

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route
 for the given protocol and destination address. Or NULL if there is no matching route.
*/
struct rtable_entry *get_best_route(uint16_t proto, struct in_addr dest_ip, struct in6_addr dest_ip6) {
	/* TODO 1: Implement the function. We don't use dest_ip6 at this exercise */
	size_t index = -1;
	for (size_t i = 0 ; i < rtable_len; i++) {
		if (proto == 4) {
			if (rtable[i].proto == 4) {
				if ((dest_ip.s_addr & rtable[i].netmask.s_addr) == rtable[i].network.s_addr) {
					if (index == -1) {
						index = i;
					} else {
						if (ntohl(rtable[index].netmask.s_addr) < ntohl(rtable[i].netmask.s_addr)) {
							index = i; 
						} else
						{
							if (rtable[index].netmask.s_addr == rtable[i].netmask.s_addr) {
								if (rtable[index].metric > rtable[i].metric) {
									index = i;
								}
							}
						}
						
					}
				}
			}
		}
	}

	if (index == -1)
		return NULL;
	else
		return &rtable[index];
}

/*
 Returns a pointer (eg. &nei_table[i]) to the best matching neighbor table entry.
 for the given protocol and destination address. Or NULL if there is no matching route.
*/
struct nei_entry *get_nei_entry(uint16_t proto, struct in_addr dest_ip, struct in6_addr dest_ip6) {
    /* TODO 2: Implement the function. We don't use dest_ip6 at this exercise. */
	for (int i = 0; i < nei_table_len; i++)
		if ((nei_table->proto == 4) && (proto == 4))
			if (memcmp(&dest_ip, &nei_table[i].ip, sizeof(struct in_addr)) == 0)
			return &nei_table[i];
    return NULL;
}

int main(int argc, char *argv[])
{
	msg m;
	int rc;

	init();

	rtable = malloc(sizeof(struct rtable_entry) * 100);
	DIE(rtable == NULL, "memory");

	nei_table = malloc(sizeof(struct  nei_entry) * 100);
	DIE(nei_table == NULL, "memory");
	
	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(rtable);
	nei_table_len = read_nei_table(nei_table);

	while (1) {
		/* Receives a packet from an interface */
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		
		/* Extract the Ethernet header from the packet. Since protocols are stacked, the first header is the ethernet header,
		 * the next header is at m.payload + sizeof(struct ether_header) */
		struct ether_header *eth_hdr = (struct ether_header *) m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
		
		struct iphdr *iph;
		struct in_addr dest_ip;
		struct in6_addr dest_ip6;
		uint16_t proto;

		/* TODO 3: DONE: Check if this is an IPv4 or IPv6 packet and route accordingly. For now we will drop IPv6 packets and forward only IPv4.*/
		/* We check if the packet is IPV4. Watch out for the usage of ntohs, why do we need it? Hint: Network Order */
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			iph = ((void*) eth_hdr) + sizeof (struct ether_header);

		/* TODO 4: Check the checksum as required by IPv4  */
			if (ip_checksum ((void *) iph, sizeof (struct iphdr)) != 0 )
				continue;

		/* TODO 5: Check TTL >= 1 */
			if (iph->ttl == 0)
				continue;
			
			dest_ip.s_addr = iph->daddr;
			proto = 4;

		/* TODO 6: Find best matching route (using the function you wrote at TODO 1) */
			struct rtable_entry *route = get_best_route(proto, dest_ip, dest_ip6);
			if (route == NULL) {
				continue;
			}

		/* TODO 7: Find matching neighbour table entry (using the function you wrote at TODO 2)*/
			struct nei_entry *nei = get_nei_entry(proto, route->nexthop, route->nexthop6);
			if (nei == NULL)
				continue;

		/* TODO 8: Update TTL and recalculate the checksum */
			if (proto == 4) {
				iph->ttl--;
				iph->check = 0;
				iph->check = ip_checksum((void *) iph, sizeof(struct iphdr));
			}

		/* TODO 9: Update the Ethernet addresses */
			memcpy(eth_hdr->ether_dhost, nei->mac, 6);
			get_interface_mac(route->interface, eth_hdr->ether_shost);

		/* TODO 10: Forward the pachet to best_route->interface */
			send_packet(route->interface, &m);
		}

	}
}
