#include "skel.h"

int interfaces[ROUTER_NUM_INTERFACES];

struct rtable_entry *rtable;
int rtable_len;

struct nei_entry *nei_table;
int nei_table_len;

int in6_cmp(struct in6_addr a, struct in6_addr b) {
    for (int i = 0; i < 16; i++) {
        if (a.s6_addr[i] < b.s6_addr[i])
		return -1;

        if (a.s6_addr[i] > b.s6_addr[i])
		return 1;
    }

    return 0;
}

struct in6_addr in6_mask(struct in6_addr a, struct in6_addr m) {
    struct in6_addr ret;

    for (int i = 0; i < 16; i++)
        ret.s6_addr[i] = a.s6_addr[i] & m.s6_addr[i];

    return ret;
}

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route
 for the given protocol and destination address. Or NULL if there is no matching route.
*/
struct rtable_entry *get_best_route(uint16_t proto, struct in_addr dest_ip, struct in6_addr dest_ip6) {
    size_t idx = -1;	

    for (size_t i = 0; i < rtable_len; i++) {
        if ((proto == 4) && (rtable[i].proto == 4) && ((dest_ip.s_addr & rtable[i].netmask.s_addr) == rtable[i].network.s_addr)) {
	    if (idx == -1) idx = i;
	    else if (ntohl(rtable[idx].netmask.s_addr) < ntohl(rtable[i].netmask.s_addr)) idx = i;
	    else if ((rtable[idx].netmask.s_addr == rtable[i].netmask.s_addr) && (rtable[idx].metric > rtable[i].metric)) idx = i;
	}

        if ((proto == 6) && (rtable[i].proto == 6) && (in6_cmp(in6_mask(dest_ip6, rtable[i].netmask6), rtable[i].network6) == 0)) {
	    if (idx == -1) idx = i;
	    else if (in6_cmp(rtable[idx].netmask6, rtable[i].netmask6) < 0) idx = i;
	    else if ((in6_cmp(rtable[idx].netmask6, rtable[i].netmask6) == 0) && (rtable[idx].metric > rtable[i].metric)) idx = i;
	}
    }
    
    if (idx == -1)
        return NULL;

    else
        return &rtable[idx];
}

/*
 Returns a pointer (eg. &nei_table[i]) to the best matching neighbor table entry.
 for the given protocol and destination address. Or NULL if there is no matching route.
*/
struct nei_entry *get_nei_entry(uint16_t proto, struct in_addr dest_ip, struct in6_addr dest_ip6) {
    for (size_t i = 0; i < nei_table_len; i++) {
        if ((nei_table[i].proto == 4) && (proto == 4) && (memcmp(&dest_ip, &nei_table[i].ip, sizeof(struct in_addr)) == 0))
	    return &nei_table[i];

        if ((nei_table[i].proto == 6) && (proto == 6) && (memcmp(&dest_ip6, &nei_table[i].ip6, sizeof(struct in6_addr)) == 0))
	    return &nei_table[i];
    }

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

	rtable_len = read_rtable(rtable);
	nei_table_len = read_nei_table(nei_table);
	/* Students will write code here */

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *eth = (struct ether_header *) m.payload;

		struct iphdr *iph;
		struct ip6_hdr *ip6h;

		struct in_addr dest_ip;
		struct in6_addr dest_ip6;
		uint16_t proto;

		if (ntohs(eth->ether_type) == 0x0800) {
			iph = ((void *) eth) + sizeof(struct ether_header);
			
			if (ip_checksum((void *) iph, sizeof(struct iphdr)) != 0)
				continue;

			if (iph->ttl == 0)
				continue;

			dest_ip.s_addr = iph->daddr;
			proto = 4;
		}

		if (ntohs(eth->ether_type) == 0x86DD) {
			ip6h = ((void *) eth) + sizeof(struct ether_header);

			if (ip6h->ip6_ctlun.ip6_un1.ip6_un1_hlim == 0)
				continue;

			dest_ip6 = ip6h->ip6_dst;
			proto = 6;
		}

		struct rtable_entry *route = get_best_route(proto, dest_ip, dest_ip6);
		if (route == NULL)
			continue;

		struct nei_entry *nei = get_nei_entry(proto, route->nexthop, route->nexthop6);
		if (nei == NULL)
			continue;

		if (proto == 4) {
			iph->ttl--;
			iph->check = 0;
			iph->check = ip_checksum((void *) iph, sizeof(struct iphdr));
		}

		if (proto == 6)
			ip6h->ip6_ctlun.ip6_un1.ip6_un1_hlim--;

		memcpy(eth->ether_dhost, nei->mac, 6);
		get_interface_mac(route->interface, eth->ether_shost);

		send_packet(route->interface, &m);
	}
}
