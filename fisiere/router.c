#include "queue.h"
#include "skel.h"
#include <netinet/if_ether.h>


void arp_reply(packet m, struct ether_header *eth_hdr, struct ether_arp *arp_hdr, int interface) {
	
	struct ether_arp *arp_hdr0 = (struct ether_header *)(m.payload + sizeof(struct ether_header));
	struct ether_header *eth_hdr0 = (struct ether_hrader *)m.payload;
	uint8_t *aux = malloc(6*sizeof(uint8_t));
	get_interface_mac(interface, aux);

	memcpy(eth_hdr0->ether_shost, aux, ETH_ALEN);
	memcpy(eth_hdr0->ether_dhost, eth_hdr->ether_shost, ETH_ALEN);

	eth_hdr0->ether_type = htons(0x806);
	arp_hdr0->arp_hrd = htons(ARPHRD_ETHER);
	arp_hdr0->arp_pro = htons(ETHERTYPE_IP);
	arp_hdr0->arp_hln = 6;
	arp_hdr0->arp_pln = 4;
	arp_hdr0->arp_op = htons(ARPOP_REPLY);
	memcpy(arp_hdr0->arp_sha, eth_hdr->ether_shost, 6);
	memcpy(arp_hdr0->arp_tha, eth_hdr->ether_dhost, 6);
	memcpy(arp_hdr0->arp_spa, arp_hdr->arp_tpa, 4);
	memcpy(arp_hdr0->arp_tpa, arp_hdr->arp_spa, 4);

	packet pack;
	pack.len = sizeof(struct ether_header) + sizeof(struct ether_arp);
	pack.interface = interface;
	memset(pack.payload, 0, 1600);
	memcpy(pack.payload, eth_hdr, sizeof(struct ether_header));
	memcpy(pack.payload + sizeof(struct ether_header), arp_hdr0, sizeof(struct ether_arp));
	send_packet(&pack);

}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	queue q;
	q = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct ether_arp *arp_hdr = (struct ether_arp*)(m.payload + sizeof(struct ether_header));
		
		if (ntohs(eth_hdr->ether_type) == 0x806) {
			if (ntohs(arp_hdr->arp_op) == ARPOP_REQUEST) {
				arp_reply(m, eth_hdr, arp_hdr, m.interface);
			}
			if (ntohs(arp_hdr->arp_op) == ARPOP_REPLY) {

			}
		}
	}
}
