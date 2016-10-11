#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <string.h>

void arp_request(pcap_t *handle, struct in_addr * sender_ip, struct ether_addr *sender_mac, struct in_addr *target_ip, struct ether_addr *target_mac) {
	struct ether_header ether;
	struct ether_header *ether_reply;
	struct ether_arp arp;
	struct ether_arp *arp_reply;
	struct ether_addr destination, source;
	u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	struct pcap_pkthdr header;
	const u_char *reply;
	char mac_imm[50];

	ether.ether_type = htons(ETHERTYPE_ARP); 

	ether_aton_r("ff:ff:ff:ff:ff:ff", &destination);

	memcpy(ether.ether_dhost, &destination.ether_addr_octet, ETHER_ADDR_LEN);

	memcpy(ether.ether_shost, sender_mac->ether_addr_octet, ETHER_ADDR_LEN);

	arp.arp_hrd = htons(ARPHRD_ETHER);
	arp.arp_pro = htons(ETHERTYPE_IP);
	arp.arp_hln = ETHER_ADDR_LEN;
	arp.arp_pln = sizeof(struct in_addr);
	arp.arp_op = htons(ARPOP_REQUEST);

	memcpy(&arp.arp_sha, sender_mac, ETHER_ADDR_LEN);
	memcpy(&arp.arp_spa, sender_ip, sizeof(struct in_addr));
	ether_aton_r("00:00:00:00:00:00", &source);
	memcpy(&arp.arp_tha, &source, ETHER_ADDR_LEN);
	memcpy(&arp.arp_tpa, target_ip, sizeof(struct in_addr));

	memcpy(packet, &ether, sizeof(struct ether_header));
	memcpy(packet+sizeof(struct ether_header), &arp, sizeof(struct ether_arp));
    while(1) {
    	if(pcap_sendpacket(handle, packet, sizeof(packet)) == -1)
    		printf("error\n");

    	reply = pcap_next(handle, &header);

    	if(reply != NULL) {
    		
    		ether_reply = (struct ether_header*)reply;
			
			if(ntohs(ether_reply->ether_type) != ETHERTYPE_ARP)
				continue;
			
			arp_reply = (struct ether_arp *)(reply+14);
			if(ntohs(arp_reply->arp_op) != ARPOP_REPLY)
				continue;
			
			if(memcmp(target_ip, arp_reply->arp_spa, sizeof(struct in_addr)) !=0)
				continue;
			
			if(memcmp(sender_ip, arp_reply->arp_tpa, sizeof(struct in_addr)) !=0)
				continue;

			memcpy(target_mac->ether_addr_octet, arp_reply->arp_sha, ETHER_ADDR_LEN);
			
			ether_ntoa_r(arp_reply->arp_sha, mac_imm);
			printf("%s\n\n", mac_imm);
			break;
    	}

    }
}