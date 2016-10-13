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

}