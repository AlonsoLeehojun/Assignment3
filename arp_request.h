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

}