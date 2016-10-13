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

}