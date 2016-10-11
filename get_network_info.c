#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <string.h>

void get_network_info(char *dev, struct in_addr *attacker_ip, struct ether_addr *attacker_mac, struct in_addr *gateway_ip){
	char cmd[200], ip_imm[50], mac_imm[50], gateway_ip_imm[50];
	FILE *fp;

	sprintf(cmd, "ifconfig | grep -A 1 '%s' | grep 'inet addr' | awk '{print $2}' | awk -F':' '{print $2}'",dev);

	fp = popen(cmd, "r");
	fgets(ip_imm, sizeof(ip_imm), fp);
	pclose(fp);

	printf("Attacker's IP: %s\n", ip_imm);

	inet_aton(ip_imm, attacker_ip);
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	sprintf(cmd, "ifconfig | grep '%s' | awk '{print$5}'",dev);
	
	fp = popen(cmd, "r");
	fgets(mac_imm, sizeof(mac_imm), fp);
	pclose(fp);

	printf("Attacker's MAC: %s\n", mac_imm);

	ether_aton_r(mac_imm, attacker_mac);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	sprintf(cmd, "netstat -rn |grep -A 1 'Gateway' | awk '{print $2}' | awk '{print $1}' | tail -n 1");

	fp=popen(cmd, "r");
	fgets(gateway_ip_imm, sizeof(gateway_ip_imm), fp);
	pclose(fp);

	printf("Gateway IP: %s\n", gateway_ip_imm);

	inet_aton(gateway_ip_imm, gateway_ip);
}