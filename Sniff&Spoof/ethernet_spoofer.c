#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>  

int spoof_Ethernet_Package(void) {

	int i;
	int sd; 
	
	// This buffer will be used to construct raw packet.
	char buffer[1024]; // You can change the buffer size

	sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if(sd < 0) {
		perror("socket() error"); exit(-1);
	}

	const char *ip_src 		= "192.168.15.9"; // pick ip to be the source
	const char *ip_des      = "192.168.15.5"; // pick ip to be the destination

	// set up the headers
	struct ethhdr *eth_header = (struct ethhdr *) buffer;
	struct iphdr *ip_header = (struct iphdr *) (buffer + sizeof(struct ethhdr));
	struct icmphdr *icmp_header = (struct icmphdr *) (buffer + 
		sizeof(struct ethhdr) + sizeof(struct iphdr));
	// ethernet header
	const unsigned char des_Mac_Addr[]	= {0x01,0x02,0x03,0x04,0x05,0x06};
	memcpy(eth_header->h_source,des_Mac_Addr,6);
	eth_header->h_proto = htons(ETH_P_IP);
	// ip header
	ip_header->tot_len 		= sizeof(struct iphdr) + sizeof(struct icmphdr);
	ip_header->ttl 			= 64;
	ip_header->frag_off		= 0x0;
	ip_header->protocol 	= IPPROTO_ICMP;
	ip_header->saddr 		= inet_addr(ip_src);
	ip_header->daddr 		= inet_addr(ip_des);
	ip_header->version 		= 4;
	ip_header->ihl         	= 5;
	// icmp header
	icmp_header->type = ICMP_ECHO;
	icmp_header->code = 0;

	// find interface index for constructing socket
	// cite: http://man7.org/linux/man-pages/man7/netdevice.7.html
	struct ifreq socket_interfc;
	memset(&socket_interfc, 0x00, sizeof(socket_interfc));
	strncpy(socket_interfc.ifr_name, "eth14", IFNAMSIZ);
	ioctl(sd, SIOCGIFINDEX, &socket_interfc);
	int intrfc_idx = socket_interfc.ifr_ifindex;
	//build socket to send package
	// cite http://man7.org/linux/man-pages/man7/packet.7.html
	struct sockaddr_ll sock_addr;
	memset((void*)&sock_addr, 0, sizeof(sock_addr)); 
	sock_addr.sll_ifindex = intrfc_idx; 

	if(sendto(sd, buffer, ip_header->tot_len+14, 0, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) < 0) {
		perror("sendto() error"); exit(-1);
	}
	return 1;
}

int main(int argc, char const *argv[])
{
	int flag = spoof_Ethernet_Package();
	if (flag != 1) {
		printf("EthernetFrame spoofing failed.\n");
		exit(1);
	}
	printf("Spoofing successed!\n");

	return 0;
}
