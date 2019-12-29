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

int spoof_Icmp_Package(void) {
	int i;
	int sd; 
	struct sockaddr_in sin;
	// This buffer will be used to construct raw packet.
	char buffer[1024]; // You can change the buffer size

	/* Create a raw socket with IP protocol. The IPPROTO_RAW parameter
	 * tells the sytem that the IP header is already included;
	 * this prevents the OS from adding another IP header.  */
	sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(sd < 0) {
		perror("socket() error"); exit(-1);
	}

	/* This data structure is needed when sending the packets
	 * using sockets. Normally, we need to fill out several
	 * fields, but for raw sockets, we only need to fill out
	 * this one field */
	sin.sin_family = AF_INET;

	// Here you can construct the IP packet using buffer[]
	//    - construct the IP header ...
	//    - construct the TCP/UDP/ICMP header ...
	//    - fill in the data part if needed ...
	// Note: you should pay attention to the network/host byte order.
	struct iphdr *ip_header = (struct iphdr *) buffer;
	struct icmphdr *icmp_header = (struct icmphdr *) (buffer + sizeof(struct iphdr));

	const char *src 		= "192.168.15.7"; 
	const char *des     	= "192.168.15.5";
    ip_header->tot_len 		= sizeof(struct iphdr) + sizeof(struct icmphdr);
    ip_header->ttl 			= 64;
    ip_header->frag_off		= 0x0;
    ip_header->protocol 	= IPPROTO_ICMP;
    ip_header->saddr 		= inet_addr(src);
    ip_header->daddr 		= inet_addr(des);
    ip_header->version 		= 4;
	ip_header->ihl         	= 5;

	icmp_header->type = ICMP_ECHO;
	icmp_header->code = 0;

	/* Send out the IP packet. * ip_len is the actual size of the packet. */
	if(sendto(sd, buffer, ip_header->tot_len, 0, (struct sockaddr *)&sin, 
		sizeof(sin)) < 0) {

		perror("sendto() error"); exit(-1);
	}
	return 1;
}

int main(int argc, char const *argv[])
{
    int flag = spoof_Icmp_Package();
    if(flag == 1) {
    	printf("Spoofing successed!.\n");
    }
	return 0;
}
