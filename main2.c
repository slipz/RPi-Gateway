//gcc -Wall main2.c security_extension.c -o a.out -lssl -lcrypto -lpthread -lpcap

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <pthread.h>
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <net/if.h>

#include <pcap.h>


/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14	// Ethernet Header Size

#define IP4_HDRLEN 20  // IPv4 header length


/* Ethernet header */
struct ethernet_header {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip_header {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)



char* iedSideI = "eth0"; //trocar eth0
char* netSideI = "eth1";

char* iedSideI_addr;
char* netSideI_addr;
char* ied_ip_addr = "192.168.2.2"; // must not be hardcoded

char errbuf1[PCAP_ERRBUF_SIZE];
char errbuf2[PCAP_ERRBUF_SIZE];

int max_packets = 1000;


void
processPacket_Ied_to_Net(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);

void
processPacket_Net_to_Ied(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);

void
transmitPacket();

uint16_t 
checksum (uint16_t *addr, int len);


int64_t timespecDiff(struct timespec *timeA_p, struct timespec *timeB_p)
{
  return ((timeA_p->tv_sec * 1000000000) + timeA_p->tv_nsec) -
           ((timeB_p->tv_sec * 1000000000) + timeB_p->tv_nsec);
}


void sendPacketLayer2(unsigned char* buffer, size_t size, char* interface){

	int sd, bytes;

	struct sockaddr_ll device;

	/* Manipulate packet */
	struct ethernet_header* ethernet;
	char* payload;

	// Populate auxiliar structs
	ethernet = (struct ethernet_header*)(buffer);
	payload = (u_char*)(buffer + SIZE_ETHERNET);


//	if(ethernet->ether_type == 8){

		memset (&device, 0, sizeof (device));
		if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
		  perror ("if_nametoindex() failed to obtain interface index ");
		  exit (EXIT_FAILURE);
		}

		device.sll_family = AF_PACKET;
		memcpy (device.sll_addr, ethernet->ether_dhost, 6 * sizeof (uint8_t));
		device.sll_halen = 6;

		// Submit request for a raw socket descriptor.
		if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
		  perror ("socket() failed ");
		  exit (EXIT_FAILURE);
		}		

		// Send ethernet frame to socket.
		if ((bytes = sendto (sd, buffer, size, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
		  perror ("sendto() failed");
		  exit (EXIT_FAILURE);
		}

		close(sd);
//	}
}








void
processPacket_Ied_to_Net(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){
	
	struct timespec start, end;
  	clock_gettime(CLOCK_MONOTONIC, &start);

	unsigned char	ch;

	printf( "\npacket\n");

	int n = header->len;

	for (int i = 0; i < n; i+=16)
	{
		printf( "\n%04X: ", i );
		for (int j = 0; j < 16; j++)
			{
			ch = ( i + j < n ) ? packet[ i+j ] : 0;
			if ( i + j < n ) printf( "%02X ", ch );
			else	printf( "   " );
			}
		for (int j = 0; j < 16; j++)
			{
			ch = ( i + j < n ) ? packet[ i+j ] : ' ';
			if (( ch < 0x20 )||( ch > 0x7E )) ch = '.';
			printf( "%c", ch );
			}
	}
	printf( "\n%d bytes read\n-------\n", n );


	// Gather packet info and analyse it



	// Transmit packet on eth1 (External Network Interface)	
	sendPacketLayer2(packet, header->len, netSideI);

	clock_gettime(CLOCK_MONOTONIC, &end);
	uint64_t timeElapsed = timespecDiff(&end, &start);

  	long seconds = end.tv_sec - start.tv_sec;
  	long ns = end.tv_nsec - start.tv_nsec;

  	printf("sendPacketLayer2_IED_NET secs: %lf\n",(double)seconds + (double)ns/(double)1000000000);


}


void
processPacket_Net_to_Ied(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){
	struct timespec start, end;
  	clock_gettime(CLOCK_MONOTONIC, &start);

	unsigned char	ch;

	printf( "\npacket\n");

	int n = header->len;

	for (int i = 0; i < n; i+=16)
	{
		printf( "\n%04X: ", i );
		for (int j = 0; j < 16; j++)
			{
			ch = ( i + j < n ) ? packet[ i+j ] : 0;
			if ( i + j < n ) printf( "%02X ", ch );
			else	printf( "   " );
			}
		for (int j = 0; j < 16; j++)
			{
			ch = ( i + j < n ) ? packet[ i+j ] : ' ';
			if (( ch < 0x20 )||( ch > 0x7E )) ch = '.';
			printf( "%c", ch );
			}
	}
		printf( "\n%d bytes read\n-------\n", n );

	// Transmit to internal network -> IED 
	sendPacketLayer2(packet, header->len, iedSideI);

	clock_gettime(CLOCK_MONOTONIC, &end);
	uint64_t timeElapsed = timespecDiff(&end, &start);

  	long seconds = end.tv_sec - start.tv_sec;
  	long ns = end.tv_nsec - start.tv_nsec;

  	printf("sendPacketLayer2_NET_IED secs: %lf\n",(double)seconds + (double)ns/(double)1000000000);



}



void* receiverThread(void *vargp){
	printf("%s\n",netSideI);
	
	pcap_t *handler;
	handler = pcap_open_live(netSideI, BUFSIZ, 1, 1000, errbuf2);

	if(handler == NULL){
		fprintf(stderr, "Could not open device %s: %s\n",netSideI,errbuf2);
		return;
	}
	
	if(pcap_setdirection(handler, PCAP_D_IN) == -1){
		printf("error\n");
	}

	// Analyse support for headers -> in this case, Ethernet

	pcap_loop(handler, max_packets, processPacket_Net_to_Ied, NULL);

	pcap_close(handler);

	printf("Thread Receiver Done.\n");
}


void senderThread(){
	printf("%s\n",iedSideI);
		
	pcap_t *handler;
	handler = pcap_open_live(iedSideI, BUFSIZ, 1, 1000, errbuf1);
	
	if(handler == NULL){
		fprintf(stderr, "Could not open device %s: %s\n",iedSideI,errbuf1);
		return;
	}
	
	if(pcap_setdirection(handler, PCAP_D_IN) == -1){
		printf("error\n");
	}

	// Analyse support for headers -> in this case, Ethernet

	pcap_loop(handler, max_packets, processPacket_Ied_to_Net, NULL);

	pcap_close(handler);

	printf("Thread Sender Done.\n");

}




int main(int argc, char** argv){

	/* Pre-configuration 
		- Getting interfaces IPv4 Addresses 
	*/

	// Allocate necessary memory - change to aux function
	iedSideI_addr = (char*)malloc(INET_ADDRSTRLEN * sizeof(char));
	netSideI_addr = (char*)malloc(INET_ADDRSTRLEN * sizeof(char));

	// Zero strings
	memset(iedSideI_addr, 0, INET_ADDRSTRLEN * sizeof(char));
	memset(netSideI_addr, 0, INET_ADDRSTRLEN * sizeof(char));

	// Getting Linked List of interfaces and respective info
	struct ifaddrs *ifaddr, *ifa;
	int s, family;
	char host[NI_MAXHOST];

	if(getifaddrs(&ifaddr) == -1){
		perror("getifaddrs");
		exit(1);
	}

	// Look for our interfaces - ifname in global variables
	for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next){
		if(strcmp(ifa->ifa_name,iedSideI) == 0){
			// IedSide Interface
			if(ifa->ifa_addr == NULL){
				// IP address not assigned -> ERROR 
				perror("Interface: Ip address not assigned.");
				exit(1);
			}

			family = ifa->ifa_addr->sa_family;

			if(family == AF_INET){
				s = getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),
				host, NI_MAXHOST,
				NULL, 0, NI_NUMERICHOST);

				if(s != 0){
					perror("getnameinfo() error");
					printf("%d\n",s);
					exit(1);
				}

				strcpy(iedSideI_addr, host);
				printf("Interface %s: %s\n", iedSideI, iedSideI_addr);
			}

		}else if(strcmp(ifa->ifa_name,netSideI) == 0){
			// NetSIde Interface
						// IedSide Interface
			if(ifa->ifa_addr == NULL){
				// IP address not assigned -> ERROR 
				perror("Interface: Ip address not assigned.");
				exit(1);
			}

			family = ifa->ifa_addr->sa_family;

			if(family == AF_INET){
				s = getnameinfo(ifa->ifa_addr,
					(family == AF_INET) ? sizeof(struct sockaddr_in) :
										  sizeof(struct sockaddr_in6),
					host, NI_MAXHOST,
					NULL, 0, NI_NUMERICHOST);

				if(s != 0){
					perror("getnameinfo() error");
					exit(1);
				}

				strcpy(netSideI_addr, host);
				printf("Interface %s: %s\n", netSideI, netSideI_addr);
			}

		
		}else{
			// Irrelevant Interface
			continue;
		}
	} 





	pthread_t treceiver_id;

	// IED <- RPi <- Network;
	pthread_create(&treceiver_id, NULL, receiverThread, (void*)&treceiver_id);

	// IED -> RPi -> Network
	senderThread();

	
}
