/* 
	Raspberry Pi Security Gateway
	Ensure integrity properties on R-GOOSE Message
*/

#include <stdio.h>
#include <string.h>

#include <pthread.h>
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <net/if.h>

#include <pcap.h>


/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14	// Ethernet Header Size

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

char errbuf1[PCAP_ERRBUF_SIZE];
char errbuf2[PCAP_ERRBUF_SIZE];

int max_packets = 1000;

void
processPacket_Ied_to_Net(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);

void
processPacket_Net_to_Ied(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);

void
transmitPacket();


/* ---------------------------------------------------------- */

void
transmitPacket(){

	int raw_sd;

	/*if((raw_sd = socket(AF_PA))){

	}*/




}


void sendPacketLayer3(unsigned char* buffer, size_t size){

	int raw_sd;
	const int on = 1;

	struct ifreq ifr;
	struct sockaddr_in sin;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", "eth1");

	
	/* Manipulate packet */
	struct ethernet_header* ethernet;
	struct ip_header* ip;

	char* payload;
	
	printf("chegou\n");

	ethernet = (struct ethernet_header*)(buffer);
	printf("1\n");
	ip = (struct ip_header*)(buffer + SIZE_ETHERNET);
	printf("2\n");
	u_int size_ip = IP_HL(ip)*4;
	printf("3\n");
	payload = (u_char*)(buffer + SIZE_ETHERNET + size_ip);


	printf("buffer[0]: %04X",buffer[0]);
	ethernet->ether_dhost[0] = 0x13;
	printf("buffer[0]: %04X",buffer[0]);

	// Change source addr from IED to RPi
	inet_pton(AF_INET, "192.168.3.1", &(ip->ip_src));	


	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	inet_aton("192.168.3.2", &sin.sin_addr.s_addr);


	if((raw_sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
		perror("socket() failed");
		exit(1);
	}

	if(setsockopt(raw_sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
		perror("2nd error");
		exit(1);
	}

	if(setsockopt(raw_sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0){
		perror("3rd error");
		exit(1);
	}

	buffer = buffer + 14;

	if(sendto(raw_sd, buffer, size-14, 0, (struct sockaddr*)&sin, sizeof(struct sockaddr)) < 0){
		perror("4th error");
		exit(1);
	}

	close(raw_sd);


}


void
processPacket_Ied_to_Net(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){
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
	sendPacketLayer3(packet, header->len);


}


void
processPacket_Net_to_Ied(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){
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

}



void* receiverThread(void *vargp){
	printf("%s\n",netSideI);
	
	pcap_t *handler;
	handler = pcap_open_live(netSideI, BUFSIZ, 1, 1000, errbuf2);

	if(handler == NULL){
		fprintf(stderr, "Could not open device %s: %s\n",netSideI,errbuf2);
		return;
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

	// Analyse support for headers -> in this case, Ethernet

	pcap_loop(handler, max_packets, processPacket_Ied_to_Net, NULL);

	pcap_close(handler);

	printf("Thread Sender Done.\n");

}



int main(int argc, char** argv){


	pthread_t treceiver_id;

	// IED <- RPi <- Network;
	pthread_create(&treceiver_id, NULL, receiverThread, (void*)&treceiver_id);

	// IED -> RPi -> Network
	senderThread();

	
}



