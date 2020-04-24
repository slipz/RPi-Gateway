/* 
	Raspberry Pi Security Gateway
	Ensure integrity properties on R-GOOSE Message
*/

#include <stdio.h>
#include <string.h>

#include <pthread.h>
#include <unistd.h>

#include <pcap.h>


char* iedSideI = "eth0"; //trocar eth0
char* netSideI = "eth1";

char errbuf1[PCAP_ERRBUF_SIZE];
char errbuf2[PCAP_ERRBUF_SIZE];

int max_packets = 1000;

void
processPacket_Ied_to_Net(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);

void
processPacket_Net_to_Ied(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);


/* ---------------------------------------------------------- */

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

	printf("Thread Sender Done.\n");
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



