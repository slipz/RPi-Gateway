/* 
	Raspberry Pi Security Gateway
	Ensure integrity properties on R-GOOSE Message
*/

#include <stdio.h>
#include <string.h>

#include <pthread.h>
#include <unistd.h>

#include <pcap.h>


char* iedSideI = "enp0s8"; //trocar eth0
char* netSideI = "eth1";

char errbuf[PCAP_ERRBUF_SIZE];

int max_packets = 1000;

void
got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);



/* ---------------------------------------------------------- */

void
got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){
	printf("yooo just got a packet!\n");
	printf("Data: %s\n",packet);
}

void* receiverThread(void *vargp){
	while(1){
		printf("ola\n");
		sleep(1);
	}
}



void senderThread(){
	printf("%s\n",iedSideI);
	printf("%s\n",netSideI);
	
	pcap_t *handler;
	handler = pcap_open_live(iedSideI, BUFSIZ, 1, 1000, errbuf);

	if(handler == NULL){
		fprintf(stderr, "Could not open device %s: %s\n",iedSideI,errbuf);
		return;
	}

	// Analyse support for headers -> in this case, Ethernet

	pcap_loop(handler, max_packets, got_packet, NULL);

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



