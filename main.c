/* 
	Raspberry Pi Security Gateway
	Ensure integrity properties on R-GOOSE Message
*/

#include <stdio.h>
#include <string.h>

#include <pthread.h>
#include <unistd.h>

//openssl headers
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>

#include "security_extension.h"

#define BUFLEN 1024

#define PORT 8888


void* receiverThread(void *vargp){
	while(1){
		printf("ola\n");
		sleep(1);
	}
}


/*void senderThread_Old(){
	int s, recv_len = 0;
	uint8_t buffer = (uint8_t*) malloc(BUFLEN);
	struct sockaddr_in si_me, si_other;
	socklen_t slen = sizeof(si_other);

	if((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
		perror("socket");
		exit(1);
	}

	memset((char*) &si_me, 0, sizeof(si_me));

	si_me.sin_family 		= AF_INET;
	si_me.sin_addr.s_addr 	= htons(INADDR_ANY);
	si_me.sin_port 			= htons(PORT);

	if(bind(s, (struct sockaddr*) &si_me, sizeof(si_me)) < 0){
		perror("bind failed");
		exit(1);
	}	


	while(1){
		printf("waiting ...\n");
		if((recv_len = recvfrom(s, buffer, BUFLEN, 0, (struct sockaddr*) &si_other, &slen)) == -1){
			//perror("recvfrom()");
			//exit(1);

			// keep doing stuff and send final message 
			
			


		}
		
		printf("%s\n",buffer);
	}

	close(s);

}*/



void senderThread(){

	int source_addr_size, data_size, dest_addr_size, bytes_sent;
	struct sockaddr_ll source_addr, dest_addr;

	unsigned char *buffer = malloc(65535);

	int receiver_socket; //= socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); //verificar htons e sock_raw
	int sender_socket; //= socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);


	if((receiver_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1){
		perror("socket");
		exit(1);
	}

	if((sender_socket = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1){
		perror("socket");
		exit(1);
	}


	memset(&source_addr, 0, sizeof(struct sockaddr_ll));
    source_addr.sll_family = AF_PACKET;
    source_addr.sll_protocol = htons(ETH_P_ALL);
    source_addr.sll_ifindex = if_nametoindex("eth0");
    if (bind(receiver_socket, (struct sockaddr*) &source_addr, sizeof(source_addr)) < 0) {
        perror("bind failed\n");
        close(receiver_socket);
    }

    memset(&dest_addr, 0, sizeof(struct sockaddr_ll));
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_protocol = htons(ETH_P_ALL);
    dest_addr.sll_ifindex = if_nametoindex("eth1");
    if (bind(sender_socket, (struct sockaddr*) &dest_addr, sizeof(dest_addr)) < 0) {
      perror("bind failed\n");
      close(sender_socket);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "wlan0");
    if (setsockopt(sender_socket, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        perror("bind to wlan0");
    }

    while(1)
    {
        source_addr_size = sizeof (struct sockaddr);
        dest_addr_size = sizeof (struct sockaddr);
        //Receive a packet
        data_size = recvfrom(receiver_socket , buffer , 65536 , 0 ,(struct sockaddr *) &source_addr , (socklen_t*)&source_addr_size);

        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        else{
        printf("Received %d bytes\n",data_size);

        //Huge code to process the packet (optional)

        //Send the same packet out
        bytes_sent=write(sender_socket,buffer,data_size);
        printf("Sent %d bytes\n",bytes_sent);
         if (bytes_sent < 0) {
            perror("sendto");
            exit(1);
         }

        }
    }

    close(receiver_socket);
    return 0;

}






int main(int argc, char** argv){


	pthread_t treceiver_id;

	// IED <- RPi <- Network;
	pthread_create(&treceiver_id, NULL, receiverThread, (void*)&treceiver_id);

	// IED -> RPi -> Network
	senderThread();

	
}

