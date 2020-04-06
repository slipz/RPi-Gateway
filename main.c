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

#include<arpa/inet.h>
#include<sys/socket.h>

#include "security_extension.h"

#define BUFLEN 1024

#define PORT 8888


void* receiverThread(void *vargp){


}


void senderThread(){
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
			perror("recvfrom()");
			exit(1);

			// keep doing stuff and send final message 

		}
		
		printf("%s\n",buffer);
	}

	close(s);

}

int main(int argc, char** argv){


	pthread_t treceiver_id;

	// IED <- RPi <- Network;
	pthread_create(&treceiver_id, NULL, receiverThread, (void*)&treceiver_id);

	// IED -> RPi -> Network
	senderThread();

	
}

