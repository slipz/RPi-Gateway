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

#include <stdlib.h>		// for exit()
#include <signal.h>		// for signal()
#include <sys/socket.h>		// for socket(), recvfrom()
#include <sys/ioctl.h>		// for SIOCGIFFLAGS, SIOCSIFFLAGS
#include <netinet/in.h>		// for htons()
#include <linux/if_ether.h>	// for ETH_P_ALL
#include <linux/if.h>		// for struct ifreq, IFNAMSIZ



#include "security_extension.h"

#define BUFLEN 1024
#define PORT 8888

#define MTU	1536		// Maximum Transfer Unit (bytes)
#define MAX_NUM	10000		// Maximum allowed packet-number


char ifname[] = "eth0";		// name for the network interface
char ifname2[] = "eth1";	// name for the network interface2
struct ifreq	ethreq;		// structure for 'ioctl' requests
struct ifreq 	if_mac;
int	receiver_s1, receiver_s2, pkt_num;		// socket-ID and packet-number 



void my_cleanup( void )
{
	// turn off the interface's 'promiscuous' mode
	ethreq.ifr_flags &= ~IFF_PROMISC;  
	if ( ioctl( receiver_s1, SIOCSIFFLAGS, &ethreq ) < 0 )
		{ perror( "ioctl: set ifflags" ); exit(1); }
}


void my_handler( int signo ) 
{ 
	// This function executes when the user hits <CTRL-C>. 
	// It initiates program-termination, thus triggering
	// the 'cleanup' function we previously installed.
	exit(0); 
}


void display_packet( char *buf, int n )
{
	unsigned char	ch;

	printf( "\npacket #%d ", ++pkt_num );
	for (int i = 0; i < n; i+=16)
		{
		printf( "\n%04X: ", i );
		for (int j = 0; j < 16; j++)
			{
			ch = ( i + j < n ) ? buf[ i+j ] : 0;
			if ( i + j < n ) printf( "%02X ", ch );
			else	printf( "   " );
			}
		for (int j = 0; j < 16; j++)
			{
			ch = ( i + j < n ) ? buf[ i+j ] : ' ';
			if (( ch < 0x20 )||( ch > 0x7E )) ch = '.';
			printf( "%c", ch );
			}
		}
	printf( "\n%d bytes read\n-------\n", n );
}


/* ----------------------------------------------------------*/


void* receiverThread(void *vargp){
	while(1){
		printf("ola\n");
		sleep(1);
	}
}



void senderThread(){

	// create an unnamed socket for reception of ethernet packets 
	receiver_s1 = socket( PF_PACKET, SOCK_DGRAM, htons( ETH_P_ALL ) ); 
	if ( receiver_s1 < 0 ) { perror( "socket" ); exit( 1 ); }
	
	receiver_s2 = socket( PF_PACKET, SOCK_DGRAM, htons( ETH_P_ALL ) ); 
	if ( receiver_s2 < 0 ) { perror( "socket" ); exit( 1 ); }
	



	// enable 'promiscuous mode' for the selected socket interface
	strncpy( ethreq.ifr_name, ifname, IFNAMSIZ );
	if ( ioctl( receiver_s1, SIOCGIFFLAGS, &ethreq ) < 0 )
		{ perror( "ioctl: get ifflags" ); exit(1); }
	ethreq.ifr_flags |= IFF_PROMISC;  // enable 'promiscuous' mode
	if ( ioctl( receiver_s1, SIOCSIFFLAGS, &ethreq ) < 0 )
		{ perror( "ioctl: set ifflags" ); exit(1); }


	// Sender SOcket on eth1
	strncpy( ethreq.ifr_name, ifname2, IFNAMSIZ );
	if ( ioctl( receiver_s2, SIOCGIFFLAGS, &ethreq ) < 0 )
		{ perror( "ioctl: get ifflags" ); exit(1); }
	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifname2, IFNAMSIZ-1);
	if (ioctl(receiver_s2, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");



	// make sure 'promiscuous mode' will get disabled upon termination
	atexit( my_cleanup );
	signal( SIGINT, my_handler );

	// main loop to intercept and display the ethernet packets
	char	buffer[ MTU ];
	printf( "\nMonitoring all packets on interface \'%s\' \n", ifname );
	do	{
		int	n = recvfrom( receiver_s1, buffer, MTU, 0, NULL, NULL );
		
		// Processing packet

		display_packet( buffer, n );

		// send data
		int bytes_s;
		bytes_s = write(receiver_s2,buffer,n);
		if(bytes_s < 0){
			printf("erro\n");
		}else{
			printf("\nSent %d Bytes !\n", bytes_s);
		}

		}
	while ( pkt_num < MAX_NUM );

}



int main(int argc, char** argv){


	pthread_t treceiver_id;

	// IED <- RPi <- Network;
	pthread_create(&treceiver_id, NULL, receiverThread, (void*)&treceiver_id);

	// IED -> RPi -> Network
	senderThread();

	
}



