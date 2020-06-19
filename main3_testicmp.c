#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "r_goose_security.h"
#include "aux_funcs.h"

// Use "ip addr show" to get interface index
int ied_if_index = 2;
int network_if_index = 3;

// R-GOOSE UDP Port in use: Default 102
int r_goose_port = 102;

// Fixed key values ...
uint8_t* key;
int key_size;

unsigned char *pacote;
long filelen;

#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100
 


// Can create separate header file (.h) for all headers' structure

// The IP header's structure

struct ipheader {
 unsigned char      iph_ihl:4, iph_ver:4;

 unsigned char      iph_tos;

 unsigned short int iph_len;

 unsigned short int iph_ident;

//    unsigned char      iph_flag;

 unsigned short int iph_offset;

 unsigned char      iph_ttl;

 unsigned char      iph_protocol;

 unsigned short int iph_chksum;

 unsigned int       iph_sourceip;

 unsigned int       iph_destip;

};

 

// UDP header's structure

struct udpheader {

 unsigned short int udph_srcport;

 unsigned short int udph_destport;

 unsigned short int udph_len;

 unsigned short int udph_chksum;

};

/* Compute checksum for count bytes starting at addr, using one's complement of one's complement sum*/
static unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
  register unsigned long sum = 0;
  while (count > 1) {
    sum += * addr++;
    count -= 2;
  }
  //if any bytes left, pad the bytes and add
  if(count > 0) {
    sum += ((*addr)&htons(0xFF00));
  }
  //Fold sum to 16 bits: add carrier to result
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }
  //one's complement
  sum = ~sum;
  return ((unsigned short)sum);
}

/* set ip checksum of a given ip header*/
void compute_ip_checksum(struct iphdr* iphdrp){
  iphdrp->check = 0;
  iphdrp->check = compute_checksum((unsigned short*)iphdrp, iphdrp->ihl<<2);
}




//based on snippet found
//www.linuxquestions.org/questions/linux-networking-3/udp-checksum-algorithm-845618/
//then modified by Gabriel Serme

struct pseudo_hdr {
    u_int32_t source;
    u_int32_t dest;
    u_int8_t zero; //reserved, check http://www.rhyshaden.com/udp.htm
    u_int8_t protocol;
    u_int16_t udp_length;
};

unsigned short csum (unsigned short *buf, int nwords);

uint16_t udp_checksum(const struct iphdr *ip, const struct udphdr *udp, const uint16_t *buf){
//take in account padding if necessary
    int calculated_length = ntohs(udp->len)%2 == 0 ? ntohs(udp->len) : ntohs(udp->len) + 1;

    struct pseudo_hdr ps_hdr = {0};
    bzero (&ps_hdr, sizeof(struct pseudo_hdr));
    uint8_t data[sizeof(struct pseudo_hdr) + calculated_length];
    bzero (data, sizeof(struct pseudo_hdr) + calculated_length );

    ps_hdr.source = ip->saddr;
    ps_hdr.dest = ip->daddr;
    ps_hdr.protocol = IPPROTO_UDP; //17
    ps_hdr.udp_length = udp->len;

    memcpy(data, &ps_hdr, sizeof(struct pseudo_hdr));

    //the remaining bytes are already set to 0
    memcpy(data + sizeof(struct pseudo_hdr), buf, ntohs(udp->len) );

    return csum((uint16_t *)data, sizeof(data)/2);
}

/* Not my code */
unsigned short csum (unsigned short *buf, int nwords){
    unsigned long sum;

    for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}




/*unsigned int checksum(uint16_t *usBuff, int isize)
{
    unsigned int cksum=0;
    for(;isize>1;isize-=2){
        cksum+=*usBuff++;
    }
    if(isize==1){
        cksum+=*(uint16_t *)usBuff;
    }
    return (cksum);
}

uint16_t check_udp_sum(uint8_t *buffer, int len)
{
    unsigned long sum=0;
    struct ipheader *tempI=(struct ipheader *)(buffer);
    struct udpheader *tempH=(struct udpheader *)(buffer+sizeof(struct ipheader));

    tempH->udph_chksum=0;
    sum=checksum( (uint16_t *)   &(tempI->iph_sourceip) ,8 );
    sum+=checksum((uint16_t *) tempH,len);

    sum+=ntohs(IPPROTO_UDP+len);
    
    sum=(sum>>16)+(sum & 0x0000ffff);
    sum+=(sum>>16);

    return (uint16_t)(~sum);
    
}


uint16_t udp_checksum(const void* buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr){
    
    const uint16_t *buf=buff;
    uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
    uint32_t sum;
    size_t length=len;

    // Calculate the sum                                            //
    sum = 0;
    while (len > 1)
    {
         sum += *buf++;
         if (sum & 0x80000000)
                 sum = (sum & 0xFFFF) + (sum >> 16);
         len -= 2;
    }

    if ( len & 1 )
         // Add the padding if the packet lenght is odd          //
         sum += *((uint8_t *)buf);

    // Add the pseudo-header                                        //
    sum += *(ip_src++);
    sum += *ip_src;

    sum += *(ip_dst++);
    sum += *ip_dst;

    sum += htons(IPPROTO_UDP);
    sum += htons(length);

    // Add the carries                                              //
    while (sum >> 16)
         sum = (sum & 0xFFFF) + (sum >> 16);

    // Return the one's complement of sum                           //
    return ( (uint16_t)(~sum)  );
}*/


void display_packet( char *buf, int n ){
    unsigned char   ch;    for (int i = 0; i < n; i+=16)
        {
        printf( "\n%04X: ", i );
        for (int j = 0; j < 16; j++)
            {
            ch = ( i + j < n ) ? buf[ i+j ] : 0;
            if ( i + j < n ) printf( "%02X ", ch );
            else    printf( "   " );
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


static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi; 
    int ret;
    char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        printf("payload_len=%d ", ret);
        display_packet(data,ret);
    }

    fputc('\n', stdout);

    return id;
}


  

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    printf("entering callback\n");

    u_int32_t id;
    char* buf;
    char* buf1;

    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);   
    id = ntohl(ph->packet_id);
    
    int ret = nfq_get_payload(nfa, &buf1);
    buf = pacote;



    int index = 9;      // IP Header Protocol Field





    //if(buf[index] == 0x11){
    if(buf1[index] == 0x01){
        // Protocol == UDP
        printf("Protocol: UDP\n");

        int udp_length, dest_port;

        index = 20;         // IP Header End -> Init next protocol
        udp_length = decode_2bytesToInt(buf,index+4);
        printf("UDP len: %d\n",udp_length);

        index += 2;         // UDP Dest Port
        dest_port = decode_2bytesToInt(buf,index);
        printf("dest_port: %d\n", dest_port);

        // Verificar se está correto no ambiente real
        //if(dest_port == r_goose_port){
            // Packet for R-GOOSE Application
            index += 6;     // UDP Payload - R-GOOSE
            //if(buf[index] == 0x01 && buf[index+1] == 0x40){
                // Init Sesstion Header Valid


                // Fetching index of physical interface packet arrived
                u_int32_t iinterface = nfq_get_physindev(nfa);

                //if(iinterface == ied_if_index){
                    // IED -> RPi -> Network

                    int alg1 = GMAC_AES256_128;

                    uint8_t* dest = NULL;
                    int res = r_gooseMessage_InsertGMAC(&buf[index], key, key_size, alg1, &dest);
                    uint8_t* tmp = (uint8_t*)malloc((filelen*sizeof(uint8_t))+MAC_SIZES[alg1]);
                    memcpy(tmp,buf,28);
                    memcpy(&tmp[28], dest, filelen-28+MAC_SIZES[alg1]);

                    encodeInt2Bytes(tmp, udp_length+MAC_SIZES[alg1], 24);

                    encodeInt2Bytes(tmp, filelen+MAC_SIZES[alg1], 2);

                    encodeInt2Bytes(tmp, 0, 10);
			
//		    r_goose_dissect(dest);

//                  r_goose_dissect(&tmp[28]);

                    //uint16_t checksum = udp_checksum(tmp, ret+MAC_SIZES[HMAC_SHA256_80],decode_4bytesToInt(tmp,12),decode_4bytesToInt(tmp,16));

                    //uint16_t checksum = check_udp_sum(tmp, ret - sizeof(struct ipheader));

                    
                    struct iphdr *ip = (struct iphdr *)tmp; 
                    struct udphdr *udp = (struct udphdr *)((void *) ip + sizeof(struct iphdr));

                    compute_ip_checksum(ip);

                    udp->check = 0;

                    uint16_t checksum = htons(udp_checksum(ip,udp, udp));

                    encodeInt2Bytes(tmp, checksum, 26);

                    printf("checksum: %02x %02x\n", tmp[26], tmp[27]);

                    //return nfq_set_verdict(qh, id, NF_ACCEPT, ret+MAC_SIZES[HMAC_SHA256_80], tmp);

		    

                    
	            int res_set = nfq_set_verdict(qh, id, NF_ACCEPT, ret, buf1);
		    free(dest);
      		    free(tmp);

		    return res_set;
			
                //}else if(iinterface == network_if_index){
                    // Network -> RPi -> IED


                    //return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

                //}else{
                    // Not normal - Suspicious traffic ? DROP or simply ACCEPT?
                    //return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
                //}
            //}else{
                // Not for R-GOOSE 
                //return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
            //}
        //}else{
            // Not for R-GOOSE 
            //return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        //}

    // Else if could be changed to single else
    }else{
        printf("Protocol: %02x\n", buf[index]);
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    
}



int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    
    char keyHex[] = "11754cd72aec309bf52f7687212e8957";
    key = hexStringToBytes(keyHex, 32);
    key_size = 16;


    // REMOVER
    FILE *fp;
    

    char* filename = "packet.pkt";

    fp = fopen(filename, "rb");

    fseek(fp, 0, SEEK_END);

    filelen = ftell(fp);
    rewind(fp);

    pacote = (unsigned char*) malloc(filelen*sizeof(char));

    fread(pacote, filelen, 1, fp);
    fclose(fp);


    pacote = pacote+14;

    int l;
    for(l = 0; l<filelen; l++){
        printf("%02X ", pacote[l]);
    }
    printf("\n\n\n");


    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    // para el tema del loss:   while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)

    while ((rv = recv(fd, buf, sizeof(buf), 0)))
    {
        printf("pkt received\n");
        nfq_handle_packet(h, buf, rv);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    free(key);

    exit(0);
}
