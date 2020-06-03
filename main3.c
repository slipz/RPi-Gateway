#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        
#include <libnetfilter_queue/libnetfilter_queue.h>

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
}


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

    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);   
    id = ntohl(ph->packet_id);
    
    int ret = nfq_get_payload(nfa, &buf);

    int index = 9;      // IP Header Protocol Field



    if(buf[index] == 0x11){
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
        if(dest_port == r_goose_port){
            // Packet for R-GOOSE Application
            index += 6;     // UDP Payload - R-GOOSE
            if(buf[index] == 0x01 && buf[index+1] == 0x40){
                // Init Sesstion Header Valid


                // Fetching index of physical interface packet arrived
                u_int32_t iinterface = nfq_get_physindev(nfa);

                if(iinterface == ied_if_index){
                    // IED -> RPi -> Network

                    uint8_t* dest = NULL;
                    int res = r_gooseMessage_InsertHMAC(&buf[index], key, key_size, HMAC_SHA256_80, &dest);
                    uint8_t* tmp = (uint8_t*)malloc((ret*sizeof(uint8_t))+MAC_SIZES[HMAC_SHA256_80]);
                    memcpy(tmp,buf,28);
                    memcpy(&tmp[28], dest, ret-28+MAC_SIZES[HMAC_SHA256_80]);

                    encodeInt2Bytes(tmp, udp_length+MAC_SIZES[HMAC_SHA256_80], 24);

                    encodeInt2Bytes(tmp, ret+MAC_SIZES[HMAC_SHA256_80], 2);

                    r_goose_dissect(&tmp[28]);

                    tmp[26] = 0x00;
                    tmp[27] = 0x00;

                    uint16_t checksum = udp_checksum(tmp, ret+MAC_SIZES[HMAC_SHA256_80],decode_4bytesToInt(tmp,12),decode_4bytesToInt(tmp,16));

                    printf("checksum: %d\n", checksum);
                    
                    encodeInt2Bytes(tmp, checksum, 26);

                    return nfq_set_verdict(qh, id, NF_ACCEPT, ret+MAC_SIZES[HMAC_SHA256_80], tmp);


                }else if(iinterface == network_if_index){
                    // Network -> RPi -> IED


                    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

                }else{
                    // Not normal - Suspicious traffic ? DROP or simply ACCEPT?
                    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
                }
            }else{
                // Not for R-GOOSE 
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
            }
        }else{
            // Not for R-GOOSE 
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }

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