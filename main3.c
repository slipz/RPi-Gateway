#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "r_goose_security.h"


void display_packet( char *buf, int n )
{
    unsigned char   ch;

//    printf( "\npacket #%d ", ++pkt_num );
    for (int i = 0; i < n; i+=16)
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
    u_int32_t id;
    char* buf;

    int ret = nfq_get_payload(nfa, &buf);

    int index = 9;      // IP Header Protocol Field

    if(buf[index] == 0x11){
        // Protocol == UDP
        printf("Protocol: UDP\n");
        index = 20;         // IP Header End -> Init next protocol
        index += 8;         // UDP Payload
    }else if(buf[index] == 0x06){
        printf("Protocol: TCP\n");
    }else if(buf[index] == 0x01){
        printf("Protocol: ICMP\n");
    }
    


    //printf("buf[20] = %02x\n",buf[20]);



    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);   
    id = ntohl(ph->packet_id);
    printf("entering callback\n");

    return nfq_set_verdict(qh, id, NF_ACCEPT, ret, buf);
}



int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

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

    exit(0);
}