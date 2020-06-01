#include <netinet/in.h> 
#include <linux/netfilter.h> 
#include <libipq.h> 
#include <stdio.h> 
#include <stdlib.h>


#define BUFSIZE 2048
static void die(struct ipq_handle *h)
{
    ipq_perror("passer");
    ipq_destroy_handle(h);
    exit(1);
}
int main(int argc, char **argv)
{
    int status, i=0;
    unsigned char buf[BUFSIZE];
    struct ipq_handle *h;
    h = ipq_create_handle(0, NFPROTO_IPV4);

    if (!h)     die(h);

    status = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);

    if (status < 0) die(h);

    do{
        i++;
        status = ipq_read(h, buf, BUFSIZE, 0);

        if (status < 0) die(h);

        switch (ipq_message_type(buf)) {
            case NLMSG_ERROR:
                fprintf(stderr, "Received error message %d\n",
                ipq_get_msgerr(buf));
                break;
            case IPQM_PACKET:
            {
                ipq_packet_msg_t *m = ipq_get_packet(buf);
                printf("\nReceived Packet");
                /****YOUR CODE TO MODIFY PACKET GOES HERE****/
                status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, 0, NULL);
                if (status < 0)  die(h);
                break;
            }
            default:
                fprintf(stderr, "Unknown message type!\n");
                break;
        }
    } while (1);
    ipq_destroy_handle(h);
    return 0;
}
