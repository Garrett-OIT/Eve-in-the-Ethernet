// demo.c - a work in progress demo to show using BPF to block IP addresses
// author - Garrett Fechter garrett.fechter@gmail.com
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/fs.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>
#include <net/sock.h>

#define MAX_PACKETS 1000
#define MAX_PACKET_LEN 5000

//#ifndef memcpy
//# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
//#endif

struct IP_Data {
    char data[MAX_PACKET_LEN];
};

BPF_HASH(headers, u64, struct ip_t, MAX_PACKETS + 1);
BPF_ARRAY(packets, struct IP_Data, MAX_PACKETS + 1);
BPF_ARRAY(count, u64, 1);

int basic_filter(struct __sk_buff *skb) {
    //int ret = TC_ACT_OK;
    int count_key = 0;
    u64 zero = 0;
    u64 *max_packet_count_p = NULL;
    u8 *cursor = 0;
    struct IP_Data *ip_data_p = NULL;
    //unsigned short *ip_data_p = NULL;

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethernet_t *eth = cursor_advance(cursor, sizeof(*eth));
    if (eth->type != ETH_P_IP) goto cleanup;

    struct ip_t *iph = cursor_advance(cursor, sizeof(*iph));
    if ((data + sizeof(*eth) + sizeof(*iph)) + 1 > data_end) goto cleanup;
    iph = data + sizeof(*eth);
    struct ip_t iph_copy = *iph;
    unsigned int tlen = ((unsigned int*) iph)[0] >> 16;
    unsigned int swap = tlen & 0xFF; //low order bits
    tlen = tlen >> 8;
    swap = swap << 8;
    tlen = tlen | swap;
    tlen = tlen & 0x7FFF;

    ip_data_p = packets.lookup(&count_key);
    if (ip_data_p == NULL) goto cleanup;
    //if ((void *) iph + tlen > data_end) goto cleanup;
    if (tlen + 5  > MAX_PACKET_LEN) goto cleanup;
    tlen++;
    bpf_skb_load_bytes(skb, sizeof(*eth), ip_data_p->data, (u32)tlen);

    max_packet_count_p = count.lookup(&count_key);
    if (max_packet_count_p == NULL) {
        // first time, index=0
        count.update(&count_key, &zero);

        max_packet_count_p = count.lookup(&count_key);
        // get max packet index pointer, should be set now
        if (max_packet_count_p == NULL) goto cleanup;
    }
    if (*max_packet_count_p > MAX_PACKETS) {
        // shouldn't get here, max packet index was greater than max value
        // "drop" all packets
        count.update(&count_key, &zero);
        goto cleanup;
    }

    //if (data + sizeof(*eth) > data_end) goto cleanup;
    //iph = data + sizeof(*eth);
    //if (sizeof(iph) != iph->hlen * 8) goto cleanup;

    //*ip_data_p = tlen;

    //unsigned short asdf = 0x0000FFFF & iph->tlen;
    //bpf_trace_printk("asfd was %x\n", iph->src);//, asdf);
    //asdf &= 0x7FFFFFFF;
    //if (asdf > MAX_PACKET_LEN) goto cleanup;
    //if (data + asdf + sizeof(*eth) > data_end) goto cleanup;
    //if (tlen + sizeof(*eth) + sizeof(*iph) > data_end) goto cleanup;
    //if (tlen < 0) goto cleanup;
    //if (iph->tlen <= sizeof(iph)) goto cleanup;
    //u32 len = iph->tlen - sizeof(iph);
    //bpf_skb_load_bytes(skb, data + sizeof(*eth), ip_data_p, 100);
    //iph_copy.tlen = asdf;
    //if (ip == NULL) goto cleanup;
    //memcpy(&ip_copy, ip, sizeof(ip_copy));
    //bpf_skb_load_bytes(skb, ip, copy);
    headers.update(max_packet_count_p, &iph_copy);
    packets.update((int *)max_packet_count_p, ip_data_p);
    // increment max packet index
    (*max_packet_count_p)++;
    if(*max_packet_count_p > MAX_PACKETS) *max_packet_count_p = 0;
    count.update(&count_key, max_packet_count_p);

cleanup:
    return TC_ACT_OK;
}
