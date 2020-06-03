// eve.c - a work in progress to save IP data
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
#define MAX_PACKET_LEN 250
#define MIN_PACKET_LEN 25

//#ifndef memcpy
//# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
//#endif

#define SAVE_INTERNAL(x) ip_data_p->data[x] = ip_data[x]

#define SAVE(from, to) if (ip_data + to > (char *) data_end) goto save; \
                       for (uint8_t i = from; i < to; i++) SAVE_INTERNAL(i); \
                       save_len++;

struct IP_Data {
    char data[MAX_PACKET_LEN];
};

BPF_HASH(headers, u64, struct ip_t, MAX_PACKETS + 1);
BPF_ARRAY(packets, struct IP_Data, MAX_PACKETS + 1);
BPF_ARRAY(lens, uint32_t, MAX_PACKETS + 1);
BPF_ARRAY(count, u64, 2);

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
    unsigned int tlen = iph_copy.tlen;
    // convert byte order
    unsigned int swap = tlen & 0xFF; //low order bits
    tlen = tlen >> 8;
    swap = swap << 8;
    tlen = tlen | swap;
    tlen = tlen & 0x7FFF;

    ip_data_p = packets.lookup(&count_key);
    if (ip_data_p == NULL) goto cleanup;
    //if ((void *) iph + tlen > data_end) goto cleanup;
    //if (tlen + 5  > MAX_PACKET_LEN) goto cleanup;
    //tlen++;
    bpf_trace_printk("tlen was %d\n", tlen);//, asdf);

    //bpf_skb_load_bytes(skb, sizeof(*eth), ip_data_p->data, (u32)tlen);
    char *ip_data = data + sizeof(*eth) + sizeof(*iph);

    uint32_t save_len = 0;
    SAVE(0, 10);
    SAVE(10, 20);
    SAVE(20, 30);
    SAVE(30, 40);
    SAVE(40, 50);
    SAVE(50, 60);
    SAVE(60, 70);
    SAVE(70, 80);
    SAVE(80, 90);
    SAVE(90, 100);
    SAVE(100, 110);
    SAVE(110, 120);
    SAVE(120, 130);
    SAVE(130, 140);
    SAVE(140, 150);
    SAVE(150, 160);
    SAVE(160, 170);
    SAVE(170, 180);
    SAVE(180, 190);
    SAVE(190, 200);
    SAVE(200, 210);
    SAVE(210, 220);
    SAVE(220, 230);
    SAVE(230, 240);
    SAVE(240, 250);

    /*bpf_trace_printk("some random data %x\n", 0xFF& ip_data_p->data[0]);//, asdf);
    bpf_trace_printk("some random data %x\n", 0xFF&ip_data_p->data[1]);//, asdf);
    bpf_trace_printk("some random data %x\n", 0xFF&ip_data_p->data[2]);//, asdf);
    bpf_trace_printk("some random data %x\n", 0xFF&ip_data_p->data[3]);//, asdf);
    bpf_trace_printk("some random data %x\n", 0xFF&ip_data_p->data[4]);//, asdf);
    bpf_trace_printk("some random data %x\n", 0xFF&ip_data_p->data[5]);//, asdf);
    bpf_trace_printk("some random data %x\n", 0xFF&ip_data_p->data[6]);//, asdf);
    bpf_trace_printk("some random data %x\n", 0xFF&ip_data_p->data[7]);//, asdf);
    bpf_trace_printk("some random data %x\n", 0xFF&ip_data_p->data[8]);//, asdf);
    bpf_trace_printk("some random data %x\n", 0xFF&ip_data_p->data[9]);//, asdf);
    bpf_trace_printk("some random data %x\n", 0xFF&ip_data_p->data[10]);//, asdf);
    bpf_trace_printk("some random data %x\n", 0xFF&ip_data_p->data[11]);//, asdf);
    bpf_trace_printk("some random data %x\n", 0xFF&ip_data_p->data[12]);//, asdf);
    bpf_trace_printk("some random data %d\n", ip_data_p->data[13]);//, asdf);
    bpf_trace_printk("some random data %d\n", ip_data_p->data[14]);//, asdf);
    bpf_trace_printk("some random data %d\n", ip_data_p->data[15]);//, asdf);
    bpf_trace_printk("some random data %d\n", ip_data_p->data[16]);//, asdf);
    bpf_trace_printk("some random data %d\n", ip_data_p->data[17]);//, asdf);
    bpf_trace_printk("some random data %d\n", ip_data_p->data[18]);//, asdf);
    bpf_trace_printk("some random data %d\n", ip_data_p->data[19]);//, asdf);
    bpf_trace_printk("some random data %d\n", ip_data_p->data[20]);//, asdf);
    bpf_trace_printk("some random data %d\n", ip_data_p->data[21]);//, asdf);
    bpf_trace_printk("some random data %d\n", ip_data_p->data[22]);//, asdf);
    bpf_trace_printk("some random data %d\n", ip_data_p->data[23]);//, asdf);
    */
save:
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
    lens.update((int *)max_packet_count_p, &save_len);
    // increment max packet index
    (*max_packet_count_p)++;
    if(*max_packet_count_p > MAX_PACKETS) *max_packet_count_p = 0;
    count.update(&count_key, max_packet_count_p);

cleanup:
    return TC_ACT_OK;
}
