// demo.c - a work in progress demo to show using BPF to block IP addresses
// author - Garrett Fechter garrett.fechter@gmail.com
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <uapi/linux/pkt_cls.h>
#include <bcc/proto.h>
#include <net/sock.h>

BPF_HISTOGRAM(time);
BPF_HASH(data);
BPF_HASH(banned_ips);

int basic_filter(struct __sk_buff *skb) {
    int ret = TC_ACT_OK;
    u8 *cursor = 0;
    u64 *stored_start_p, start_key = 0;
    u64 delta = 0;
    u64 now = bpf_ktime_get_ns();

    stored_start_p = data.lookup(&start_key);
    // if lookup existed
    if (stored_start_p != NULL) {
        // delta is now - stored start time converted to seconds
        delta = (now - *stored_start_p) / 1000000000;
        time.increment(delta);
    }
    else {
        // first time
        data.update(&start_key, &now);
    }

    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if (ethernet->type != ETH_P_IP)
    goto cleanup;

    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

    u64 idx = 0;
    u64 drop_key = 1;
    u64 *count = 0;

    u64 *ip_p = banned_ips.lookup(&idx);
    if (ip_p) {
        if (ip->src == *ip_p || ip->dst == *ip_p) {
            ret = TC_ACT_SHOT;
            count = data.lookup(&drop_key);
            if (count != NULL) *count += 1;
            else data.update(&drop_key, &drop_key);
            ret = TC_ACT_SHOT;
        }
    }

    // this repetition is really gross, but a for loop wasn't being accepted by verifier
    idx++;
    ip_p = banned_ips.lookup(&idx);
    if (ip_p) {
        if (ip->src == *ip_p || ip->dst == *ip_p) {
            ret = TC_ACT_SHOT;
            count = data.lookup(&drop_key);
            if (count != NULL) *count += 1;
            else data.update(&drop_key, &drop_key);
            ret = TC_ACT_SHOT;
        }
    }
    idx++;
    ip_p = banned_ips.lookup(&idx);
    if (ip_p) {
        if (ip->src == *ip_p || ip->dst == *ip_p) {
            ret = TC_ACT_SHOT;
            count = data.lookup(&drop_key);
            if (count != NULL) *count += 1;
            else data.update(&drop_key, &drop_key);
            ret = TC_ACT_SHOT;
        }
    }
    idx++;
    ip_p = banned_ips.lookup(&idx);
    if (ip_p) {
        if (ip->src == *ip_p || ip->dst == *ip_p) {
            ret = TC_ACT_SHOT;
            count = data.lookup(&drop_key);
            if (count != NULL) *count += 1;
            else data.update(&drop_key, &drop_key);
            ret = TC_ACT_SHOT;
        }
    }
    idx++;
    ip_p = banned_ips.lookup(&idx);
    if (ip_p) {
        if (ip->src == *ip_p || ip->dst == *ip_p) {
            ret = TC_ACT_SHOT;
            count = data.lookup(&drop_key);
            if (count != NULL) *count += 1;
            else data.update(&drop_key, &drop_key);
            ret = TC_ACT_SHOT;
        }
    }
    idx++;
    ip_p = banned_ips.lookup(&idx);
    if (ip_p) {
        if (ip->src == *ip_p || ip->dst == *ip_p) {
            ret = TC_ACT_SHOT;
            count = data.lookup(&drop_key);
            if (count != NULL) *count += 1;
            else data.update(&drop_key, &drop_key);
            ret = TC_ACT_SHOT;
        }
    }
    idx++;
    ip_p = banned_ips.lookup(&idx);
    if (ip_p) {
        if (ip->src == *ip_p || ip->dst == *ip_p) {
            ret = TC_ACT_SHOT;
            count = data.lookup(&drop_key);
            if (count != NULL) *count += 1;
            else data.update(&drop_key, &drop_key);
            ret = TC_ACT_SHOT;
        }
    }
    idx++;
    ip_p = banned_ips.lookup(&idx);
    if (ip_p) {
        if (ip->src == *ip_p || ip->dst == *ip_p) {
            ret = TC_ACT_SHOT;
            count = data.lookup(&drop_key);
            if (count != NULL) *count += 1;
            else data.update(&drop_key, &drop_key);
            ret = TC_ACT_SHOT;
        }
    }
    idx++;
    ip_p = banned_ips.lookup(&idx);
    if (ip_p) {
        if (ip->src == *ip_p || ip->dst == *ip_p) {
            ret = TC_ACT_SHOT;
            count = data.lookup(&drop_key);
            if (count != NULL) *count += 1;
            else data.update(&drop_key, &drop_key);
            ret = TC_ACT_SHOT;
        }
    }
    idx++;
    ip_p = banned_ips.lookup(&idx);
    if (ip_p) {
        if (ip->src == *ip_p || ip->dst == *ip_p) {
            ret = TC_ACT_SHOT;
            count = data.lookup(&drop_key);
            if (count != NULL) *count += 1;
            else data.update(&drop_key, &drop_key);
            ret = TC_ACT_SHOT;
        }
    }

cleanup:
    return ret;
}
