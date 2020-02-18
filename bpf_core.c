// bpf_core.c - Eve's framework functionality
//      includes pseudocode for planned functionality
// author - Garrett Fechter garrett.fechter@gmail.com
//

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <uapi/linux/pkt_cls.h>
#include <bcc/proto.h>
#include <net/sock.h>

// need to decide how to forward packets from one interface to another
// tentative: tc bpf using bpf_redirect
//
// hash1 is incoming packet data, hash1[0] is current index
//
// if (changingPacket)
//      serial.light3.blink()
// if (packet.isIncoming())
//      cyclicalIndex = hash1[0]
//      hash1[cyclicalIndex] = packet
//      cyclicalIndex++
//      if (cyclicalIndex > hash1.len)
//           cyclicalIndex = 1
