# Garrett Fechter garrett.fechter@gmail.com
from __future__ import print_function
from bcc import BPF
from pyroute2 import IPRoute
from bcc.utils import printb
import time
import socket
from ctypes import *

def PrintIP(ip_h):
    print(ip_h)
    print("ver:", ip_h.ver)
    print("hlen:", ip_h.hlen)
    print("tos:", ip_h.tos)
    print("tlen:", ip_h.tlen)
    print("identification:", ip_h.identification)
    print("ffo_unused:", ip_h.ffo_unused)
    print("df:", ip_h.df)
    print("mf:", ip_h.mf)
    print("foffset:", ip_h.foffset)
    print("ttl:", ip_h.ttl)
    print("nextp:", ip_h.nextp)
    print("hchecksum:", ip_h.hchecksum)
    print("src:", socket.inet_ntoa(int.to_bytes(ip_header.src, 4, "little")))
    print("dst:", socket.inet_ntoa(int.to_bytes(ip_header.dst, 4, "little")))

def ip_t_to_IP_HEADER(ip):
    return IP_HEADER(ip.ver, ip.hlen, ip.tos, ip.tlen, ip.identification, \
            ip.ffo_unused, ip.df, ip.mf, ip.foffset, ip.ttl, ip.nextp, \
            ip.hchecksum, ip.src, ip.dst)

class IP_HEADER(Structure):
    _fields_ = [("ver", c_ubyte, 4),
                ("hlen", c_ubyte, 4),
                ("tos", c_ubyte),
                ("tlen", c_ushort),
                ("identification", c_ushort),
                ("ffo_unused", c_ushort, 1),
                ("df", c_ushort, 1),
                ("mf", c_ushort, 1),
                ("foffset", c_ushort, 13),
                ("ttl", c_ubyte),
                ("nextp", c_ubyte),
                ("hchecksum", c_ushort),
                ("src", c_uint),
                ("dst", c_uint),
               ]

# open logging file
f = open("/home/garrett/scrap/eve/bpf_output", "ab")

# load the BPF C source to compile to eBPF bytecode
b = BPF(src_file="demo.c")
# below is traffic control BPF
# this loads and compiles it
fn = b.load_func("basic_filter", BPF.SCHED_CLS)

# use pyroute2 lib as wrapper over tc
ip = IPRoute()
# get index of desired interface idx = ip.link_lookup(ifname="wlp4s0")[0]
idx = ip.link_lookup(ifname="wlp4s0")[0]

#banned = b.get_table("banned_ips")
#for k, v in sorted(banned.items(), key=lambda banned: banned[1].value):
#        print("%s \"%x\"" % (socket.inet_ntoa(int.to_bytes(v.value, 4, "big")), k.value))

# add cls_act to device
ip.tc("add", "clsact", idx)
# add ingress bpf in direct-action mode
# direct action mode means the return from the classifier will also filter
ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", classid=1, direct_action=True)

print("Starting packet capture...")
max_saved = 0
while 1:
    max_stored = b["count"][0].value
    if (max_saved < max_stored):
        # save packets from stored+1 to saved
        for i in range(max_saved, max_stored):
            ip_header = bytes((b["headers"][c_uint(i)]))
            f.write(ip_header);
            #PrintIP(ip_header)
        max_saved = max_stored
    elif (max_saved > max_stored):
        #wrapped around
        for i in range(max_saved, 999):
            ip_header = bytes((b["headers"][c_uint(i)]))
            f.write(ip_header);
            #PrintIP(ip_header)
        for i in range(0, max_stored):
            ip_header = bytes((b["headers"][c_uint(i)]))
            f.write(ip_header);
            #PrintIP(ip_header)
        max_saved = max_stored
