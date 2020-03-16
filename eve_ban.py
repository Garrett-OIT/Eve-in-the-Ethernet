# Garrett Fechter garrett.fechter@gmail.com
from __future__ import print_function
from bcc import BPF
from pyroute2 import IPRoute
from bcc.utils import printb
import time
import socket
import subprocess
import os
import sys
from ctypes import *

def PrintIP(ip_h):
    pass
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
f = open("bpf_output", "ab")

# load the BPF C source to compile to eBPF bytecode
b = BPF(src_file="eve.c")
# below is traffic control BPF
# this loads and compiles it
fn = b.load_func("basic_filter", BPF.SCHED_CLS)

# use pyroute2 lib as wrapper over tc
ip = IPRoute()
# get index of desired interface idx = ip.link_lookup(ifname="lan1")[0]
idx = ip.link_lookup(ifname="wan")[0]
idx2 = ip.link_lookup(ifname="lan0")[0]

#banned = b.get_table("banned_ips")
#for k, v in sorted(banned.items(), key=lambda banned: banned[1].value):
#        print("%s \"%x\"" % (socket.inet_ntoa(int.to_bytes(v.value, 4, "big")), k.value))

# add cls_act to device
ip.tc("add", "clsact", idx)
ip.tc("add", "clsact", idx2)
# add ingress bpf in direct-action mode
# direct action mode means the return from the classifier will also filter
ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", classid=1, direct_action=True)
ip.tc("add-filter", "bpf", idx2, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", classid=1, direct_action=True)

# add banned_ips into the BPF hash
banned_ips = [ "8.8.8.8", "157.240.3.35" ]
index = 0
for b_ip in banned_ips:
    ip_int = int.from_bytes(socket.inet_aton(b_ip), "big")
    print("banning", b_ip)
    b["banned_ips"].__setitem__(c_int(index), c_ulong(ip_int))
    index += 1

banned = b.get_table("banned_ips")
for k, v in sorted(banned.items(), key=lambda banned: banned[1].value):
        print("%s \"%x\"" % (socket.inet_ntoa(int.to_bytes(v.value, 4, "big")), k.value))

print("Starting packet capture...")
max_saved = 0
while 1:
    #try:
        time.sleep(.2)
        #subprocess.call("bash blinkLED.sh 2", shell=True)
        max_stored = b["count"][0].value
        if (max_saved < max_stored):
            print("saved is", max_saved, "count is", max_stored)
            # save packets from stored+1 to saved
            for i in range(max_saved, max_stored):
                #print("a tlen was", b["packets"][c_int(i)])
                ip_header = (b["headers"][c_uint(i)])
                packet_bytes = b["packets"][c_int(i)]
                f.write(ip_header)
                f.write(packet_bytes)
                print("i is", i)
                print("packet_bytes is size:", sys.getsizeof(packet_bytes))
                print("and type", type(packet_bytes))
                print("raw data:", packet_bytes)

                print("packet_bytes.data is size:", sys.getsizeof(packet_bytes.data))
                print("and type", type(packet_bytes.data))
                print("raw data:", packet_bytes)
                PrintIP(ip_header)
            max_saved = max_stored
        elif (max_saved > max_stored):
            #wrapped around
            for i in range(max_saved, 1000):
                ip_header = (b["headers"][c_uint(i)])
                f.write(b["packets"][c_int(i)])
                #f.write(ip_header);
                PrintIP(ip_header)
            for i in range(0, max_stored):
                f.write(b["packets"][c_int(i)])
                ip_header = (b["headers"][c_uint(i)])
                #f.write(ip_header);
                PrintIP(ip_header)
            max_saved = max_stored
        f.flush()
        os.fsync(f)
    #except KeyboardInterrupt:
    #    ip.tc("del", "clsact", idx)
