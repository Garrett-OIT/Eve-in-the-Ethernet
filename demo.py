# demo.py - a work in progress demo of using BPF to block IP addresses
# author - Garrett Fechter garrett.fechter@gmail.com
from __future__ import print_function
from bcc import BPF
from pyroute2 import IPRoute
from bcc.utils import printb
import time
import socket
from ctypes import *

# load the BPF C source to compile to eBPF bytecode
b = BPF(src_file="demo.c")

# below is traffic control BPF
# this loads and compiles it
fn = b.load_func("basic_filter", BPF.SCHED_CLS)
# use pyroute2 lib as wrapper over tc
ip = IPRoute()
# get index of desired interface
idx = ip.link_lookup(ifname="wlp4s0")[0]

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

# add cls_act to device
ip.tc("add", "clsact", idx)
# add ingress bpf in direct-action mode
# direct action mode means the return from the classifier will also filter
ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", classid=1, direct_action=True)

# below is simple socket_filter BPF
#fn = b.load_func("basic_filter", BPF.SOCKET_FILTER)
#BPF.attach_raw_socket(fn, "wlp4s0")

while 1:
    print("Starting custom filter...")
    try:
        #b.trace_print()
        time.sleep(9999)
    except ValueError:
        continue
    except KeyboardInterrupt:
        print("Dropped packets:")
        print(b["data"].values())
        print("\nip histogram")
        b["time"].print_linear_hist("seconds")
    finally:
        ip.tc("del", "clsact", idx)
        exit()
