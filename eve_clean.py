from pyroute2 import IPRoute
ip = IPRoute()
idx = ip.link_lookup(ifname="wlp4s0")[0]
ip.tc("del", "clsact", idx)
