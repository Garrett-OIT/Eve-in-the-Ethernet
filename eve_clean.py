from pyroute2 import IPRoute
ip = IPRoute()
idx = ip.link_lookup(ifname="wan")[0]
ip.tc("del", "clsact", idx)
