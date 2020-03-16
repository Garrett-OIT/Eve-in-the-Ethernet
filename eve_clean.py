from pyroute2 import IPRoute
ip = IPRoute()
idx = ip.link_lookup(ifname="wan")[0]
ip.tc("del", "clsact", idx)
idx = ip.link_lookup(ifname="lan0")[0]
ip.tc("del", "clsact", idx)
