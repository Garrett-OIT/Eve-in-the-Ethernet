# Eve-in-the-Ethernet
## Overview
Eve in the Ethernet is a man-in-the-middle network device that records and potentially modifies traffic over an Ethernet connection. It's intended for educational purposes, as a tool to learn more about networking and network security. Eve forwards packets, records packets in removable media, and can be programmed to modify packets. Eve will be a Linux application, likely written as a eBPF program running on the EspressoBIN single-board computer.

Eve was a year-long project that I created to hack around with Linux and BPF. It's more of a learning experiment than a polished design.

## Background
### eBPF and bpfilter
BPF (Berkley Packet Filter) was [originally designed](https://www.tcpdump.org/papers/bpf-usenix93.pdf) in 1992 as a way to filter packet data in the kernel without the need to copy it to userspace. BPF is a simple virtual machine architecture that the kernel runs. eBPF ("extended" BPF) was the result of Alexei Starovoitov's development in 2013 and includes tools that can be used to develop kernel modules in userspace to work with network packets, such as in the popular utility tcpdump and network management tool bpfilter. eBPF also introduced new kernel hooks that can be used for kernel tracing.

The [BPF Compiler Collection](https://github.com/iovisor/bcc#bpf-compiler-collection-bcc) (BCC) includes tools for writing C programs that compile to eBPF bytecode, which can be loaded into the kernel with the [bpf system call](http://man7.org/linux/man-pages/man2/bpf.2.html). Eve will likely make use of these tools to achieve its functionality.

Although Linux support for BPF has been around since the 2.5 kernel, it is still under active development. Bpfilter is proposed as a replacement for iptables and nftables for network management in the Linux kernel, but is not yet a working substitute for iptables or nftables. As such, it's an exciting time to study and be on the forefront of new development, but there may be additional research challenges involved with choosing to implement Eve with eBPF.
