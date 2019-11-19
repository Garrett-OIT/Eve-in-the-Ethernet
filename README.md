# Eve-in-the-Ethernet
## About Me
I'm Garrett Fechter, a student at Oregon Institute of Technology. Eve in the Ethernet is my year-long individual senior project. I am pursuing a Bachelor of Science in Embedded Systems Engineering Technology. 
## Overview
Eve in the Ethernet is a man-in-the-middle network device that records and potentially modifies traffic over an Ethernet connection. It's intended for education purposes, as a tool to learn more about networking and network security. Eve forwards packets, records packets in removable media, and can be programmed to modify packets. Eve will be a Linux application, likely written as a eBPF program running on the EspressoBIN single-board computer.
## Background
### eBPF and bpfilter
The extended Berkely Packet Filter is a simple virtual machine architecture that the kernel runs. eBPF includes tools that can be used to develop kernel modules in userspace to work with network packets (see the [original BPF proposal](https://www.tcpdump.org/papers/bpf-usenix93.pdf)), such as in the popular utility tcpdump and network management tool bpfilter. eBPF can also be used for kernel tracing and monitoring various events. The Berkley Compiler Collection includes tools for writing C programs that compile to BPF, which can be loaded into the kernel with the bpf system call. Eve will likely make use of these tools to achieve its functionality.

Although Linux support for BPF has been around since the 2.5 kernel, it is still under active development. Bpfilter is proposed as a replacement for iptables and nftables for network management in the Linux kernel, but is not yet a working substitute for iptables or nftables. As such, it's an exciting time to study and be on the forefront of new development, but there may be additional research challenges involved with choosing to implement Eve with eBPF.
## Hardware
Eve will likely run on the [EspressoBIN single board computer](http://espressobin.net/tech-spec/) for prototyping, but should be portable to any BPF-enabled Linux kernel.
