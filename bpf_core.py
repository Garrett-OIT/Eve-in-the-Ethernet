# bpf_core.py - Eve's framework functionality
#   includes pseudocode for planned functionality
# author - Garrett Fechter garrett.fechter@gmail.com

from __future__ import print_function
from bcc import BPF
from pyroute2 import IPRoute
import time
import socket

# b = BPF(src_file="bpf_core.c")

# while 1
# sleep 1
# index = hash1[0]
# if index > prev_index
#   save hash1[prev_index] to hash1[index] on USB
# elif index < prev_index
#   save hash1[prev_index] to hash1[max]
#   save hash1[1] to hash1[index]
