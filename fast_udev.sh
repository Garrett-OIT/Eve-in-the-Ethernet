#!/bin/bash
# script for Eve to mount and read for updated bpf programs
#
# format is /dev/sdc sdc 1 /media/sdc1DEVICENAME, to work with udev rule
# rule is something like
# KERNEL=="sd[abcde]", SUBSYSTEM=="block", SUBSYSTEMS=="usb", ATTRS{product}=="Cruzer Fit", ATTRS{serial}=="", \
#       ACTION=="add", RUN+="thisscript $devnode $name 1 $env{ID_MODEL}"

echo "ARG1=$1" > /eve/mount.conf
echo "ARG2=$2" >> /eve/mount.conf
echo "ARG3=$3" >> /eve/mount.conf
echo "ARG4=$4" >> /eve/mount.conf
systemctl restart eve_mount.service
