#!/bin/bash
# basic bash script to mount a device
# format is /dev/sdc sdc 1 /media/sdc1DEVICENAME, to work with udev rule
# rule is something like
# KERNEL=="sd[abcde]", SUBSYSTEM=="block", SUBSYSTEMS=="usb", ATTRS{product}=="Cruzer Fit", ATTRS{serial}=="", \
#       ACTION=="add", RUN+="thisscript $devnode $name 1 $env{ID_MODEL}"
echo mounting $1 $2 $3 $4 >> /home/garrett/tools/mount_log
systemd-mount --no-block --automount=yes --collect $1$3 /media/$2$3$4
