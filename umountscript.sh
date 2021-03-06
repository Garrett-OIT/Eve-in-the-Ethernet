#!/bin/bash
# basic bash script to umount a device
# format is /dev/sdc sdc 1 DEVICENAME, to work with udev rule
# rule is something like
# KERNEL=="sd[abcde]", SUBSYSTEM=="block", SUBSYSTEMS=="usb", ATTRS{product}=="Cruzer Fit", ATTRS{serial}=="", \
#       ACTION=="add", RUN+="thisscript $devnode $name 1 $env{ID_MODEL}"
#systemd-umount $1$3
LOG="/eve/mount_log"
echo "Removing /media/$2$3$4 mount point from system" >> $LOG
umount /media/$2$3$4
rmdir /media/$2$3$4
