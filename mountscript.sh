#!/bin/bash
# script for Eve to mount and read for updated bpf programs
#
# format is /dev/sdc sdc 1 /media/sdc1DEVICENAME, to work with udev rule
# rule is something like
# KERNEL=="sd[abcde]", SUBSYSTEM=="block", SUBSYSTEMS=="usb", ATTRS{product}=="Cruzer Fit", ATTRS{serial}=="", \
#       ACTION=="add", RUN+="thisscript $devnode $name 1 $env{ID_MODEL}"

systemd-mount --no-block --automount=yes --collect $1$3 /media/$2$3$4

MOUNT="/media/$2$3$4"
EVE_PY="eve.py"
EVE_C="eve.c"
CLEAN="eve_clean.py"

if [ -f "$MOUNT/$EVE_PY" ]; then
    cp $MOUNT/$EVE_PY /eve/$EVE_PY
    cp $MOUNT/$EVE_C /eve/$EVE_C
    systemctl restart eve.service
    ./eve/blinkLED.sh 1
fi

# also check for the clean program, which is called by eve.service ExecStop
if [ -f "$MOUNT/$CLEAN" ]; then
    cp $MOUNT/$CLEAN /eve/$CLEAN
fi
