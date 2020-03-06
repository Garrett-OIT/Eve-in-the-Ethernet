#!/bin/bash
# script for Eve to mount and read for updated bpf programs

LOG="/eve/mount_log"
set +e

echo "mounting" >> $LOG
if [ ! -d /media/$2$3$4 ]; then
    mkdir /media/$2$3$4
fi
mount $1$3 /media/$2$3$4
#systemd-mount --no-block --automount=yes --collect $1$3 /media/$2$3$4
# give it a second to mount
sleep 1

echo "declaring vars" >> $LOG
MOUNT="/media/$2$3$4"
EVE_PY="eve.py"
EVE_C="eve.c"
CLEAN="eve_clean.py"

echo "checking for eve.py and eve.c" >> $LOG
if [ -f "$MOUNT/$EVE_PY" -a -f "$MOUNT/$EVE_C" ]; then
    echo "found eve.py and eve.c! copying" >> $LOG
    cp $MOUNT/$EVE_PY /eve/$EVE_PY
    cp $MOUNT/$EVE_C /eve/$EVE_C
    echo "restarting eve service..." >> $LOG
    systemctl stop eve.service
    systemctl start eve.service
    bash /eve/blinkLED.sh 1
fi

# also check for the clean program, which is called by eve.service ExecStop
echo "checking for $MOUNT/$CLEAN" >> $LOG
if [ -f "$MOUNT/$CLEAN" ]; then
    echo "eve_clean found! copying" >> $LOG
    cp $MOUNT/$CLEAN /eve/$CLEAN
    bash /eve/blinkLED.sh 1
fi
