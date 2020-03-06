#!/bin/bash
# Status LED for wan and lan0 interfaces
# Blinks when both arent connected
# On while both are
GPIONUM=505 # corresponds to pin 23 on the P8 header
VALUEFILE=/sys/class/gpio/gpio$GPIONUM/value
WAN_FILE="/sys/class/net/wan/carrier"
LAN0_FILE="/sys/class/net/lan0/carrier"

# enable gpio pin if needed
if [ ! -f "$VALUEFILE" ]; then
    echo $GPIONUM > /sys/class/gpio/export
    echo out > /sys/class/gpio/gpio$GPIONUM/direction
fi

while true; do
    WAN_STAT=`cat $WAN_FILE`
    LAN0_STAT=`cat $LAN0_FILE`
    if [ "$WAN_STAT" -eq "0" ]; then
	echo 0 > /sys/class/gpio/gpio$GPIONUM/value
	sleep .25
	echo 1 > /sys/class/gpio/gpio$GPIONUM/value
	sleep .25
    elif [ "$LAN0_STAT" -eq "0" ]; then
	echo 0 > /sys/class/gpio/gpio$GPIONUM/value
	sleep .25
	echo 1 > /sys/class/gpio/gpio$GPIONUM/value
	sleep .25
    else
	echo 1 > /sys/class/gpio/gpio$GPIONUM/value
	sleep 3
    fi
done
