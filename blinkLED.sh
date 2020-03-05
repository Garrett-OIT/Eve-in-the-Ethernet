#!/bin/bash
# This blinks an LED attached to the ESPRESSOBin
if [ -z "$1" ]; then
    echo "Specify LED 1, 2 or 3"
    exit
fi
if [ "$1" -eq 1 ]; then
    GPIONUM=504 # corresponds to pin 6 on the P8 header
elif [ "$1" -eq 2 ]; then
    GPIONUM=492 # corresponds to pin 7 on the P8 header
elif [ "$1" -eq 3 ]; then
    GPIONUM=505 # corresponds to pin 23 on the P8 header
else
    echo "Specify LED 1, 2, or 3"
    exit
fi

VALUEFILE=/sys/class/gpio/gpio$GPIONUM/value

# enable gpio pin if needed
if [ ! -f "$VALUEFILE" ]; then
    echo $GPIONUM > /sys/class/gpio/export
    echo out > /sys/class/gpio/gpio$GPIONUM/direction
fi

echo 1 > $VALUEFILE
sleep .2
echo 0 > $VALUEFILE
