#!/bin/bash

sudo modprobe -r iwlwifi
sudo modprobe iwlwifi debug=0x1
sudo rfkill unblock wlan

sleep 3

intfs=$(iw dev | grep Interface | cut -d' ' -f2 | cut -d' ' -f1)
intf=$(echo $intfs | cut -d' ' -f1)
intf2=$(echo $intfs | cut -d' ' -f2)
echo "First interface name: ${intf}"
echo "Secondary interface name: ${intf2}"
if [ $intf == "wlan1" ]
then
    intf=$intf2
fi

echo "Main interface name: ${intf}"

if [ $intf != "" ]
then
    sudo ifconfig ${intf} down
    sudo iw ${intf} interface add mon0 type monitor
    sudo ifconfig mon0 up
else
    echo "No wireless interface foud!"
fi

echo "Enter band [2|5|6]:"
read -r bw
echo "Enter channel:"
read -r chan
echo "Enter channel width [20|40|80|160|320]:"
read -r chan_width

sudo ifconfig ${intf} up
sudo iw dev ${intf} scan
sleep 3
sudo ifconfig ${intf} down
sleep 3
sudo ./setup_sniffer ${bw} ${chan} ${chan_width}
