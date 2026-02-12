#!/bin/bash

intf=$(iw dev | grep Interface | cut -d' ' -f2)
if [ $intf != "" ]
then
    sudo ifconfig ${intf} down
    sudo iw ${intf} interface add mon0 type monitor
    sudo ifconfig mon0 up
else
    echo "no wireless interface found"
fi

echo "enter band to sniff on: [2|5|6]"
read -r band

echo "enter channel to monitor: "
read -r ch_num

echo "enter channel width: [20|40|80|160|320]"
read -r ch_width

sudo ./setup_sniffer ${band} ${ch_num} ${ch_width}

sudo wireshark -i mon0 -k