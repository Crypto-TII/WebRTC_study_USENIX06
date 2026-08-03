#!/bin/bash

IPTABLES=/sbin/iptables

# configure interface names here

WANIF='TODO CHANGE: OUTBOUND'

LANIF='TODO CHANGE: INBOUND'



# enable ip forwarding in the kernel

echo 'Enabling Kernel IP forwarding...'

/bin/echo 1 > /proc/sys/net/ipv4/ip_forward



# flush rules and delete chains

echo 'Flushing rules and deleting existing chains...'

$IPTABLES -F

$IPTABLES -X



# enable masquerading to allow LAN internet access for tcp

echo 'Enabling IP Masquerading and other rules...'
echo 'Allowing DNS'
$IPTABLES -A FORWARD -i $LANIF -p udp --dport 53 -j ACCEPT
$IPTABLES -A FORWARD -i $WANIF -p udp --sport 53 -j ACCEPT

$IPTABLES -A INPUT -p tcp -j ACCEPT
$IPTABLES -A INPUT -p icmp --icmp-type 3/3 -j DROP
$IPTABLES -P INPUT ACCEPT


$IPTABLES -A OUTPUT -p tcp -j ACCEPT
$IPTABLES -A OUTPUT -p icmp --icmp-type 3/3 -j DROP
$IPTABLES -P OUTPUT ACCEPT

$IPTABLES -t nat -A POSTROUTING -o $LANIF -j MASQUERADE
$IPTABLES -t nat -A POSTROUTING -o $WANIF -j MASQUERADE
$IPTABLES -A FORWARD -p tcp -i $WANIF -o $LANIF -j ACCEPT
$IPTABLES -A FORWARD -p tcp -i $LANIF -o $WANIF -j ACCEPT
$IPTABLES -A FORWARD -i $LANIF -p udp -j DROP
$IPTABLES -A FORWARD -p icmp --icmp-type 3/3 -j DROP
$IPTABLES -P FORWARD ACCEPT

