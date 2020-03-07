#!/bin/sh

if [ "$(id -u)" -ne 0 ]; then
	echo "Please run this script as root" >&2
	exit 1
fi

echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
apt-get update
apt-get install wireguard

# add the interface
ip link add dev wg0 type wireguard

# assign IPv4 address
ip address add dev wg0 10.11.12.1/24

# generate private and public key for the node
cd /etc/wireguard/
umask 077
wg genkey | tee private.key | wg pubkey > public.key

wg set wg0 listen-port 53 private-key /etc/wireguard/private.key

ip link set up dev wg0

wg

# on the other peer, run the following:
#  ip link add dev wg0 type wireguard
#  ip address add dev wg0 10.11.12.2/24
#  cd /etc/wireguard/
#  umask 077
#  wg genkey | tee private.key | wg pubkey > public.key
#  wg set wg0 listen-port 50001 private-key /etc/wireguard/private.key
#  ip link set up dev wg0
# share the public keys, and add the peer with the public IP on the "client":
#  wg set wg0 peer base64publickeyserver allowed-ips 10.11.12.1/24 endpoint 1.2.3.4:53
# add the "client" peer on the endpoint with public IP:
#  wg set wg0 peer base64publickeyclient allowed-ips 10.11.12.2/24

# on the AWS side, compare
#  tcpdump -A -i eth0 port not ssh
# with
#  tcpdump -A -i wg0
