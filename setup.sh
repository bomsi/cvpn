#!/usr/bin/bash

if [ "$(id -u)" -ne 0 ]; then
	echo "Please run this script as root" >&2
	exit 1
fi

echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
apt-get update
apt-get install wireguard

# generate private and public key for the node
cd /etc/wireguard/
umask 077
wg genkey | tee private.key | wg pubkey > public.key

# "server" config
cat >wg0.conf << EOF
[Interface]
PrivateKey = $(cat private.key)
ListenPort = 53
Address = 10.11.12.1/24
EOF

# if you would like to allow clients to use the server as exit:
# * edit /etc/sysctl.conf, and set net.ipv4.ip_forward=1
# * sysctl -p
# * iptables -t nat -A POSTROUTING -s 10.11.12.0/24 -o ens3 -j MASQUERADE
# in that case, clients need to have "AllowedIPs = 0.0.0.0/0, ::/0" in their conf
# otherwise, set "AllowedIPs = 10.11.12.1/24" in their conf

# start the interface
wg-quick up wg0

wg

# on the other peer ("client"), run the following:
#  cd /etc/wireguard/
#  umask 077
#  wg genkey | tee private.key | wg pubkey > public.key
#  echo "base64serverpublickey" > server-public.key
#  cat >wg0.conf << EOF
#  [Interface]
#  PrivateKey = $(cat private.key)
#  Address = 10.11.12.2/24
#  
#  [Peer]
#  PublicKey = $(cat server-public.key)
#  AllowedIPs = 0.0.0.0/0, ::/0
#  Endpoint = 1.2.3.4:53
#  PersistentKeepalive = 15
#  EOF

# add the "client" peer on the endpoint with public IP:
# echo "base64client1publickey" > client1.key
# cat >>wg0.conf << EOF
# [Peer]
# PublicKey = $(cat client1.key)
# AllowedIPs = 10.11.12.2/32
# EOF
# wg-quick down wg0; wg-quick up wg0

# on the AWS side, compare
#  tcpdump -A -i eth0 port not ssh
# with
#  tcpdump -A -i wg0
