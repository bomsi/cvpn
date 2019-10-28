#!/bin/sh
echo "public_ip_address=$1"
echo "private_ip_address=$2"

apt-get clean && apt-get update && apt-get install -y pptpd

modprobe ppp-compress-18 && echo "ppp-compress-18 ok"
modprobe nf_conntrack_proto_gre && echo "nf_conntrack_proto_gre ok"
modprobe nf_conntrack_pptp && echo "nf_conntrack_pptp ok"

from=$(echo "$2" | cut -d . -f 4)
if [ "$from" -ge "128" ]; then
    from=50
    to=70
else
    from=200
    to=220
fi

echo "" >>/etc/pptpd.conf
echo "localip $2" >>/etc/pptpd.conf
echo "remoteip 192.168.8.$from-$to" >>/etc/pptpd.conf

echo "" >>/etc/ppp/pptpd-options
echo "ms-dns 8.8.8.8" >>/etc/ppp/pptpd-options
echo "ms-dns 8.8.4.4" >>/etc/ppp/pptpd-options

echo "" >>/etc/ppp/chap-secrets
echo "user1 pptpd password1 *" >>/etc/ppp/chap-secrets
echo "user2 pptpd password2 *" >>/etc/ppp/chap-secrets
echo "user3 pptpd password3 *" >>/etc/ppp/chap-secrets
echo "user4 pptpd password4 *" >>/etc/ppp/chap-secrets
echo "user5 pptpd password5 *" >>/etc/ppp/chap-secrets

sysctl net.ipv4.ip_forward=1

ufw disable

iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -F
iptables -Z

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 1723 -j ACCEPT
iptables -A INPUT -p gre -j ACCEPT

iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -j SNAT --to "$1"

iptables -A INPUT -j DROP

/etc/init.d/pptpd restart

echo "Done."