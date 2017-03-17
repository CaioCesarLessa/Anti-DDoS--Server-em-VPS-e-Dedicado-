#!/bin/bash
echo "Block TraceRoute : ppp0 wlan0 eth0 lo ..."
iptables -A INPUT -p udp -s 0/0 -i ppp0 --dport 33435:33525 -j DROP

echo "Block TCP-CONNECT scan attempts (SYN bit packets)"
iptables -A INPUT -p tcp --syn -j DROP

echo "Block TCP-SYN scan attempts (only SYN bit packets)"
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH SYN -j DROP

echo "Block TCP-FIN scan attempts (only FIN bit packets)"
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH FIN -j DROP

echo "Block TCP-ACK scan attempts (only ACK bit packets)"
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH ACK -j DROP

echo "Block TCP-NULL scan attempts (packets without flag)"
iptables -A INPUT -m conntrack --ctstate INVALID -p tcp --tcp-flags ! SYN,RST,ACK,FIN,URG,PSH SYN,RST,ACK,FIN,URG,PSH -j DROP

echo "Block "Christmas Tree" TCP-XMAS scan attempts (packets with FIN, URG, PSH bits)"
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH FIN,URG,PSH -j DROP

echo "Block DOS - Ping Da Morte"
iptables -A INPUT -p ICMP --icmp-type echo-request -m length --length 60:65535 -j ACCEPT
iptables -A FORWARD -p icmp --icmp-type echo-request -m connlimit --connlimit 1/s -j accept
iptables -A FORWARD -p icmp --icmp-type echo-request -j DROP

echo "Block DOS - Teardrop"
iptables -A INPUT -p UDP -f -j DROP

echo "Block DDOS - SYN-flood"
iptables -A INPUT -p TCP --syn -m connlimit --connlimit-above 9 -j DROP

echo "Block DDOS - Smurf"
iptables -A INPUT -m pkttype --pkt-type broadcast -j DROP
iptables -A INPUT -p ICMP --icmp-type echo-request -m pkttype --pkttype broadcast -j DROP
iptables -A INPUT -p ICMP --icmp-type echo-request -m limit --limit 3/s -j ACCEPT
iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
iptables -A INPUT -p icmp -m icmp -m limit --limit 1/second -j ACCEPT

echo "Block DDOS - UDP-flood (Pepsi)"
iptables -A INPUT -p UDP --dport 7 -j DROP
iptables -A INPUT -p UDP --dport 19 -j DROP

echo "Block DDOS - SMBnuke"
iptables -A INPUT -p UDP --dport 135:139 -j DROP
iptables -A INPUT -p TCP --dport 135:139 -j DROP

echo "Block DDOS - Connection-flood"
iptables -A INPUT -p TCP --syn -m connlimit --connlimit-above 3 -j DROP

echo "Block DDOS - Fraggle"
iptables -A INPUT -p UDP -m pkttype --pkt-type broadcast -j DROP
iptables -A INPUT -p UDP -m limit --limit 3/s -j ACCEPT

echo "Block DDOS - Jolt"
iptables -A INPUT -p ICMP -f -j DROP

echo "Bloquear NetBus"
iptables -A INPUT -p tcp --dport 12345:12346 -j DROP
iptables -A INPUT -p udp --dport 12345:12346 -j DROP 

echo "Contra Port Scanners"
iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
echo "Bloquear Back Orifice"
iptables -A INPUT -p tcp --dport 31337 -j DROP
iptables -A INPUT -p udp --dport 31337 -j DROP


#Esta comentado pois como se pode ver ele bloqueia certas ranges então cuidado
echo "Bloqueio De Pacotes FragMentados / invalidos"
#Bloqueando pacotes fragmentados
#iptables -A INPUT -i ppp0 -m unclean -j log_unclean
#iptables -A INPUT -f -i ppp0 -j log_fragment
#invalidos
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP

echo "Protecoes contra ataques"
#Protecoes contra ataques
iptables -A INPUT -m state --state INVALID -j DROP

echo "Bloqueio De Algumas TTLs |g3m|T50"
iptables -I INPUT -p icmp -i eth0 -m ttl --ttl-gt 160 -j DROP
iptables -I INPUT -p udp -i eth0 -m ttl --ttl-gt 160 -j DROP
iptables -I INPUT -p tcp -i eth0 -m ttl --ttl-gt 160 -j DROP

echo "Drop excessive RST packets to avoid smurf attacks"
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

echo "slowloris mitigation"
iptables -I INPUT -p tcp -m state --state NEW --dport 80 -m recent \
--name slowloris --set
iptables -I INPUT -p tcp -m state --state NEW --dport 80 -m recent \
--name slowloris --update --seconds 15 --hitcount 10 -j DROP
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

echo "block icmp"
iptables -I INPUT -p ICMP --icmp-type 8 -j REJECT
iptables -A OUTPUT -p icmp --icmp-type echo-request -j DROP
iptables -A OUTPUT -p icmp --icmp-type 8 -j DROP